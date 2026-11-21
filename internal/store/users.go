package store

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Roles in increasing order of privilege (PDF pkt 13; VISION 5).
var RoleLevel = map[string]int{"viewer": 1, "analyst": 2, "operator": 3, "admin": 4}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
}

func (u User) Can(role string) bool { return !u.Disabled && RoleLevel[u.Role] >= RoleLevel[role] }

// ---- passwords: PBKDF2-SHA256, 600k iterations (OWASP 2023), stdlib only ----

const pbkdfIter = 600_000

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	k, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k)), nil
}

func CheckPassword(hash, pw string) bool {
	p := strings.Split(hash, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, _ := strconv.Atoi(p[1])
	salt, err1 := base64.RawStdEncoding.DecodeString(p[2])
	want, err2 := base64.RawStdEncoding.DecodeString(p[3])
	if err1 != nil || err2 != nil || iter < 1 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// ---- users ----

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(ctx context.Context, username, password, role string) (User, error) {
	if RoleLevel[role] == 0 {
		return User{}, fmt.Errorf("unknown role %q", role)
	}
	h, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	u := User{Username: username, Role: role}
	err = s.DB.QueryRow(ctx, `INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3) RETURNING id`,
		username, h, role).Scan(&u.ID)
	return u, err
}

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, username, role, disabled FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (User, error) {
		var u User
		return u, r.Scan(&u.ID, &u.Username, &u.Role, &u.Disabled)
	})
}

// Login checks credentials and returns a new session token (only its hash is stored).
func (s *Store) Login(ctx context.Context, username, password string, ttl time.Duration) (User, string, error) {
	var u User
	var hash string
	err := s.DB.QueryRow(ctx, `SELECT id, username, role, disabled, password_hash FROM users WHERE username=$1`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &hash)
	if err != nil || u.Disabled || !CheckPassword(hash, password) {
		CheckPassword("pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAA", password) // same timing for unknown users
		return User{}, "", errors.New("invalid credentials")
	}
	tok, err := s.NewToken(ctx, u.ID, "session", ttl)
	return u, tok, err
}

// NewToken creates an API/session token for a user; returns the plain token once.
func (s *Store) NewToken(ctx context.Context, userID int64, name string, ttl time.Duration) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	tok := "asi_" + hex.EncodeToString(b)
	var exp *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		exp = &t
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO api_tokens (user_id, token_hash, name, expires_at) VALUES ($1,$2,$3,$4)`,
		userID, tokenHash(tok), name, exp)
	return tok, err
}

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// SetPassword replaces a user's password. Recovery path: the admin seeded from .env
// exists only when the users table was empty, so a stale hash (password changed in
// .env afterwards) cannot be fixed from the GUI without logging in. Clears disabled.
func (s *Store) SetPassword(ctx context.Context, username, password string) (User, error) {
	if len(password) < 10 {
		return User{}, fmt.Errorf("password too short (min. 10 characters)")
	}
	h, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	var u User
	err = s.DB.QueryRow(ctx, `UPDATE users SET password_hash=$2, disabled=false WHERE username=$1
		RETURNING id, username, role, disabled`, username, h).Scan(&u.ID, &u.Username, &u.Role, &u.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("no user %q", username)
	}
	return u, err
}

func (s *Store) UserByToken(ctx context.Context, tok string) (User, error) {
	var u User
	err := s.DB.QueryRow(ctx, `UPDATE api_tokens t SET last_used_at=now() FROM users u
		WHERE t.token_hash=$1 AND u.id=t.user_id AND (t.expires_at IS NULL OR t.expires_at > now()) AND NOT u.disabled
		RETURNING u.id, u.username, u.role, u.disabled`, tokenHash(tok)).Scan(&u.ID, &u.Username, &u.Role, &u.Disabled)
	return u, err
}

func (s *Store) RevokeToken(ctx context.Context, tok string) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM api_tokens WHERE token_hash=$1`, tokenHash(tok))
	return err
}

// ---- audit ----

func (s *Store) Audit(ctx context.Context, userID *int64, action, objType, objID string, changes any) {
	b, _ := json.Marshal(changes)
	s.DB.Exec(ctx, `INSERT INTO audit_log (user_id, action, object_type, object_id, changes) VALUES ($1,$2,$3,$4,$5)`,
		userID, action, objType, objID, b)
}

type AuditEntry struct {
	At       time.Time       `json:"at"`
	Username string          `json:"username"`
	Action   string          `json:"action"`
	Object   string          `json:"object"`
	Changes  json.RawMessage `json:"changes"`
}

func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.DB.Query(ctx, `SELECT a.at, coalesce(u.username,'system'), a.action, a.object_type||':'||a.object_id, coalesce(a.changes,'null')
		FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		return e, r.Scan(&e.At, &e.Username, &e.Action, &e.Object, &e.Changes)
	})
}
