package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ErrLastAdmin is returned when an operation would leave no active administrator
// (PDF pkt 12-13: without it the panel could be locked out for good).
var ErrLastAdmin = errors.New("to jest ostatnie aktywne konto administratora")

// UserUpdate describes what to change in a user. Zero values mean "leave as is":
// empty Role keeps the role, nil Disabled keeps the flag, empty Password keeps the hash.
type UserUpdate struct {
	Role     string
	Disabled *bool
	Password string
}

// UpdateUser changes role / disabled / password of one account. Guards:
//   - role must be known (viewer|analyst|operator|admin),
//   - password, if given, must have at least 10 characters,
//   - the last active admin cannot be demoted or disabled (ErrLastAdmin).
//
// Disabling an account or changing its password revokes all of its sessions and API
// tokens, so an already logged-in user is cut off immediately (UserByToken also
// filters disabled users, so this is belt and braces).
func (s *Store) UpdateUser(ctx context.Context, id int64, up UserUpdate) (User, error) {
	if up.Role != "" && RoleLevel[up.Role] == 0 {
		return User{}, fmt.Errorf("unknown role %q", up.Role)
	}
	if up.Password != "" && len(up.Password) < 10 {
		return User{}, fmt.Errorf("password too short (min. 10 characters)")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx)

	var u User
	var hash string
	err = tx.QueryRow(ctx, `SELECT id, username, role, disabled, password_hash FROM users WHERE id=$1 FOR UPDATE`, id).
		Scan(&u.ID, &u.Username, &u.Role, &u.Disabled, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, fmt.Errorf("no user with id %d", id)
	}
	if err != nil {
		return User{}, err
	}

	role := u.Role
	if up.Role != "" {
		role = up.Role
	}
	disabled := u.Disabled
	if up.Disabled != nil {
		disabled = *up.Disabled
	}
	wasAdmin := u.Role == "admin" && !u.Disabled
	stillAdmin := role == "admin" && !disabled
	if wasAdmin && !stillAdmin {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled AND id<>$1`, id).Scan(&n); err != nil {
			return User{}, err
		}
		if n == 0 {
			return User{}, ErrLastAdmin
		}
	}

	newHash := hash
	if up.Password != "" {
		if newHash, err = HashPassword(up.Password); err != nil {
			return User{}, err
		}
	}
	if err := tx.QueryRow(ctx, `UPDATE users SET role=$2, disabled=$3, password_hash=$4 WHERE id=$1
		RETURNING id, username, role, disabled`, id, role, disabled, newHash).
		Scan(&u.ID, &u.Username, &u.Role, &u.Disabled); err != nil {
		return User{}, err
	}
	if disabled || up.Password != "" {
		if _, err := tx.Exec(ctx, `DELETE FROM api_tokens WHERE user_id=$1`, id); err != nil {
			return User{}, err
		}
	}
	return u, tx.Commit(ctx)
}

// DeleteUser removes an account and its tokens. The last active admin cannot be deleted.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var role string
	var disabled bool
	err = tx.QueryRow(ctx, `SELECT role, disabled FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&role, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("no user with id %d", id)
	}
	if err != nil {
		return err
	}
	if role == "admin" && !disabled {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE role='admin' AND NOT disabled AND id<>$1`, id).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM api_tokens WHERE user_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
