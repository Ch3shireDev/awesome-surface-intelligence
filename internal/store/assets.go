package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type Asset struct {
	Key               string          `json:"key"`
	Kind              string          `json:"kind"`
	Parent            string          `json:"parent,omitempty"`
	IP                string          `json:"ip"`
	Port              int             `json:"port,omitempty"`
	State             string          `json:"state"`
	Flapping          bool            `json:"flapping"`
	FirstSeen         time.Time       `json:"first_seen"`
	LastSeen          time.Time       `json:"last_seen"`
	LastSeenRun       string          `json:"last_seen_run"`
	ConsecutiveMisses int             `json:"consecutive_misses"`
	SeenCount         int             `json:"seen_count"`
	HoursSeen         int             `json:"hours_seen"` // bit h = seen at hour h (UTC)
	Current           json.RawMessage `json:"current,omitempty"`
	UserTags          []string        `json:"user_tags"`
	UserNote          string          `json:"user_note,omitempty"`
	UserOverrides     json.RawMessage `json:"user_overrides"`
}

type AssetFilter struct {
	State    string // new | active | missing | gone | "" = all
	Kind     string // host | port | ""
	Flapping bool
	Search   string // substring of key
	Limit    int
}

func (s *Store) Assets(ctx context.Context, f AssetFilter) ([]Asset, error) {
	q := `SELECT key, kind, parent_key, host(ip), port, state, flapping, first_seen, last_seen, last_seen_run,
		consecutive_misses, seen_count, hours_seen, current_enc, user_tags, user_note_enc, user_overrides FROM assets WHERE true`
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		q += fmt.Sprintf(" AND "+cond, len(args))
	}
	if f.State != "" {
		add("state=$%d", f.State)
	}
	if f.Kind != "" {
		add("kind=$%d", f.Kind)
	}
	if f.Flapping {
		q += " AND flapping"
	}
	if f.Search != "" {
		add("key ILIKE $%d", "%"+strings.ReplaceAll(f.Search, "%", "")+"%")
	}
	if f.Limit <= 0 {
		f.Limit = 1000
	}
	args = append(args, f.Limit)
	q += fmt.Sprintf(" ORDER BY ip, port LIMIT $%d", len(args))
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Asset, error) {
		var a Asset
		var cur, note []byte
		if err := r.Scan(&a.Key, &a.Kind, &a.Parent, &a.IP, &a.Port, &a.State, &a.Flapping, &a.FirstSeen, &a.LastSeen,
			&a.LastSeenRun, &a.ConsecutiveMisses, &a.SeenCount, &a.HoursSeen, &cur, &a.UserTags, &note, &a.UserOverrides); err != nil {
			return a, err
		}
		if cur != nil {
			b, err := s.Sealer.Open(cur)
			if err != nil {
				return a, err
			}
			a.Current = b
		}
		if note != nil {
			b, err := s.Sealer.Open(note)
			if err != nil {
				return a, err
			}
			a.UserNote = string(b)
		}
		return a, nil
	})
}

// AssetEdit: user-owned fields. nil = leave unchanged.
type AssetEdit struct {
	Tags      *[]string        `json:"user_tags,omitempty"`
	Note      *string          `json:"user_note,omitempty"`
	Overrides *json.RawMessage `json:"user_overrides,omitempty"`
}

// EditAsset updates user fields (kept across all future scans) and writes the audit log.
func (s *Store) EditAsset(ctx context.Context, userID *int64, key string, e AssetEdit) error {
	return pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		var id int64
		if err := tx.QueryRow(ctx, `SELECT id FROM assets WHERE key=$1 FOR UPDATE`, key).Scan(&id); err != nil {
			return fmt.Errorf("asset %s: %w", key, err)
		}
		if e.Tags != nil {
			if _, err := tx.Exec(ctx, `UPDATE assets SET user_tags=$2, updated_at=now() WHERE id=$1`, id, nonNil(*e.Tags)); err != nil {
				return err
			}
		}
		if e.Note != nil {
			var enc []byte
			if *e.Note != "" {
				var err error
				if enc, err = s.Sealer.Seal([]byte(*e.Note)); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE assets SET user_note_enc=$2, updated_at=now() WHERE id=$1`, id, enc); err != nil {
				return err
			}
		}
		if e.Overrides != nil {
			if _, err := tx.Exec(ctx, `UPDATE assets SET user_overrides=$2, updated_at=now() WHERE id=$1`, id, []byte(*e.Overrides)); err != nil {
				return err
			}
		}
		// audit without the note's content (it is sensitive)
		changes := map[string]any{}
		if e.Tags != nil {
			changes["user_tags"] = *e.Tags
		}
		if e.Note != nil {
			changes["user_note"] = "(changed)"
		}
		if e.Overrides != nil {
			changes["user_overrides"] = *e.Overrides
		}
		b, _ := json.Marshal(changes)
		_, err := tx.Exec(ctx, `INSERT INTO audit_log (user_id, action, object_type, object_id, changes) VALUES ($1,'edit','asset',$2,$3)`,
			userID, key, b)
		return err
	})
}

// Events of one run (runID != "") or of one asset (key != ""), newest first.
func (s *Store) Events(ctx context.Context, runID, key string, limit int) ([]Event, error) {
	q := `SELECT e.key, a.kind, e.type, e.before_enc, e.after_enc, e.run_id, e.at FROM asset_events e JOIN assets a ON a.id=e.asset_id WHERE true`
	var args []any
	if runID != "" {
		args = append(args, runID)
		q += fmt.Sprintf(" AND e.run_id=$%d", len(args))
	}
	if key != "" {
		args = append(args, key)
		q += fmt.Sprintf(" AND e.key=$%d", len(args))
	}
	if limit <= 0 {
		limit = 1000
	}
	args = append(args, limit)
	q += fmt.Sprintf(" ORDER BY e.at DESC, e.id DESC LIMIT $%d", len(args))
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
		var e Event
		var b, a []byte
		if err := r.Scan(&e.Key, &e.Kind, &e.Type, &b, &a, &e.RunID, &e.At); err != nil {
			return e, err
		}
		if b != nil {
			e.Before, _ = s.Sealer.Open(b)
		}
		if a != nil {
			e.After, _ = s.Sealer.Open(a)
		}
		return e, nil
	})
}
