package store

import (
	"context"
	"fmt"
)

// sealedColumns lists every column written through Sealer (migrations 001 and 005).
// Order matters only for the report; each row is updated by ctid within one transaction.
var sealedColumns = []struct{ table, column string }{
	{"targets", "note_enc"},
	{"observations", "data_enc"},
	{"raw_outputs", "data_enc"},
	{"assets", "current_enc"},
	{"assets", "user_note_enc"},
	{"assets", "http_enc"},
	{"asset_events", "before_enc"},
	{"asset_events", "after_enc"},
}

// Reseal seals legacy plaintext values in the *_enc columns: rows written before
// ASI_ENCRYPTION_KEYS was configured (or while it was missing). Values that already
// carry the "ASI1" prefix are skipped, so the command is idempotent and safe to run
// after every key change. With dryRun it only counts rows and changes nothing.
//
// It refuses to run without a real key (Store.Sealer == Plain), because that would
// report success while writing plaintext back.
func (s *Store) Reseal(ctx context.Context, dryRun bool) (map[string]int, error) {
	if _, plain := s.Sealer.(Plain); plain || s.Sealer == nil {
		return nil, fmt.Errorf("no encryption key: set ASI_ENCRYPTION_KEYS (make env-keys) first")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	counts := make(map[string]int, len(sealedColumns))
	for _, c := range sealedColumns {
		// bt: values without the magic prefix are legacy plaintext (see internal/crypto).
		q := fmt.Sprintf(`SELECT ctid::text, %[2]s FROM %[1]s
			WHERE %[2]s IS NOT NULL AND substring(%[2]s from 1 for 4) <> 'ASI1'::bytea`,
			c.table, c.column)
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", c.table, c.column, err)
		}
		type row struct {
			ctid string
			val  []byte
		}
		var batch []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.ctid, &r.val); err != nil {
				rows.Close()
				return nil, fmt.Errorf("%s.%s: %w", c.table, c.column, err)
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", c.table, c.column, err)
		}
		for _, r := range batch {
			sealed, err := s.Sealer.Seal(r.val)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: seal: %w", c.table, c.column, err)
			}
			if dryRun {
				continue
			}
			upd := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE ctid = $2::tid`, c.table, c.column)
			if _, err := tx.Exec(ctx, upd, sealed, r.ctid); err != nil {
				return nil, fmt.Errorf("%s.%s: %w", c.table, c.column, err)
			}
		}
		counts[c.table+"."+c.column] = len(batch)
	}
	if dryRun {
		return counts, tx.Rollback(ctx)
	}
	return counts, tx.Commit(ctx)
}
