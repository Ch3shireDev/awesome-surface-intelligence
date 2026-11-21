// Package store keeps runs, chunks, observations, targets and assets in PostgreSQL
// (asi-db, separate from DefectDojo's database). Schema: migrations/*.sql,
// applied in order by Migrate and tracked in schema_migrations.
//
// Sensitive values (observation data, raw tool output, notes) go through Sealer,
// so they are encrypted at rest once SEC-6 plugs AES-GCM in (internal/crypto).
package store

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"asi/internal/obs"
	"asi/internal/targets"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Sealer encrypts/decrypts sensitive column values. Plain is the no-op default.
type Sealer interface {
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

type Plain struct{}

func (Plain) Seal(b []byte) ([]byte, error) { return b, nil }
func (Plain) Open(b []byte) ([]byte, error) { return b, nil }

type Store struct {
	DB     *pgxpool.Pool
	Sealer Sealer
}

func Open(ctx context.Context, url string, s Sealer) (*Store, error) {
	if s == nil {
		s = Plain{}
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: %w", err)
	}
	return &Store{DB: pool, Sealer: s}, nil
}

func (s *Store) Close() { s.DB.Close() }

// Migrate applies pending migrations (each in its own transaction).
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	if _, err := s.DB.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	entries, _ := migrations.ReadDir("migrations")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var applied []string
	for _, n := range names {
		var exists bool
		s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, n).Scan(&exists)
		if exists {
			continue
		}
		sql, _ := migrations.ReadFile("migrations/" + n)
		err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, n)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", n, err)
		}
		applied = append(applied, n)
	}
	return applied, nil
}

// ---------------------------------------------------------------- runs & chunks

type Run struct {
	ScheduleID *int64          `json:"schedule_id,omitempty"`
	ResumeOf   string          `json:"resume_of,omitempty"`
	ResumedBy  string          `json:"resumed_by,omitempty"`
	Pending    int             `json:"pending"`
	ID         string          `json:"id"`
	SetName    string          `json:"set_name"`
	Status     string          `json:"status"`
	Trigger    string          `json:"trigger"`
	Profile    json.RawMessage `json:"profile"`
	Stats      json.RawMessage `json:"stats"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
}

func (s *Store) CreateRun(ctx context.Context, id, setName, trigger string, profile any) error {
	p, _ := json.Marshal(profile)
	_, err := s.DB.Exec(ctx, `INSERT INTO runs (id, set_name, status, trigger, profile) VALUES ($1,$2,'running',$3,$4)`,
		id, setName, trigger, p)
	return err
}

// FinishRun sets the final status: completed | partial (window/interrupt) | failed | cancelled.
func (s *Store) FinishRun(ctx context.Context, id, status string, stats any) error {
	b, _ := json.Marshal(stats)
	_, err := s.DB.Exec(ctx, `UPDATE runs SET status=$2, stats=$3, finished_at=now() WHERE id=$1`, id, status, b)
	return err
}

func (s *Store) Runs(ctx context.Context, limit int) ([]Run, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, set_name, status, trigger, profile, stats, started_at, finished_at,
		schedule_id, resume_of, resumed_by, cardinality(pending_targets)
		FROM runs ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Run, error) {
		var x Run
		err := r.Scan(&x.ID, &x.SetName, &x.Status, &x.Trigger, &x.Profile, &x.Stats, &x.StartedAt, &x.FinishedAt,
			&x.ScheduleID, &x.ResumeOf, &x.ResumedBy, &x.Pending)
		return x, err
	})
}

func (s *Store) StartChunk(ctx context.Context, runID, stage string, id int, tgts []string) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO chunks (run_id, stage, id, targets, size, status, started_at)
		VALUES ($1,$2,$3,$4,$5,'running',now())
		ON CONFLICT (run_id, stage, id) DO UPDATE SET status='running', attempts=chunks.attempts+1, started_at=now()`,
		runID, stage, id, tgts, len(tgts))
	return err
}

func (s *Store) FinishChunk(ctx context.Context, runID, stage string, id int, status string, dur time.Duration, errMsg string) error {
	_, err := s.DB.Exec(ctx, `UPDATE chunks SET status=$4, finished_at=now(), duration_ms=$5, error=$6, progress_pct=100
		WHERE run_id=$1 AND stage=$2 AND id=$3`, runID, stage, id, status, dur.Milliseconds(), errMsg)
	return err
}

// SetChunkPorts records the port set a chunk actually scanned (nmap ranges, per protocol tcp).
func (s *Store) SetChunkPorts(ctx context.Context, runID, stage string, id int, ports string) error {
	_, err := s.DB.Exec(ctx, `UPDATE chunks SET ports=$4 WHERE run_id=$1 AND stage=$2 AND id=$3`, runID, stage, id, ports)
	return err
}

// PortSet is a parsed nmap port list ("22,80,1000-1010"). Empty set = unknown, covers everything.
type PortSet [][2]int

func ParsePorts(s string) PortSet {
	var ps PortSet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var a, b int
		if n, _ := fmt.Sscanf(part, "%d-%d", &a, &b); n == 2 {
			ps = append(ps, [2]int{a, b})
		} else if n, _ := fmt.Sscanf(part, "%d", &a); n == 1 {
			ps = append(ps, [2]int{a, a})
		}
	}
	return ps
}

func (ps PortSet) Has(p int) bool {
	if len(ps) == 0 {
		return true
	}
	for _, r := range ps {
		if p >= r[0] && p <= r[1] {
			return true
		}
	}
	return false
}

// ChunkStats: count of chunks per stage and status, for progress from the database (VISION 4.6).
func (s *Store) ChunkStats(ctx context.Context, runID string) (map[string]map[string]int, error) {
	rows, err := s.DB.Query(ctx, `SELECT stage, status, count(*) FROM chunks WHERE run_id=$1 GROUP BY 1,2`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var st, status string
		var n int
		rows.Scan(&st, &status, &n)
		if out[st] == nil {
			out[st] = map[string]int{}
		}
		out[st][status] = n
	}
	return out, rows.Err()
}

func (s *Store) SaveRaw(ctx context.Context, runID, stage string, chunkID int, tool, format string, data []byte) error {
	enc, err := s.Sealer.Seal(data)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO raw_outputs (run_id, stage, chunk_id, tool, format, data_enc)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (run_id, stage, chunk_id) DO UPDATE SET data_enc=EXCLUDED.data_enc`,
		runID, stage, chunkID, tool, format, enc)
	return err
}

// ---------------------------------------------------------------- observations

func (s *Store) InsertObservations(ctx context.Context, runID, stage string, chunkID int, os []obs.Observation) error {
	if len(os) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(os))
	for _, o := range os {
		ip, proto, port := obs.SplitKey(o.AssetKey)
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("observation %s: %w", o.AssetKey, err)
		}
		enc, err := s.Sealer.Seal(o.Data)
		if err != nil {
			return err
		}
		svc := ""
		if o.Kind == obs.KindService {
			var d obs.ServiceData
			o.Decode(&d)
			svc = d.Name
		}
		rows = append(rows, []any{runID, stage, chunkID, string(o.Kind), o.AssetKey, addr, proto, port, svc,
			enc, o.FPHash, o.Confidence, o.Tool, o.ObservedAt})
	}
	_, err := s.DB.CopyFrom(ctx, pgx.Identifier{"observations"},
		[]string{"run_id", "stage", "chunk_id", "kind", "asset_key", "ip", "proto", "port", "service",
			"data_enc", "fp_hash", "confidence", "tool", "observed_at"},
		pgx.CopyFromRows(rows))
	return err
}

// Observations of one run, optionally filtered by kind, decrypted.
func (s *Store) Observations(ctx context.Context, runID string, kinds ...obs.Kind) ([]obs.Observation, error) {
	q := `SELECT kind, asset_key, data_enc, fp_hash, confidence, tool, observed_at FROM observations WHERE run_id=$1`
	args := []any{runID}
	if len(kinds) > 0 {
		ks := make([]string, len(kinds))
		for i, k := range kinds {
			ks[i] = string(k)
		}
		q += ` AND kind = ANY($2)`
		args = append(args, ks)
	}
	rows, err := s.DB.Query(ctx, q+` ORDER BY asset_key, kind`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (obs.Observation, error) {
		var o obs.Observation
		var kind string
		var enc []byte
		if err := r.Scan(&kind, &o.AssetKey, &enc, &o.FPHash, &o.Confidence, &o.Tool, &o.ObservedAt); err != nil {
			return o, err
		}
		o.Kind = obs.Kind(kind)
		data, err := s.Sealer.Open(enc)
		o.Data = data
		return o, err
	})
}

// LiveHosts of a run (kind=host).
func (s *Store) LiveHosts(ctx context.Context, runID string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT host(ip) FROM observations WHERE run_id=$1 AND kind='host' ORDER BY 1`, runID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ---------------------------------------------------------------- targets

func (s *Store) ensureSet(ctx context.Context, tx pgx.Tx, name string) (int64, error) {
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO target_sets(name) VALUES ($1)
		ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id`, name).Scan(&id)
	return id, err
}

func kindOf(v string) string {
	if _, err := netip.ParseAddr(v); err == nil {
		return "ip"
	}
	if _, err := netip.ParsePrefix(v); err == nil {
		return "cidr"
	}
	return "domain"
}

// UpsertTargets adds or updates targets of a set (by value), replacing all fields
// (explicit edit). Returns rows written.
func (s *Store) UpsertTargets(ctx context.Context, set string, ts []targets.Target) (int, error) {
	return s.upsertTargets(ctx, set, ts, false)
}

// MergeTargets adds targets; for existing ones it only fills in what the input has:
// empty tags/note/asset/owner in the input never erase stored values (an import of a
// bare .txt list must not wipe tags and notes added earlier - PDF pkt 14).
func (s *Store) MergeTargets(ctx context.Context, set string, ts []targets.Target) (int, error) {
	return s.upsertTargets(ctx, set, ts, true)
}

func (s *Store) upsertTargets(ctx context.Context, set string, ts []targets.Target, merge bool) (int, error) {
	n := 0
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		sid, err := s.ensureSet(ctx, tx, set)
		if err != nil {
			return err
		}
		for _, t := range ts {
			v := strings.TrimSpace(t.Target)
			if v == "" {
				continue
			}
			var note []byte
			if t.Note != "" {
				if note, err = s.Sealer.Seal([]byte(t.Note)); err != nil {
					return err
				}
			}
			tags := t.Tags
			if tags == nil {
				tags = []string{}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO targets (set_id, kind, value, asset, owner, tags, enabled, note_enc)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
				ON CONFLICT (set_id, value) DO UPDATE SET `+onConflict(merge),
				sid, kindOf(v), v, t.Asset, t.Owner, tags, t.Enabled, note); err != nil {
				return fmt.Errorf("target %s: %w", v, err)
			}
			n++
		}
		return nil
	})
	return n, err
}

// Targets of a set, notes decrypted.
func (s *Store) Targets(ctx context.Context, set string) ([]targets.Target, error) {
	rows, err := s.DB.Query(ctx, `SELECT t.value, t.asset, t.owner, t.tags, t.enabled, t.note_enc
		FROM targets t JOIN target_sets ts ON ts.id=t.set_id WHERE ts.name=$1 ORDER BY t.id`, set)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (targets.Target, error) {
		var t targets.Target
		var note []byte
		if err := r.Scan(&t.Target, &t.Asset, &t.Owner, &t.Tags, &t.Enabled, &note); err != nil {
			return t, err
		}
		if note != nil {
			b, err := s.Sealer.Open(note)
			if err != nil {
				return t, err
			}
			t.Note = string(b)
		}
		return t, nil
	})
}

// DeleteTargetSet removes a target set with its targets and returns how many targets went
// with it. It refuses without `force` when the set is not empty or when something still
// points at it (runs by set name, schedules). Deleting a set that was scanned leaves runs
// without their starting list, hence the explicit flag.
func (s *Store) DeleteTargetSet(ctx context.Context, name string, force bool) (int, error) {
	var id int64
	if err := s.DB.QueryRow(ctx, `SELECT id FROM target_sets WHERE name=$1`, name).Scan(&id); err != nil {
		if err == pgx.ErrNoRows {
			return 0, fmt.Errorf("nie ma zbioru celów %q", name)
		}
		return 0, err
	}
	var targetsN, runsN, schedN int
	if err := s.DB.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM targets WHERE set_id=$1),
			(SELECT count(*) FROM runs WHERE set_name=$2),
			(SELECT count(*) FROM schedules WHERE set_name=$2)`, id, name).
		Scan(&targetsN, &runsN, &schedN); err != nil {
		return 0, err
	}
	if !force && (targetsN > 0 || runsN > 0 || schedN > 0) {
		return 0, fmt.Errorf("zbiór %q nie jest pusty (cele: %d, przebiegi: %d, harmonogramy: %d) - dodaj -force",
			name, targetsN, runsN, schedN)
	}
	deleted := 0
	err := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM targets WHERE set_id=$1`, id)
		if err != nil {
			return err
		}
		deleted = int(tag.RowsAffected())
		_, err = tx.Exec(ctx, `DELETE FROM target_sets WHERE id=$1`, id)
		return err
	})
	return deleted, err
}

// ---------------------------------------------------------------- target editing (GUI form)

type TargetRow struct {
	ID        int64     `json:"id"`
	Set       string    `json:"set"`
	Kind      string    `json:"kind"`
	Value     string    `json:"target"`
	Asset     string    `json:"asset"`
	Owner     string    `json:"owner"`
	Tags      []string  `json:"tags"`
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s *Store) TargetRows(ctx context.Context, set string) ([]TargetRow, error) {
	rows, err := s.DB.Query(ctx, `SELECT t.id, ts.name, t.kind, t.value, t.asset, t.owner, t.tags, t.enabled, t.note_enc, t.updated_at
		FROM targets t JOIN target_sets ts ON ts.id=t.set_id WHERE ts.name=$1 ORDER BY t.id`, set)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (TargetRow, error) {
		var t TargetRow
		var note []byte
		if err := r.Scan(&t.ID, &t.Set, &t.Kind, &t.Value, &t.Asset, &t.Owner, &t.Tags, &t.Enabled, &note, &t.UpdatedAt); err != nil {
			return t, err
		}
		if note != nil {
			b, err := s.Sealer.Open(note)
			if err != nil {
				return t, err
			}
			t.Note = string(b)
		}
		return t, nil
	})
}

func (s *Store) TargetSets(ctx context.Context) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT name FROM target_sets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// TargetValueByID returns the value (IP/CIDR/domain) of a target row. Used by the GUI
// edit path (DEV-12), where analyst may modify enabled/tags/note/owner of an EXISTING
// target but may not create one by changing its value.
func (s *Store) TargetValueByID(ctx context.Context, id int64) (string, error) {
	var v string
	err := s.DB.QueryRow(ctx, `SELECT value FROM targets WHERE id=$1`, id).Scan(&v)
	return v, err
}

func (s *Store) DeleteTarget(ctx context.Context, id int64) (string, error) {
	var v string
	err := s.DB.QueryRow(ctx, `DELETE FROM targets WHERE id=$1 RETURNING value`, id).Scan(&v)
	return v, err
}

func onConflict(merge bool) string {
	if !merge {
		return `kind=EXCLUDED.kind, asset=EXCLUDED.asset, owner=EXCLUDED.owner,
			tags=EXCLUDED.tags, enabled=EXCLUDED.enabled, note_enc=EXCLUDED.note_enc, updated_at=now()`
	}
	return `kind=EXCLUDED.kind,
			asset=CASE WHEN EXCLUDED.asset='' THEN targets.asset ELSE EXCLUDED.asset END,
			owner=CASE WHEN EXCLUDED.owner='' THEN targets.owner ELSE EXCLUDED.owner END,
			tags=(SELECT coalesce(array_agg(DISTINCT t), '{}') FROM unnest(targets.tags || EXCLUDED.tags) t),
			enabled=EXCLUDED.enabled,
			note_enc=coalesce(EXCLUDED.note_enc, targets.note_enc), updated_at=now()`
}
