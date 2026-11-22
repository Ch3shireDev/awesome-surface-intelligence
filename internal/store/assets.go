package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/findings"
	"asi/internal/obs"
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
	HTTP              json.RawMessage `json:"http,omitempty"`
	UserTags          []string        `json:"user_tags"`
	UserNote          string          `json:"user_note,omitempty"`
	UserOverrides     json.RawMessage `json:"user_overrides"`
}

type AssetFilter struct {
	State    string // new | active | missing | gone | live (new+active) | "" = all
	Kind     string // host | port | ""
	Flapping bool
	Search   string   // substring of key
	RunID    string   // only assets with an event of one of Events types in this run
	Events   []string // new | reappeared | changed | reverted | missing | gone | flapping (with RunID)
	Limit    int
}

func (s *Store) Assets(ctx context.Context, f AssetFilter) ([]Asset, error) {
	q := `SELECT key, kind, parent_key, host(ip), port, state, flapping, first_seen, last_seen, last_seen_run,
		consecutive_misses, seen_count, hours_seen, current_enc, http_enc, user_tags, user_note_enc, user_overrides FROM assets WHERE true`
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		q += fmt.Sprintf(" AND "+cond, len(args))
	}
	switch f.State {
	case "":
	case "live": // new + active: wszystko, co teraz odpowiada
		q += " AND state IN ('new','active')"
	default:
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
	if f.RunID != "" && len(f.Events) > 0 {
		// kafelek "nowe w ostatnim skanie" pokazuje dokładnie te assety, które w tym przebiegu
		// dostały zdarzenie danego typu (stan assetu bywa już "active", więc filtr po samym stanie kłamie)
		args = append(args, f.RunID, f.Events)
		q += fmt.Sprintf(" AND key IN (SELECT a.key FROM asset_events e JOIN assets a ON a.id=e.asset_id WHERE e.run_id=$%d AND e.type = ANY($%d))", len(args)-1, len(args))
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
		var cur, httpEnc, note []byte
		if err := r.Scan(&a.Key, &a.Kind, &a.Parent, &a.IP, &a.Port, &a.State, &a.Flapping, &a.FirstSeen, &a.LastSeen,
			&a.LastSeenRun, &a.ConsecutiveMisses, &a.SeenCount, &a.HoursSeen, &cur, &httpEnc, &a.UserTags, &note, &a.UserOverrides); err != nil {
			return a, err
		}
		if cur != nil {
			b, err := s.Sealer.Open(cur)
			if err != nil {
				return a, err
			}
			a.Current = b
		}
		if httpEnc != nil {
			b, err := s.Sealer.Open(httpEnc)
			if err != nil {
				return a, err
			}
			a.HTTP = b
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

// RunEventTypes: asset key -> its event type in one run (the most meaningful one when there are several,
// e.g. "missing" over "flapping"). Used to describe a diff in the words of the history (LAB-T5).
func (s *Store) RunEventTypes(ctx context.Context, runID string) (map[string]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT key, type FROM asset_events WHERE run_id=$1`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, t string
		if err := rows.Scan(&k, &t); err != nil {
			return nil, err
		}
		out[k] = findings.PickEvent(out[k], t)
	}
	return out, rows.Err()
}

// EventCounts per run for the dashboard timeline: the newest `runs` runs, ordered oldest first.
type RunEvents struct {
	RunID  string         `json:"run_id"`
	At     time.Time      `json:"at"`
	Status string         `json:"status"`
	Counts map[string]int `json:"counts"`
}

func (s *Store) EventCounts(ctx context.Context, runs int) ([]RunEvents, error) {
	rows, err := s.DB.Query(ctx, `SELECT r.id, r.started_at, r.status, e.type, count(e.id)
		FROM (SELECT id, started_at, status FROM runs ORDER BY started_at DESC LIMIT $1) r
		LEFT JOIN asset_events e ON e.run_id=r.id GROUP BY 1,2,3,4 ORDER BY 2`, runs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunEvents
	idx := map[string]int{}
	for rows.Next() {
		var id, status string
		var typ *string
		var at time.Time
		var n int
		if err := rows.Scan(&id, &at, &status, &typ, &n); err != nil {
			return nil, err
		}
		i, ok := idx[id]
		if !ok {
			i = len(out)
			idx[id] = i
			out = append(out, RunEvents{RunID: id, At: at, Status: status, Counts: map[string]int{}})
		}
		if typ != nil {
			out[i].Counts[*typ] = n
		}
	}
	return out, rows.Err()
}

// EventAssetKeys: distinct asset keys that had an event of one of the given types in a run.
// The dashboard uses it so that a KPI tile and the list behind it count the same thing.
func (s *Store) EventAssetKeys(ctx context.Context, runID string, types []string) ([]string, error) {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT a.key FROM asset_events e JOIN assets a ON a.id=e.asset_id
		WHERE e.run_id=$1 AND e.type = ANY($2) ORDER BY 1`, runID, types)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var k string
		return k, r.Scan(&k)
	})
}

// AssetObservations: the newest observations of the given kinds for one asset
// (all of them from the latest run that has any), e.g. http + signature for the GUI.
func (s *Store) AssetObservations(ctx context.Context, key string, kinds ...string) ([]obs.Observation, error) {
	var run string
	err := s.DB.QueryRow(ctx, `SELECT run_id FROM observations WHERE asset_key=$1 AND kind = ANY($2)
		ORDER BY observed_at DESC LIMIT 1`, key, kinds).Scan(&run)
	if err == pgx.ErrNoRows {
		return []obs.Observation{}, nil
	} else if err != nil {
		return nil, err
	}
	all, err := s.Observations(ctx, run)
	if err != nil {
		return nil, err
	}
	out := []obs.Observation{}
	want := map[string]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	for _, o := range all {
		if o.AssetKey == key && want[string(o.Kind)] {
			out = append(out, o)
		}
	}
	return out, nil
}

// LatestSignatures: signature hits of the newest run that ran the signatures stage.
func (s *Store) LatestSignatures(ctx context.Context) (string, []obs.Observation, error) {
	var run string
	err := s.DB.QueryRow(ctx, `SELECT run_id FROM observations WHERE kind='signature' ORDER BY observed_at DESC LIMIT 1`).Scan(&run)
	if err == pgx.ErrNoRows {
		return "", nil, nil
	} else if err != nil {
		return "", nil, err
	}
	os, err := s.Observations(ctx, run, obs.KindSignature)
	return run, os, err
}

// LatestKind: observations of one kind from the newest run that produced that kind
// (e.g. http when the last scans skipped the http stage).
func (s *Store) LatestKind(ctx context.Context, kind obs.Kind) ([]obs.Observation, error) {
	var run string
	err := s.DB.QueryRow(ctx, `SELECT run_id FROM observations WHERE kind=$1 ORDER BY observed_at DESC LIMIT 1`, string(kind)).Scan(&run)
	if err == pgx.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return s.Observations(ctx, run, kind)
}

// ScannedHours: 24-bit mask (UTC) of hours in which scans ran during the last `days` days.
func (s *Store) ScannedHours(ctx context.Context, days int) (int, error) {
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT extract(hour from started_at AT TIME ZONE 'UTC')::int FROM runs
		WHERE started_at > now() - make_interval(days => $1) AND status IN ('completed','partial')`, days)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	m := 0
	for rows.Next() {
		var h int
		if rows.Scan(&h) == nil {
			m |= 1 << h
		}
	}
	return m, rows.Err()
}
