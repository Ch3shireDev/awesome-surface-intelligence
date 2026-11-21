package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type Schedule struct {
	ID            int64           `json:"id"`
	Name          string          `json:"name"`
	Set           string          `json:"set"`
	Cron          string          `json:"cron"`
	WindowMinutes int             `json:"window_minutes"`
	Params        json.RawMessage `json:"params"`
	Enabled       bool            `json:"enabled"`
	NextRunAt     *time.Time      `json:"next_run_at"`
	LastRunAt     *time.Time      `json:"last_run_at"`
	LastRunID     string          `json:"last_run_id"`
	LastError     string          `json:"last_error"`
}

const schedCols = `id, name, set_name, cron, window_minutes, params, enabled, next_run_at, last_run_at, last_run_id, last_error`

func scanSchedule(r pgx.CollectableRow) (Schedule, error) {
	var s Schedule
	err := r.Scan(&s.ID, &s.Name, &s.Set, &s.Cron, &s.WindowMinutes, &s.Params, &s.Enabled, &s.NextRunAt, &s.LastRunAt, &s.LastRunID, &s.LastError)
	return s, err
}

func (s *Store) Schedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+schedCols+` FROM schedules ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSchedule)
}

// SaveSchedule inserts (ID==0) or updates a schedule; next is the computed next start.
func (s *Store) SaveSchedule(ctx context.Context, sc Schedule, next *time.Time, by *int64) (Schedule, error) {
	if len(sc.Params) == 0 {
		sc.Params = json.RawMessage(`{}`)
	}
	var row pgx.Rows
	var err error
	if sc.ID == 0 {
		row, err = s.DB.Query(ctx, `INSERT INTO schedules (name, set_name, cron, window_minutes, params, enabled, next_run_at, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+schedCols,
			sc.Name, sc.Set, sc.Cron, sc.WindowMinutes, []byte(sc.Params), sc.Enabled, next, by)
	} else {
		row, err = s.DB.Query(ctx, `UPDATE schedules SET name=$2, set_name=$3, cron=$4, window_minutes=$5, params=$6, enabled=$7,
			next_run_at=$8, last_error='' WHERE id=$1 RETURNING `+schedCols,
			sc.ID, sc.Name, sc.Set, sc.Cron, sc.WindowMinutes, []byte(sc.Params), sc.Enabled, next)
	}
	if err != nil {
		return sc, err
	}
	return pgx.CollectExactlyOneRow(row, scanSchedule)
}

func (s *Store) DeleteSchedule(ctx context.Context, id int64) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM schedules WHERE id=$1`, id)
	return err
}

// DueSchedules: enabled schedules whose next start has come.
func (s *Store) DueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+schedCols+` FROM schedules WHERE enabled AND next_run_at IS NOT NULL AND next_run_at <= $1 ORDER BY next_run_at`, now)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSchedule)
}

// MarkScheduleFired records an attempt (started or skipped) and the next start.
func (s *Store) MarkScheduleFired(ctx context.Context, id int64, firedAt time.Time, next *time.Time, errMsg string) error {
	_, err := s.DB.Exec(ctx, `UPDATE schedules SET last_run_at=$2, next_run_at=$3, last_error=$4 WHERE id=$1`, id, firedAt, next, errMsg)
	return err
}

func (s *Store) SetScheduleLastRun(ctx context.Context, id int64, runID string) error {
	_, err := s.DB.Exec(ctx, `UPDATE schedules SET last_run_id=$2 WHERE id=$1`, id, runID)
	return err
}

// ---- run linkage and resume ----

// SetRunLinks marks a run as started by a schedule and/or continuing another run.
func (s *Store) SetRunLinks(ctx context.Context, runID string, scheduleID int64, resumeOf string) error {
	var sid *int64
	if scheduleID > 0 {
		sid = &scheduleID
	}
	_, err := s.DB.Exec(ctx, `UPDATE runs SET schedule_id=$2, resume_of=$3 WHERE id=$1`, runID, sid, resumeOf)
	if err == nil && resumeOf != "" {
		_, err = s.DB.Exec(ctx, `UPDATE runs SET resumed_by=$2 WHERE id=$1`, resumeOf, runID)
	}
	return err
}

func (s *Store) SetPending(ctx context.Context, runID string, pending []string) error {
	_, err := s.DB.Exec(ctx, `UPDATE runs SET pending_targets=$2 WHERE id=$1`, runID, nonNil(pending))
	return err
}

// Resumable returns the newest partial run with pending targets not yet taken over,
// optionally restricted to a schedule (scheduleID > 0).
func (s *Store) Resumable(ctx context.Context, scheduleID int64) (string, []string, error) {
	q := `SELECT id, pending_targets FROM runs WHERE status='partial' AND cardinality(pending_targets) > 0 AND resumed_by=''`
	args := []any{}
	if scheduleID > 0 {
		q += ` AND schedule_id=$1`
		args = append(args, scheduleID)
	}
	var id string
	var p []string
	err := s.DB.QueryRow(ctx, q+` ORDER BY started_at DESC LIMIT 1`, args...).Scan(&id, &p)
	if err == pgx.ErrNoRows {
		return "", nil, nil
	}
	return id, p, err
}

func (s *Store) RunPending(ctx context.Context, runID string) ([]string, string, error) {
	var p []string
	var by string
	err := s.DB.QueryRow(ctx, `SELECT pending_targets, resumed_by FROM runs WHERE id=$1`, runID).Scan(&p, &by)
	return p, by, err
}

// LatestRunSince: newest run started at or after t (the run of a just-finished subprocess).
func (s *Store) LatestRunSince(ctx context.Context, t time.Time) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, `SELECT id FROM runs WHERE started_at >= $1::timestamptz - interval '5 seconds' ORDER BY started_at DESC LIMIT 1`, t).Scan(&id)
	return id, err
}

// CancelRun: a cancelled run keeps its results but its leftovers are not resumed.
func (s *Store) CancelRun(ctx context.Context, id string) error {
	_, err := s.DB.Exec(ctx, `UPDATE runs SET status='cancelled', pending_targets='{}' WHERE id=$1 AND status IN ('partial','running')`, id)
	return err
}

// SetRunStart backdates a run (imports of older scans keep their real time).
func (s *Store) SetRunStart(ctx context.Context, id string, at time.Time) error {
	_, err := s.DB.Exec(ctx, `UPDATE runs SET started_at=$2 WHERE id=$1`, id, at)
	return err
}

// SaveImportRaw keeps the imported file as evidence (sealed like any raw output).
func (s *Store) SaveImportRaw(ctx context.Context, runID, format string, data []byte) error {
	if _, err := s.DB.Exec(ctx, `INSERT INTO chunks (run_id, stage, id, targets, size, status, started_at, finished_at)
		VALUES ($1,'import',0,'{}',0,'done',now(),now()) ON CONFLICT DO NOTHING`, runID); err != nil {
		return err
	}
	return s.SaveRaw(ctx, runID, "import", 0, "import", format, data)
}

func (s *Store) LatestReconciledStart(ctx context.Context) (time.Time, error) {
	var t *time.Time
	err := s.DB.QueryRow(ctx, `SELECT max(started_at) FROM runs WHERE reconciled_at IS NOT NULL`).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}
