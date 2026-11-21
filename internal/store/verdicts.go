package store

import (
	"context"
	"encoding/json"
	"fmt"

	"asi/internal/findings"
	"asi/internal/obs"
)

// Verdicts: analyst decisions (assets.user_overrides) keyed by asset key.
func (s *Store) Verdicts(ctx context.Context) (map[string]findings.Verdict, error) {
	rows, err := s.DB.Query(ctx, `SELECT key, user_overrides FROM assets WHERE user_overrides <> '{}'::jsonb`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]findings.Verdict{}
	for rows.Next() {
		var k string
		var raw []byte
		if rows.Scan(&k, &raw) != nil {
			continue
		}
		var v findings.Verdict
		if json.Unmarshal(raw, &v) == nil && (v.Status != "" || v.Interest != "") {
			out[k] = v
		}
	}
	return out, rows.Err()
}

// DiffRuns compares two runs stored in the database (ports/services and live hosts).
func (s *Store) DiffRuns(ctx context.Context, a, b string) (findings.Diff, error) {
	if a == "" || b == "" {
		rs, err := s.Runs(ctx, 100)
		if err != nil {
			return findings.Diff{}, err
		}
		var done []string
		for _, r := range rs {
			if r.Status == "completed" {
				done = append(done, r.ID)
			}
		}
		if len(done) < 2 {
			return findings.Diff{}, fmt.Errorf("potrzebne są dwa zakończone przebiegi, jest %d", len(done))
		}
		a, b = done[1], done[0]
	}
	load := func(id string) ([]findings.Service, []string, error) {
		os, err := s.Observations(ctx, id, obs.KindPort, obs.KindService)
		if err != nil {
			return nil, nil, err
		}
		up, err := s.LiveHosts(ctx, id)
		return findings.FromObservations(os, nil), up, err
	}
	sa, ua, err := load(a)
	if err != nil {
		return findings.Diff{}, err
	}
	sb, ub, err := load(b)
	if err != nil {
		return findings.Diff{}, err
	}
	return findings.Compare(a, b, sa, sb, ua, ub), nil
}
