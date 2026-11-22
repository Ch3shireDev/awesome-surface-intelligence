package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

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
		// default: the newest completed run and the previous completed run OF THE SAME
		// target set (comparing different sets would report everything as new/gone)
		rs, err := s.Runs(ctx, 500)
		if err != nil {
			return findings.Diff{}, err
		}
		var newest *Run
		for i := range rs {
			r := &rs[i]
			if r.Status != "completed" {
				continue
			}
			if newest == nil {
				newest = r
				continue
			}
			if SetKey(r.SetName) == SetKey(newest.SetName) {
				a, b = r.ID, newest.ID
				break
			}
		}
		if a == "" {
			return findings.Diff{}, fmt.Errorf("brak dwóch zakończonych przebiegów tego samego zbioru celów")
		}
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
	d := findings.Compare(a, b, sa, sb, ua, ub)
	if ev, err := s.RunEventTypes(ctx, b); err == nil {
		d.Annotate(ev) // LAB-T5: the newer run's words from the history (missing vs gone, new vs reappeared)
	}
	return d, nil
}

// SetKey normalizes a run's set label: GUI runs used to store the frozen targets file name
// ("20261121-162414-lab-demo.json"), now the set name ("lab-demo") - both map to "lab-demo".
func SetKey(name string) string {
	n := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".json"), ".csv"), ".txt")
	if len(n) > 16 && n[8] == '-' && n[15] == '-' {
		if _, err := strconv.Atoi(n[:8]); err == nil {
			n = n[16:]
		}
	}
	return n
}
