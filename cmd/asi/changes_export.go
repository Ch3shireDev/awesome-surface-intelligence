package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"asi/internal/dojo"
	"asi/internal/store"
)

// exportChanges sends the "asi-changes" test to DefectDojo (SEC-7): conditions from
// reconcile (missing / gone / flapping / latest change) as Generic Findings.
// closeOld must be false for partial runs: a run that did not cover the whole set
// must never close anything in DefectDojo (coverage rule, VISION 4.7).
// Only assets of the run's targets go out (scope = IPs of the run's plan): assets are
// global in the database, and conditions of other target sets must not land in this
// run's DefectDojo product. An empty scope sends nothing.
// The report is also written to dir/findings_changes.json when dir != "".
func exportChanges(dd *dojo.Client, st *store.Store, t dojo.Target, closeOld bool, scope map[string]bool, dir string, logf func(string, ...any)) {
	if dd == nil || st == nil {
		return
	}
	if len(scope) == 0 {
		logf("dojo: asi-changes skipped: no targets in the run's plan")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	assets, err := st.Assets(ctx, store.AssetFilter{Limit: 1_000_000})
	if err != nil {
		logf("dojo: asi-changes: assets: %v", err)
		return
	}
	events, err := st.Events(ctx, "", "", 1_000_000)
	if err != nil {
		logf("dojo: asi-changes: events: %v", err)
		return
	}
	assets, events = inScope(assets, events, scope)
	report := dojo.ChangesJSON(assets, events)
	if dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "findings_changes.json"), report, 0o644); err != nil {
			logf("dojo: asi-changes: %v", err)
		}
	}
	t.ScanType, t.TestTitle = "Generic Findings Import", dojo.ChangesTestTitle
	t.Tags = append(append([]string{}, t.Tags...), "asi-changes")
	res, err := dd.Reimport("asi-changes.json", report, t, closeOld)
	if err != nil {
		logf("dojo: asi-changes: %v", err)
		return
	}
	logf("dojo: asi-changes %d conditions (close_old=%v) -> %s/test/%d, delta %v",
		countFindings(report), closeOld, dd.URL, res.Test, res.Delta)
}

// inScope keeps assets whose IP is in scope and events of those assets.
func inScope(assets []store.Asset, events []store.Event, scope map[string]bool) ([]store.Asset, []store.Event) {
	keys := map[string]bool{}
	var as []store.Asset
	for _, a := range assets {
		if scope[a.IP] {
			as = append(as, a)
			keys[a.Key] = true
		}
	}
	var ev []store.Event
	for _, e := range events {
		if keys[e.Key] {
			ev = append(ev, e)
		}
	}
	return as, ev
}

// planScope reads the target IPs of a run from results/<run>/plan.json.
func planScope(runDir string) map[string]bool {
	b, err := os.ReadFile(filepath.Join(runDir, "plan.json"))
	if err != nil {
		return nil
	}
	var p struct {
		Hosts []struct {
			IP string `json:"ip"`
		} `json:"hosts"`
	}
	json.Unmarshal(b, &p)
	out := map[string]bool{}
	for _, h := range p.Hosts {
		out[h.IP] = true
	}
	return out
}

func countFindings(report []byte) int {
	var r struct {
		Findings []json.RawMessage `json:"findings"`
	}
	json.Unmarshal(report, &r)
	return len(r.Findings)
}

// runIsPartial reads results/<run>/run.json: an interrupted run (window closed,
// Ctrl+C) covered only part of its targets.
func runIsPartial(runDir string) bool {
	b, err := os.ReadFile(filepath.Join(runDir, "run.json"))
	if err != nil {
		return false
	}
	var r struct {
		Status string `json:"status"`
	}
	json.Unmarshal(b, &r)
	return r.Status == "interrupted"
}
