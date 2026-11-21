package importer

import (
	"context"
	"fmt"
	"time"

	"asi/internal/store"
)

type Options struct {
	// Coverage: "auto" - hosts/ports in the file count as scanned (nmap XML: exactly what nmap
	// probed; CSV/JSON: listed hosts and the union of listed ports), so a later import or scan
	// can mark them missing; "none" - observations only, nothing ever goes missing because of it.
	Coverage  string
	At        time.Time // when the scan happened (zero = now)
	By        *int64
	Reconcile store.ReconcileConfig
}

type Summary struct {
	RunID    string         `json:"run_id"`
	Format   string         `json:"format"`
	Rows     int            `json:"rows"`
	Hosts    int            `json:"hosts"`
	Obs      int            `json:"observations"`
	Coverage string         `json:"coverage"`
	Skipped  []string       `json:"skipped,omitempty"`
	Events   map[string]int `json:"events"`
}

// Import stores a parsed file as a run (trigger "import") and reconciles it.
func Import(ctx context.Context, st *store.Store, name string, data []byte, o Options) (Summary, error) {
	r, err := Parse(name, data)
	if err != nil {
		return Summary{}, err
	}
	if o.Coverage == "" {
		o.Coverage = "auto"
	}
	at := o.At
	if at.IsZero() {
		at = time.Now()
	}
	historical := false
	if last, err := st.LatestReconciledStart(ctx); err == nil && !last.IsZero() && at.Before(last) {
		// older than what the assets already reflect: keep as history, do not rewind states
		historical, o.Coverage = true, "none"
	}
	id := at.UTC().Format("20060102-150405") + "-imp"
	if err := st.CreateRun(ctx, id, "import:"+name, "import", map[string]any{"file": name, "format": r.Format, "coverage": o.Coverage}); err != nil {
		return Summary{}, fmt.Errorf("run: %w", err)
	}
	st.SetRunStart(ctx, id, at)
	if o.Coverage == "auto" {
		// chunk records = coverage for reconcile (VISION 4.7)
		st.StartChunk(ctx, id, "discovery", 0, r.Hosts)
		st.FinishChunk(ctx, id, "discovery", 0, "done", 0, "")
		st.StartChunk(ctx, id, "services", 0, r.Hosts)
		st.FinishChunk(ctx, id, "services", 0, "done", 0, "")
		st.SetChunkPorts(ctx, id, "services", 0, r.Ports)
	}
	for i := range r.Observations {
		r.Observations[i].ObservedAt = at.UTC()
	}
	if err := st.InsertObservations(ctx, id, "import", 0, r.Observations); err != nil {
		st.FinishRun(ctx, id, "failed", map[string]any{"error": err.Error()})
		return Summary{}, err
	}
	if err := st.SaveImportRaw(ctx, id, r.Format, data); err != nil {
		return Summary{}, err
	}
	up := 0
	for _, x := range r.Observations {
		if x.Kind == "host" {
			up++
		}
	}
	st.FinishRun(ctx, id, "completed", map[string]any{"imported": name, "format": r.Format, "rows": r.Rows,
		"targets": len(r.Hosts), "hosts_up": up, "observations": len(r.Observations)})
	s := Summary{RunID: id, Format: r.Format, Rows: r.Rows, Hosts: len(r.Hosts), Obs: len(r.Observations),
		Coverage: o.Coverage, Skipped: r.Skipped}
	if historical {
		s.Coverage = "none (import starszy niż ostatni przebieg: zapisany jako historia, stany assetów bez zmian)"
		return s, nil
	}
	rr, err := st.Reconcile(ctx, id, o.Reconcile)
	if err != nil {
		return s, fmt.Errorf("reconcile: %w", err)
	}
	s.Events = rr.Counts
	return s, nil
}
