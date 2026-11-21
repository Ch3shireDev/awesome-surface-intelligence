package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"asi/internal/findings"
	"asi/internal/obs"
	"asi/internal/progress"
	"asi/internal/safety"
	"asi/internal/scanner"
	httpxad "asi/internal/scanner/httpx"
	nucleiad "asi/internal/scanner/nuclei"
)

type webStages struct {
	runID, dir, httpMode, sigDir string
	parallel, rate               int
	chunkTimeout                 time.Duration
	tune                         tuning
	guard                        *safety.Policy
}

func haveTool(name string) bool { _, err := exec.LookPath(name); return err == nil }

// runWebStages: http (httpx) on web ports found by nmap, then signatures (nuclei with
// our templates) on the URLs that answered. Each stage only gets what the previous
// one found (VISION 4.3). Returns all observations of both stages.
func runWebStages(ctx context.Context, w webStages, svcs []findings.Service, tr *progress.Tracker, rec *dbRecorder) []obs.Observation {
	skip := func(phase, why string) {
		tr.Update(func(s *progress.State) { tr.Phase(phase).State = "skipped" })
		if why != "" {
			tr.Logf("%s: skipped (%s)", phase, why)
		}
	}
	urls := httpxad.URLs(svcs)
	switch {
	case w.httpMode == "off":
		skip("http", "")
		skip("signatures", "no http stage")
		return nil
	case !haveTool("httpx"):
		if w.httpMode == "on" {
			tr.Logf("http: httpx not installed")
		}
		skip("http", "httpx not installed")
		skip("signatures", "no http stage")
		return nil
	case len(urls) == 0 || ctx.Err() != nil:
		skip("http", "no web services")
		skip("signatures", "no web services")
		return nil
	}
	perProc := max(1, w.rate/w.parallel)
	var all []obs.Observation
	collect := func(stage string) func(scanner.ChunkResult) {
		return func(r scanner.ChunkResult) {
			if r.State == "killed" && ctx.Err() != nil {
				r.State = "deferred"
			}
			all = append(all, r.Observations...) // RunPhase calls onDone from workers: guard below
			rec.chunkDone(stage, stage, "jsonl", r)
		}
	}
	var mu sync.Mutex
	wrap := func(f func(scanner.ChunkResult)) func(scanner.ChunkResult) {
		return func(r scanner.ChunkResult) { mu.Lock(); defer mu.Unlock(); f(r) }
	}

	z := &scanner.Sizer{Target: 30 * time.Second, Min: 4, Max: 256, Start: 32}
	z.Seed(w.tune["http"])
	scanner.RunPhase(ctx, scanner.PhaseConfig{Name: "http", RunID: w.runID, Adapter: &httpxad.Adapter{},
		Stage: obs.StageConfig{RatePPS: perProc}, Parallel: w.parallel, Sizer: z, ChunkTimeout: w.chunkTimeout,
		OutDir: filepath.Join(w.dir, "http"), OnStart: rec.chunkStart("http"), Guard: w.guard}, urls, tr, wrap(collect("http")))
	if v := z.SecPerHost(); v > 0 {
		w.tune["http"] = v
	}
	httpObs := append([]obs.Observation(nil), all...)
	live := make([]progress.Service, 0, len(httpObs))
	for _, o := range httpObs {
		var d httpxad.HTTPData
		o.Decode(&d)
		live = append(live, progress.Service{Key: o.AssetKey, Label: httpLabel(d), Interest: "low"})
	}
	tr.AddServices(live)

	// signatures: nuclei with our templates on URLs that answered
	tdir := w.sigDir
	if tdir != "" {
		if st, err := os.Stat(tdir); err != nil || !st.IsDir() {
			tdir = ""
		}
	}
	switch {
	case tdir == "":
		skip("signatures", "no signatures directory")
	case !haveTool("nuclei"):
		skip("signatures", "nuclei not installed")
	case ctx.Err() != nil || len(httpObs) == 0:
		skip("signatures", "nothing answered over HTTP")
	default:
		targets := nucleiad.Targets(httpObs, svcs)
		zs := &scanner.Sizer{Target: 60 * time.Second, Min: 4, Max: 128, Start: 16}
		zs.Seed(w.tune["signatures"])
		scanner.RunPhase(ctx, scanner.PhaseConfig{Name: "signatures", RunID: w.runID,
			Adapter: &nucleiad.Adapter{Templates: tdir}, Stage: obs.StageConfig{RatePPS: perProc},
			Parallel: max(1, w.parallel/2), Sizer: zs, ChunkTimeout: w.chunkTimeout,
			OutDir: filepath.Join(w.dir, "signatures"), OnStart: rec.chunkStart("signatures"), Guard: w.guard}, targets, tr,
			wrap(func(r scanner.ChunkResult) {
				collect("signatures")(r)
				hits := make([]progress.Service, 0, len(r.Observations))
				for _, o := range r.Observations {
					var d obs.SignatureData
					o.Decode(&d)
					hits = append(hits, progress.Service{Key: o.AssetKey, Label: "sygnatura: " + d.Name, Interest: sevInterest(d.Severity)})
				}
				tr.AddServices(hits)
			}))
		if v := zs.SecPerHost(); v > 0 {
			w.tune["signatures"] = v
		}
	}
	return all
}

func httpLabel(d httpxad.HTTPData) string {
	l := d.Title
	if d.WebServer != "" {
		l += " · " + d.WebServer
	}
	for _, t := range d.Tech {
		l += " · " + t
	}
	return l
}

func sevInterest(sev string) string {
	switch sev {
	case "high", "critical":
		return "high"
	case "medium", "low":
		return "medium"
	}
	return "low"
}
