// asi - Attack Surface Intelligence PoC.
//
//	asi convert -in targets/targets.csv -out targets/targets.json
//	asi plan    [-targets targets/targets.csv]
//	asi scan    [-targets ...] [-parallel 5] [-rate 300] [-ui 127.0.0.1:8090] [-upload live|end|off]
//	asi upload  [-run results/<id>]
//	asi diff    [runA runB]          (default: two latest)
//	asi serve   [-addr 127.0.0.1:8090]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"asi/internal/cli"
	"asi/internal/dojo"
	"asi/internal/findings"
	"asi/internal/obs"
	"asi/internal/progress"
	"asi/internal/scanner"
	nmapad "asi/internal/scanner/nmap"
	"asi/internal/targets"
	"asi/internal/web"
)

const (
	defaultDiscovery = nmapad.DefaultDiscoveryArgs
	defaultServices  = nmapad.DefaultServicesArgs
)

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "convert":
		cmdConvert(args)
	case "plan":
		cmdPlan(args)
	case "scan":
		cmdScan(args)
	case "upload":
		cmdUpload(args)
	case "diff":
		cmdDiff(args)
	case "serve":
		cmdServe(args)
	case "db":
		cmdDB(args)
	case "server":
		cmdServer(args)
	case "changes":
		cmdChanges(args)
	case "assets":
		cmdAssets(args)
	case "asset":
		cmdAsset(args)
	case "targets-extract":
		cmdTargetsExtract(args)
	case "mcp":
		cmdMCP(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: asi <server|convert|plan|scan|upload|diff|serve|db|changes|assets|asset|targets-extract|mcp> [flags]   (asi <cmd> -h)")
	os.Exit(2)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	must(os.WriteFile(path, append(b, '\n'), 0o644))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// ddClient builds a DefectDojo client from the environment (same .env as the
// compose stack): DD_URL (default http://localhost:${DD_PORT:-8080}), token
// from DD_TOKEN or DD_API_KEY, otherwise a login with DD_ADMIN_USER/DD_ADMIN_PASSWORD.
func ddClient() (*dojo.Client, error) {
	url := strings.TrimRight(envOr("DD_URL", "http://localhost:"+envOr("DD_PORT", "8080")), "/")
	c := &dojo.Client{URL: url, Token: envOr("DD_TOKEN", os.Getenv("DD_API_KEY"))}
	if c.Token != "" {
		return c, nil
	}
	user, pass := envOr("DD_ADMIN_USER", "admin"), os.Getenv("DD_ADMIN_PASSWORD")
	if pass == "" {
		return nil, fmt.Errorf("set DD_TOKEN / DD_API_KEY or DD_ADMIN_PASSWORD (e.g. `set -a; . ./.env`)")
	}
	tok, err := c.Login(user, pass)
	if err != nil {
		return nil, fmt.Errorf("DefectDojo login as %s: %w", user, err)
	}
	c.Token = tok
	return c, nil
}

// ---------------------------------------------------------------- convert / plan

func cmdConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	in := fs.String("in", "targets/targets.csv", "input (.csv/.json/.txt)")
	out := fs.String("out", "targets/targets.json", "output .json")
	fs.Parse(args)
	ts, err := targets.Load(*in)
	must(err)
	must(targets.SaveJSON(*out, ts))
	log.Printf("%d targets -> %s", len(ts), *out)
}

type planFlags struct {
	targets          *string
	skipCDN, onlyInv *bool
}

func addPlanFlags(fs *flag.FlagSet) planFlags {
	return planFlags{
		targets: fs.String("targets", "targets/targets.csv", "targets file (.csv/.json/.txt)"),
		skipCDN: fs.Bool("skip-cdn", true, "don't scan CDN (Cloudflare) edge IPs behind domains"),
		onlyInv: fs.Bool("only-inventory", true, "domains only label IPs already listed as IP/CIDR targets"),
	}
}

func (p planFlags) build() targets.Plan {
	ts, err := targets.Load(*p.targets)
	must(err)
	return policyPlan(policy(), targets.BuildPlan(ts, targets.PlanOptions{SkipCDN: *p.skipCDN, OnlyInventory: *p.onlyInv}))
}

func cmdPlan(args []string) {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	pf := addPlanFlags(fs)
	out := fs.String("o", "", "write plan JSON here (default: table on stdout)")
	fs.Parse(args)
	plan := pf.build()
	log.Printf("%d unique IPs to scan, %d skipped", len(plan.Hosts), len(plan.Skipped))
	if *out != "" {
		writeJSON(*out, plan)
		return
	}
	for _, h := range plan.Hosts {
		fmt.Printf("%-16s %-20s %s\n", h.IP, strings.Join(h.Assets, ","), strings.Join(h.Domains, " "))
	}
	fmt.Println("\nskipped:")
	for _, s := range plan.Skipped {
		fmt.Printf("  %-36s %s %v\n", s.Target, s.Reason, s.IPs)
	}
}

// ---------------------------------------------------------------- scan

type tuning map[string]float64 // phase -> seconds per host

func loadTuning(path string) tuning {
	t := tuning{}
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &t)
	return t
}

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	pf := addPlanFlags(fs)
	parallel := fs.Int("parallel", 5, "nmap processes at once")
	rate := fs.Int("rate", 300, "GLOBAL packet rate limit (pps), split evenly between nmap processes")
	chunk := fs.Int("chunk", 0, "fixed hosts per service chunk (0 = adaptive)")
	target := fs.Duration("chunk-target", 45*time.Second, "adaptive: desired duration of one service chunk")
	dChunk := fs.Int("discovery-chunk", 0, "fixed hosts per discovery chunk (0 = adaptive)")
	discArgs := fs.String("discovery-args", defaultDiscovery, "nmap args for host discovery")
	svcArgs := fs.String("nmap", defaultServices, "nmap args for service scan")
	skipDisc := fs.Bool("skip-discovery", false, "treat every IP as up (for networks dropping probes)")
	chunkTimeout := fs.Duration("chunk-timeout", 20*time.Minute, "kill a single nmap after this")
	window := fs.Duration("window", 0, "scan window: stop everything after this (e.g. 2h), 0 = no limit")
	outRoot := fs.String("out", "results", "results directory")
	uiWait := fs.Bool("ui-wait", true, "with -ui: keep the panel open after the scan until Ctrl+C")
	ui := fs.String("ui", "", "serve live web panel on this address, e.g. 127.0.0.1:8090")
	dbURL := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL; empty = files only (env ASI_DATABASE_URL)")
	recCfg := reconcileFlags(fs)
	resume := fs.String("resume", "", "continue a partial run: scan only its targets not covered when its window closed")
	scheduleID := fs.Int64("schedule-id", 0, "set by the scheduler (links the run to a schedule)")
	trigger := fs.String("trigger", "manual", "manual | schedule (recorded in the database)")
	upload := fs.String("upload", "off", "DefectDojo: off | end (one reimport) | live (per chunk + final)")
	product := fs.String("product", envOr("DD_PRODUCT", "ASI PoC"), "DefectDojo product (env DD_PRODUCT)")
	eng := fs.String("engagement", "discovery", "DefectDojo engagement")
	fs.Parse(args)

	// SEC-8: hard limits from .env win over flags; profile args must pass the nmap allow-list
	pol := policy()
	var limitNotes []string
	*rate, *parallel, limitNotes = pol.Limits(*rate, *parallel)
	checkNmapArgs(pol, "-discovery-args", *discArgs)
	checkNmapArgs(pol, "-nmap", *svcArgs)

	runID := time.Now().Format("20060102-150405")
	dir := filepath.Join(*outRoot, runID)
	must(os.MkdirAll(dir, 0o755))
	tr := progress.New(runID, *parallel, filepath.Join(dir, "events.ndjson"))
	if *window > 0 {
		tr.Update(func(s *progress.State) { s.Window = window.String() })
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *window > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *window)
		defer cancel()
	}

	var srv *http.Server
	if *ui != "" {
		srv = startUI(*ui, &web.Server{Tracker: tr, ResultsDir: *outRoot})
	}
	bar := cli.NewBar(tr)
	bar.Start()
	tr.Logf("policy: %s", pol)
	for _, n := range limitNotes {
		tr.Logf("policy: %s", n)
	}

	var rec *dbRecorder
	if st, err := openStore(context.Background(), *dbURL); err != nil {
		tr.Logf("db: %v - continuing with files only", err)
	} else if st != nil {
		defer st.Close()
		rec = &dbRecorder{st: st, runID: runID, logf: tr.Logf}
		tr.Logf("db: recording run %s", runID)
	}

	// --- plan (or: the not-yet-scanned remainder of a partial run)
	var plan targets.Plan
	setLabel := filepath.Base(*pf.targets)
	if *resume != "" {
		var err error
		plan, err = resumePlan(*outRoot, *resume, rec)
		if err != nil {
			bar.Stop()
			log.Fatalf("resume %s: %v", *resume, err)
		}
		plan = policyPlan(pol, plan)
		setLabel = "resume:" + *resume
		tr.Logf("resume: %d targets left over from %s", len(plan.Hosts), *resume)
	} else {
		plan = pf.build()
	}
	writeJSON(filepath.Join(dir, "plan.json"), plan)
	meta := map[string]targets.Host{}
	ips := make([]string, len(plan.Hosts))
	for i, h := range plan.Hosts {
		ips[i], meta[h.IP] = h.IP, h
	}
	tr.Update(func(s *progress.State) {
		s.Targets, s.Skipped, s.Status = len(ips), len(plan.Skipped), "running"
	})
	tr.Logf("plan: %d IPs, %d targets skipped (see plan.json)", len(ips), len(plan.Skipped))
	rec.start(setLabel, *trigger, *scheduleID, *resume, map[string]any{"parallel": *parallel, "rate_pps": *rate,
		"discovery_args": *discArgs, "nmap_args": *svcArgs, "window": window.String(), "targets": len(ips),
		"policy": pol.Summary()})

	tunePath := filepath.Join(*outRoot, "tuning.json")
	tune := loadTuning(tunePath)
	perProcN := max(1, *rate / *parallel)
	perProc := fmt.Sprint(perProcN)
	stageCfg := obs.StageConfig{RatePPS: perProcN}
	var (
		obsMu  sync.Mutex
		allObs []obs.Observation // every observation of this run (-> observations.json, database)
	)
	keep := func(o []obs.Observation) { obsMu.Lock(); allObs = append(allObs, o...); obsMu.Unlock() }

	// --- dojo (live uploads go through one goroutine so scanning never waits on HTTP)
	var dd *dojo.Client
	ddTarget := dojo.Target{ScanType: "Generic Findings Import", ProductType: envOr("DD_PRODUCT_TYPE", "Research and Development"),
		Product: *product, Engagement: *eng, TestTitle: "ASI discovery", Tags: []string{"asi"}}
	upQ := make(chan []findings.Service, 64)
	var upWG sync.WaitGroup
	if *upload != "off" {
		var err error
		if dd, err = ddClient(); err != nil {
			tr.Logf("upload=%s but no DefectDojo credentials (%v) - skipping DefectDojo", *upload, err)
		}
	}
	if dd != nil && *upload == "live" {
		upWG.Add(1)
		go func() {
			defer upWG.Done()
			for batch := range upQ {
				uploadBatch(dd, ddTarget, batch, false, tr)
			}
		}()
	}

	// --- phase 1: discovery
	var up []string
	var upMu sync.Mutex
	var discRes []scanner.ChunkResult
	if *skipDisc {
		up = ips
		tr.Update(func(s *progress.State) { tr.Phase("discovery").State = "skipped"; s.HostsUp = len(ips) })
	} else {
		z := &scanner.Sizer{Fixed: *dChunk, Target: 20 * time.Second, Min: 16, Max: 1024, Start: 64}
		z.Seed(tune["discovery"])
		discRes = scanner.RunPhase(ctx, scanner.PhaseConfig{Name: "discovery", RunID: runID, Adapter: nmapad.Discovery(*discArgs),
			Stage: stageCfg, Parallel: *parallel, Sizer: z, ChunkTimeout: *chunkTimeout,
			OutDir: filepath.Join(dir, "discovery"), OnStart: rec.chunkStart("discovery"), Guard: pol}, ips, tr,
			func(r scanner.ChunkResult) {
				keep(r.Observations)
				if r.State == "killed" && ctx.Err() != nil {
					r.State = "deferred" // cut by the scan window -> resumes in the next window
				}
				rec.chunkDone("discovery", "nmap", "nmap-xml", r)
				n := 0
				upMu.Lock()
				for _, o := range r.Observations {
					if o.Kind == obs.KindHost {
						up = append(up, o.AssetKey)
						n++
					}
				}
				upMu.Unlock()
				tr.Update(func(s *progress.State) { s.HostsUp += n })
			})
		if v := z.SecPerHost(); v > 0 {
			tune["discovery"] = v
		}
	}
	up = sortIPs(up)
	writeJSON(filepath.Join(dir, "hosts_up.json"), up)

	// --- phase 2: services on live hosts
	var (
		svcMu sync.Mutex
		svcs  []findings.Service
	)
	z := &scanner.Sizer{Fixed: *chunk, Target: *target, Min: 1, Max: 64, Start: 4}
	z.Seed(tune["services"])
	svcRes := scanner.RunPhase(ctx, scanner.PhaseConfig{Name: "services", RunID: runID, Adapter: nmapad.Services(*svcArgs),
		Stage: stageCfg, Parallel: *parallel, Sizer: z, ChunkTimeout: *chunkTimeout,
		OutDir: filepath.Join(dir, "services"), OnStart: rec.chunkStart("services"), Guard: pol}, up, tr,
		func(r scanner.ChunkResult) {
			keep(r.Observations)
			if r.State == "killed" && ctx.Err() != nil {
				r.State = "deferred"
			}
			rec.chunkDone("services", "nmap", "nmap-xml", r)
			got := findings.FromObservations(r.Observations, meta)
			svcMu.Lock()
			svcs = append(svcs, got...)
			svcMu.Unlock()
			live := make([]progress.Service, len(got))
			for i, s := range got {
				live[i] = progress.Service{Key: s.Key(), Label: strings.TrimSpace(s.Fingerprint() + " · " + s.Reason),
					Interest: s.Interest, Domains: strings.Join(s.Domains, " ")}
			}
			tr.AddServices(live)
			tr.Update(func(s *progress.State) { s.Open += len(got) })
			if dd != nil && *upload == "live" && len(got) > 0 {
				upQ <- got
			}
		})
	if v := z.SecPerHost(); v > 0 {
		tune["services"] = v
	}
	writeJSON(tunePath, tune)

	// --- confirmation: services that vanished since the previous run while their host
	// is still up get one more, slower look before we call them gone (and close them in DefectDojo).
	if prev := previousRun(*outRoot, runID); prev != "" && ctx.Err() == nil {
		old, _ := findings.Load(filepath.Join(*outRoot, prev, "services.json"))
		have, isUp := map[string]bool{}, map[string]bool{}
		for _, s := range svcs {
			have[s.Key()] = true
		}
		for _, ip := range up {
			isUp[ip] = true
		}
		recheck, n := map[string][]int{}, 0
		for _, o := range old {
			if !have[o.Key()] && isUp[o.IP] && o.Proto == "tcp" {
				recheck[o.IP] = append(recheck[o.IP], o.Port)
				n++
			}
		}
		if n > 0 {
			tr.Logf("confirm: %d services vanished since %s on live hosts - re-checking", n, prev)
			args := append(strings.Fields("-sT -sV --version-light -Pn -T3 --max-retries 4"), "--max-rate", perProc)
			hosts := scanner.Confirm(ctx, recheck, args, *parallel, filepath.Join(dir, "confirm"), pol, perProcN, tr.Logf)
			confirmed := nmapad.FromHosts(hosts)
			keep(confirmed)
			rec.observations("confirm", confirmed)
			back := findings.FromObservations(confirmed, meta)
			for i := range back {
				back[i].Tags = append(back[i].Tags, "unstable")
				tr.Logf("confirm: %s still open (missed by first pass) - kept, tagged unstable", back[i].Key())
			}
			svcs = append(svcs, back...)
			tr.Update(func(s *progress.State) { s.Open += len(back) })
			if len(back) < n {
				tr.Logf("confirm: %d services really gone", n-len(back))
			}
		}
	}
	close(upQ)
	upWG.Wait()

	// --- outputs
	interrupted := ctx.Err() != nil
	// targets not covered by finished chunks: discovery leftovers + live hosts without a service scan
	pending := scanner.Unscanned(up, svcRes)
	if !*skipDisc {
		pending = append(scanner.Unscanned(ips, discRes), pending...)
	}
	pending = sortIPs(uniq(pending))
	if len(pending) > 0 {
		tr.Logf("pending: %d targets not covered - resume with: asi scan -resume %s", len(pending), runID)
	}
	findings.Sort(svcs)
	must(findings.Save(filepath.Join(dir, "services.json"), svcs))
	must(os.WriteFile(filepath.Join(dir, "findings_defectdojo.json"), findings.GenericJSON(svcs), 0o644))
	obs.Sort(allObs)
	writeJSON(filepath.Join(dir, "observations.json"), allObs)
	var xmls []string
	for _, r := range svcRes {
		xmls = append(xmls, r.Output)
	}
	domains := map[string][]string{}
	for ip, h := range meta {
		domains[ip] = h.Domains
	}
	scanner.MergeXML(filepath.Join(dir, "merged.xml"), xmls, domains)

	// final reimport: closes findings that disappeared - but only after a COMPLETE run,
	// otherwise hosts we never reached would be wrongly marked as mitigated.
	if dd != nil {
		uploadBatch(dd, ddTarget, svcs, !interrupted, tr)
	}

	status := "done"
	if interrupted {
		status = "interrupted"
	}
	hi, med := 0, 0
	for _, s := range svcs {
		switch s.Interest {
		case "high":
			hi++
		case "medium":
			med++
		}
	}
	snap := tr.Snapshot()
	writeJSON(filepath.Join(dir, "run.json"), map[string]any{
		"id": runID, "started": snap.Started, "duration_s": snap.Elapsed, "status": status,
		"targets": len(ips), "skipped": len(plan.Skipped), "hosts_up": len(up), "open": len(svcs),
		"interest_high": hi, "interest_medium": med, "dojo_test": snap.Upload.TestURL,
		"phases": snap.Phases, "parallel": *parallel, "rate_pps": *rate,
		"discovery_args": *discArgs, "nmap_args": *svcArgs, "pending": pending, "resume_of": *resume,
		"policy": pol.Summary(),
	})
	dbStatus := "completed"
	if interrupted {
		dbStatus = "partial" // coverage rule: unscanned chunks must not produce "missing"
	}
	rec.finish(dbStatus, map[string]any{"duration_s": snap.Elapsed, "targets": len(ips), "skipped": len(plan.Skipped),
		"hosts_up": len(up), "open": len(svcs), "interest_high": hi, "interest_medium": med, "dojo_test": snap.Upload.TestURL})
	rec.pending(pending)
	rec.reconcile(*recCfg)
	tr.Update(func(s *progress.State) { s.Status = status })
	tr.Logf("run %s %s: %d/%d hosts up, %d open services (%d high, %d medium) -> %s", runID, status, len(up), len(ips), len(svcs), hi, med, dir)
	time.Sleep(300 * time.Millisecond)
	bar.Stop()
	writeJSON(filepath.Join(dir, "final_state.json"), tr.Snapshot())
	tr.Close()

	if prev := previousRun(*outRoot, runID); prev != "" {
		if d, err := web.DiffRuns(filepath.Join(*outRoot, prev), dir); err == nil {
			printDiff(d)
		}
	}
	if srv != nil && !*uiWait {
		time.Sleep(2 * time.Second) // let the panel show the final state
		srv.Close()
	} else if srv != nil {
		fmt.Fprintf(os.Stderr, "panel: http://%s  (Ctrl+C aby zamknąć)\n", *ui)
		stop()
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		srv.Close()
	}
}

func uploadBatch(dd *dojo.Client, t dojo.Target, svcs []findings.Service, closeOld bool, tr *progress.Tracker) {
	tr.Update(func(s *progress.State) { s.Upload.State = "running" })
	res, err := dd.Reimport("asi-findings.json", findings.GenericJSON(svcs), t, closeOld)
	tr.Update(func(s *progress.State) {
		s.Upload.Batches++
		if err != nil {
			s.Upload.State, s.Upload.Last = "failed", err.Error()
			return
		}
		s.Upload.State = "done"
		s.Upload.TestURL = fmt.Sprintf("%s/test/%d", dd.URL, res.Test)
		s.Upload.Delta = res.Delta
		s.Upload.Last = fmt.Sprintf("%d findings, close_old=%v", len(svcs), closeOld)
	})
	if err != nil {
		tr.Logf("dojo: %v", err)
	} else {
		tr.Logf("dojo: reimport %d findings (close_old=%v) -> test %d, delta %v", len(svcs), closeOld, res.Test, res.Delta)
	}
}

func startUI(addr string, s *web.Server) *http.Server {
	ln, err := net.Listen("tcp", addr)
	must(err)
	srv := &http.Server{Handler: s.Handler()}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("ui: %v", err)
		}
	}()
	fmt.Fprintf(os.Stderr, "panel: http://%s\n", addr)
	return srv
}

func sortIPs(ips []string) []string {
	s := make([]findings.Service, len(ips))
	for i, ip := range ips {
		s[i] = findings.Service{IP: ip}
	}
	findings.Sort(s)
	out := make([]string, len(s))
	for i := range s {
		out[i] = s[i].IP
	}
	return out
}

func previousRun(root, current string) string {
	for _, r := range web.ListRuns(root) {
		if r.ID < current && r.Status == "done" {
			return r.ID
		}
	}
	return ""
}

// ---------------------------------------------------------------- upload / diff / serve

func latestRun(root string) string {
	runs := web.ListRuns(root)
	if len(runs) == 0 {
		log.Fatal("no runs in " + root + " - run `asi scan` first")
	}
	return filepath.Join(root, runs[0].ID)
}

func cmdUpload(args []string) {
	fs := flag.NewFlagSet("upload", flag.ExitOnError)
	run := fs.String("run", "", "run directory (default: latest)")
	format := fs.String("format", "generic", "generic (one finding per IP:port, change tracking) | nmap (raw merged.xml)")
	product := fs.String("product", envOr("DD_PRODUCT", "ASI PoC"), "DefectDojo product (env DD_PRODUCT)")
	eng := fs.String("engagement", "discovery", "DefectDojo engagement")
	closeOld := fs.Bool("close-old", true, "close findings missing from this run (generic only)")
	fs.Parse(args)
	c, err := ddClient()
	must(err)
	if *run == "" {
		*run = latestRun("results")
	}
	t := dojo.Target{ProductType: envOr("DD_PRODUCT_TYPE", "Research and Development"), Product: *product, Engagement: *eng, Tags: []string{"asi"}}
	var res dojo.Result
	if *format == "nmap" {
		b, e := os.ReadFile(filepath.Join(*run, "merged.xml"))
		must(e)
		t.ScanType, t.TestTitle = "Nmap Scan", "nmap "+filepath.Base(*run)
		res, err = c.Import("merged.xml", b, t)
	} else {
		svcs, e := findings.Load(filepath.Join(*run, "services.json"))
		must(e)
		t.ScanType, t.TestTitle = "Generic Findings Import", "ASI discovery"
		res, err = c.Reimport("asi-findings.json", findings.GenericJSON(svcs), t, *closeOld)
	}
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s -> %s/test/%d  delta=%v", *run, c.URL, res.Test, res.Delta)
}

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	root := fs.String("results", "results", "results directory")
	asJSON := fs.Bool("json", false, "print JSON")
	fromDB := fs.Bool("db", false, "compare runs stored in the database (ASI_DATABASE_URL) instead of results/")
	fs.Parse(args)
	if *fromDB {
		d, err := diffFromDB(os.Getenv("ASI_DATABASE_URL"), fs.Arg(0), fs.Arg(1))
		must(err)
		if *asJSON {
			out, _ := json.MarshalIndent(d, "", "  ")
			fmt.Println(string(out))
		} else {
			printDiff(d)
		}
		return
	}
	var a, b string
	switch fs.NArg() {
	case 2:
		a, b = fs.Arg(0), fs.Arg(1)
	case 0:
		runs := web.ListRuns(*root)
		if len(runs) < 2 {
			log.Fatal("need at least two runs")
		}
		a, b = runs[1].ID, runs[0].ID
	default:
		log.Fatal("usage: asi diff [runA runB]")
	}
	if !strings.Contains(a, "/") {
		a, b = filepath.Join(*root, a), filepath.Join(*root, b)
	}
	d, err := web.DiffRuns(a, b)
	must(err)
	if *asJSON {
		out, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(out))
		return
	}
	printDiff(d)
}

func printDiff(d findings.Diff) {
	fmt.Printf("\nzmiany %s -> %s: ", d.From, d.To)
	if len(d.Changes) == 0 && len(d.HostsNew) == 0 && len(d.HostsGone) == 0 {
		fmt.Printf("brak (%d usług bez zmian)\n", d.Unchanged)
		return
	}
	fmt.Printf("%d zmian, %d bez zmian\n", len(d.Changes), d.Unchanged)
	for _, h := range d.HostsNew {
		fmt.Printf("  \033[32m+ host\033[0m    %s\n", h)
	}
	for _, h := range d.HostsGone {
		fmt.Printf("  \033[31m- host\033[0m    %s\n", h)
	}
	for _, c := range d.Changes {
		switch c.Kind {
		case "new":
			fmt.Printf("  \033[32m+ new\033[0m     %-24s %s\n", c.Key, c.After.Fingerprint())
		case "gone":
			fmt.Printf("  \033[31m- gone\033[0m    %-24s %s\n", c.Key, c.Before.Fingerprint())
		case "changed":
			fmt.Printf("  \033[33m~ changed\033[0m %-24s %s -> %s\n", c.Key, c.Before.Fingerprint(), c.After.Fingerprint())
		}
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8090", "listen address")
	root := fs.String("results", "results", "results directory")
	fs.Parse(args)
	srv := startUI(*addr, &web.Server{ResultsDir: *root})
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	srv.Close()
}
