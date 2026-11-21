package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"asi/internal/findings"
	"asi/internal/nmapxml"
	"asi/internal/obs"
	"asi/internal/scanner"
	"asi/internal/store"
	"asi/internal/targets"
)

// openStore connects to ASI_DATABASE_URL (or url) and applies migrations.
// Returns nil (no error) when no URL is configured: the scanner then works file-only.
func openStore(ctx context.Context, url string) (*store.Store, error) {
	if url == "" {
		return nil, nil
	}
	st, err := store.Open(ctx, url, sealer())
	if err != nil {
		return nil, err
	}
	if applied, err := st.Migrate(ctx); err != nil {
		st.Close()
		return nil, err
	} else if len(applied) > 0 {
		log.Printf("db: applied migrations %v", applied)
	}
	return st, nil
}

// sealer is replaced by internal/crypto (SEC-6) once ASI_ENCRYPTION_KEYS is set.
var sealer = func() store.Sealer { return store.Plain{} }

// dbRecorder writes a scan run into the database. All writes use a background
// context so a closing scan window does not lose already finished work.
// DB errors are logged and do not stop the scan (files in results/ stay the fallback).
type dbRecorder struct {
	st    *store.Store
	runID string
	logf  func(string, ...any)
}

func (d *dbRecorder) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func (d *dbRecorder) start(set, trigger string, scheduleID int64, resumeOf string, profile any) {
	if d == nil {
		return
	}
	c, cancel := d.ctx()
	defer cancel()
	if err := d.st.CreateRun(c, d.runID, set, trigger, profile); err != nil {
		d.logf("db: create run: %v", err)
		return
	}
	if scheduleID > 0 || resumeOf != "" {
		if err := d.st.SetRunLinks(c, d.runID, scheduleID, resumeOf); err != nil {
			d.logf("db: run links: %v", err)
		}
	}
	if scheduleID > 0 {
		d.st.SetScheduleLastRun(c, scheduleID, d.runID)
	}
}

func (d *dbRecorder) pending(p []string) {
	if d == nil {
		return
	}
	c, cancel := d.ctx()
	defer cancel()
	if err := d.st.SetPending(c, d.runID, p); err != nil {
		d.logf("db: pending: %v", err)
	}
}

// resumePlan: the plan of a previous run restricted to its pending targets
// (from the database if available, else from results/<run>/run.json).
func resumePlan(root, runID string, rec *dbRecorder) (targets.Plan, error) {
	var plan targets.Plan
	b, err := os.ReadFile(filepath.Join(root, runID, "plan.json"))
	if err != nil {
		return plan, fmt.Errorf("no plan.json of run %s: %w", runID, err)
	}
	if err := json.Unmarshal(b, &plan); err != nil {
		return plan, err
	}
	var pending []string
	if rec != nil {
		p, by, err := rec.st.RunPending(context.Background(), runID)
		if err != nil {
			return plan, err
		}
		if by != "" {
			return plan, fmt.Errorf("already resumed by run %s", by)
		}
		pending = p
	} else {
		var rj struct {
			Pending []string `json:"pending"`
		}
		rb, _ := os.ReadFile(filepath.Join(root, runID, "run.json"))
		json.Unmarshal(rb, &rj)
		pending = rj.Pending
	}
	if len(pending) == 0 {
		return plan, fmt.Errorf("run %s has nothing pending", runID)
	}
	want := map[string]bool{}
	for _, ip := range pending {
		want[ip] = true
	}
	var hosts []targets.Host
	for _, h := range plan.Hosts {
		if want[h.IP] {
			hosts = append(hosts, h)
		}
	}
	plan.Hosts, plan.Skipped, plan.Created = hosts, nil, time.Now()
	return plan, nil
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	out := s[:0:0]
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func (d *dbRecorder) chunkStart(stage string) func(int, []string) {
	if d == nil {
		return nil
	}
	return func(id int, tgts []string) {
		c, cancel := d.ctx()
		defer cancel()
		if err := d.st.StartChunk(c, d.runID, stage, id, tgts); err != nil {
			d.logf("db: chunk start: %v", err)
		}
	}
}

func (d *dbRecorder) chunkDone(stage, tool, format string, r scanner.ChunkResult) {
	if d == nil {
		return
	}
	c, cancel := d.ctx()
	defer cancel()
	if err := d.st.FinishChunk(c, d.runID, stage, r.ID, r.State, r.Duration, r.Error); err != nil {
		d.logf("db: chunk finish: %v", err)
	}
	if err := d.st.InsertObservations(c, d.runID, stage, r.ID, r.Observations); err != nil {
		d.logf("db: observations: %v", err)
	}
	if format == "nmap-xml" {
		if run, err := nmapxml.ParseFile(r.Output); err == nil {
			if p := run.Ports("tcp"); p != "" {
				if err := d.st.SetChunkPorts(c, d.runID, stage, r.ID, p); err != nil {
					d.logf("db: chunk ports: %v", err)
				}
			}
		}
	}
	if b, err := os.ReadFile(r.Output); err == nil && len(b) > 0 {
		if err := d.st.SaveRaw(c, d.runID, stage, r.ID, tool, format, b); err != nil {
			d.logf("db: raw output: %v", err)
		}
	}
}

func (d *dbRecorder) observations(stage string, os []obs.Observation) {
	if d == nil {
		return
	}
	c, cancel := d.ctx()
	defer cancel()
	if err := d.st.InsertObservations(c, d.runID, stage, 0, os); err != nil {
		d.logf("db: observations (%s): %v", stage, err)
	}
}

func (d *dbRecorder) finish(status string, stats any) {
	if d == nil {
		return
	}
	c, cancel := d.ctx()
	defer cancel()
	if err := d.st.FinishRun(c, d.runID, status, stats); err != nil {
		d.logf("db: finish run: %v", err)
	}
}

// ---------------------------------------------------------------- asi db ...

func cmdDB(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: asi db <migrate|import-targets|targets|runs|reconcile RUN> [flags]")
		os.Exit(2)
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("db "+sub, flag.ExitOnError)
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL (env ASI_DATABASE_URL)")
	set := fs.String("set", "default", "target set name")
	file := fs.String("targets", "targets/targets.csv", "targets file (.csv/.json/.txt) for import-targets")
	rc := reconcileFlags(fs)
	fs.Parse(args)
	if *url == "" {
		log.Fatal("set ASI_DATABASE_URL or -db")
	}
	ctx := context.Background()
	st, err := openStore(ctx, *url)
	must(err)
	defer st.Close()
	switch sub {
	case "migrate":
		log.Print("db: schema up to date")
	case "import-targets":
		ts, err := targets.Load(*file)
		must(err)
		n, err := st.UpsertTargets(ctx, *set, ts)
		must(err)
		log.Printf("db: %d targets upserted into set %q", n, *set)
	case "targets":
		ts, err := st.Targets(ctx, *set)
		must(err)
		for _, t := range ts {
			fmt.Printf("%-32s %-6v %-14s %v %s\n", t.Target, t.Enabled, t.Asset, t.Tags, t.Note)
		}
	case "runs":
		rs, err := st.Runs(ctx, 50)
		must(err)
		for _, r := range rs {
			cs, _ := st.ChunkStats(ctx, r.ID)
			fmt.Printf("%s  %-10s %s  chunks=%v  stats=%s\n", r.ID, r.Status, r.StartedAt.Format(time.DateTime), cs, r.Stats)
		}
	case "reconcile": // backfill: asi db reconcile RUN [RUN...] (in chronological order)
		for _, id := range fs.Args() {
			r, err := st.Reconcile(ctx, id, *rc)
			must(err)
			log.Printf("reconcile %s: %d covered, %d live, events %v", id, r.CoveredHosts, r.LiveHosts, r.Counts)
		}
	default:
		log.Fatalf("unknown: asi db %s", sub)
	}
}

// diffFromDB compares the two latest finished runs stored in the database
// (or the given ids).
func diffFromDB(url, a, b string) (findings.Diff, error) {
	ctx := context.Background()
	st, err := openStore(ctx, url)
	if err != nil {
		return findings.Diff{}, err
	}
	defer st.Close()
	if a == "" {
		rs, err := st.Runs(ctx, 50)
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
			return findings.Diff{}, fmt.Errorf("need two completed runs in the database, have %d", len(done))
		}
		a, b = done[1], done[0]
	}
	load := func(id string) ([]findings.Service, []string, error) {
		os, err := st.Observations(ctx, id, obs.KindPort, obs.KindService)
		if err != nil {
			return nil, nil, err
		}
		up, err := st.LiveHosts(ctx, id)
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

// ---------------------------------------------------------------- reconcile / assets / changes

func reconcileFlags(fs *flag.FlagSet) *store.ReconcileConfig {
	c := &store.ReconcileConfig{}
	fs.IntVar(&c.HostMissThreshold, "miss-threshold", 3, "consecutive misses before a host is gone")
	fs.IntVar(&c.PortMissThreshold, "port-miss-threshold", 2, "consecutive misses before a port is gone")
	fs.DurationVar(&c.GoneAfter, "gone-after", 0, "and at least this long since last seen (e.g. 24h)")
	fs.IntVar(&c.FlapWindow, "flap-window", 10, "flapping: look at the last N runs")
	fs.IntVar(&c.FlapTransitions, "flap-transitions", 3, "flapping: this many active<->missing transitions")
	return c
}

func (d *dbRecorder) reconcile(cfg store.ReconcileConfig) {
	if d == nil {
		return
	}
	c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	r, err := d.st.Reconcile(c, d.runID, cfg)
	if err != nil {
		d.logf("db: reconcile: %v", err)
		return
	}
	d.logf("reconcile: %d covered hosts, %d live, events %v", r.CoveredHosts, r.LiveHosts, r.Counts)
}

func printEvents(ev []store.Event) {
	colors := map[string]string{"new": "32", "reappeared": "32", "changed": "33", "missing": "31", "gone": "31", "flapping": "35"}
	for _, e := range ev {
		detail := ""
		if e.Type == "changed" {
			detail = fmt.Sprintf("%s -> %s", e.Before, e.After)
		} else if e.After != nil {
			detail = string(e.After)
		} else if e.Before != nil {
			detail = "was " + string(e.Before)
		}
		fmt.Printf("  \033[%sm%-10s\033[0m %-26s %s\n", colors[e.Type], e.Type, e.Key, detail)
	}
}

func dbOrDie(url string) *store.Store {
	if url == "" {
		log.Fatal("set ASI_DATABASE_URL or -db")
	}
	st, err := openStore(context.Background(), url)
	must(err)
	return st
}

// asi changes [run]  - events of a run (default: latest reconciled)
func cmdChanges(args []string) {
	fs := flag.NewFlagSet("changes", flag.ExitOnError)
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL")
	key := fs.String("asset", "", "history of one asset instead of one run")
	fs.Parse(args)
	st := dbOrDie(*url)
	defer st.Close()
	ctx := context.Background()
	run := fs.Arg(0)
	if run == "" && *key == "" {
		rs, err := st.Runs(ctx, 1)
		must(err)
		if len(rs) == 0 {
			log.Fatal("no runs")
		}
		run = rs[0].ID
	}
	ev, err := st.Events(ctx, run, *key, 5000)
	must(err)
	if *key != "" {
		fmt.Printf("historia %s:\n", *key)
	} else {
		fmt.Printf("zmiany w przebiegu %s: %d\n", run, len(ev))
	}
	printEvents(ev)
}

// asi assets [-state missing] [-flapping] [-q 10.0.0]
func cmdAssets(args []string) {
	fs := flag.NewFlagSet("assets", flag.ExitOnError)
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL")
	f := store.AssetFilter{}
	fs.StringVar(&f.State, "state", "", "new | active | missing | gone")
	fs.StringVar(&f.Kind, "kind", "", "host | port")
	fs.BoolVar(&f.Flapping, "flapping", false, "only flapping assets")
	fs.StringVar(&f.Search, "q", "", "key contains")
	fs.Parse(args)
	st := dbOrDie(*url)
	defer st.Close()
	as, err := st.Assets(context.Background(), f)
	must(err)
	for _, a := range as {
		flap := ""
		if a.Flapping {
			flap = "FLAPPING"
		}
		fmt.Printf("%-26s %-5s %-8s %-8s seen=%-3d miss=%d last=%s %s tags=%v %s\n", a.Key, a.Kind, a.State, flap,
			a.SeenCount, a.ConsecutiveMisses, a.LastSeen.Format("01-02 15:04"), a.Current, a.UserTags, a.UserNote)
	}
	fmt.Fprintf(os.Stderr, "%d assets\n", len(as))
}

// asi asset edit KEY [-tags a,b] [-note "..."]
func cmdAsset(args []string) {
	if len(args) < 2 || args[0] != "edit" {
		log.Fatal("usage: asi asset edit <key> [-tags a,b] [-note text]")
	}
	key := args[1]
	fs := flag.NewFlagSet("asset edit", flag.ExitOnError)
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL")
	tags := fs.String("tags", "\x00", "comma separated user tags (empty = clear)")
	note := fs.String("note", "\x00", "user note (encrypted at rest)")
	fs.Parse(args[2:])
	st := dbOrDie(*url)
	defer st.Close()
	var e store.AssetEdit
	if *tags != "\x00" {
		t := []string{}
		for _, x := range strings.Split(*tags, ",") {
			if x = strings.TrimSpace(x); x != "" {
				t = append(t, x)
			}
		}
		e.Tags = &t
	}
	if *note != "\x00" {
		e.Note = note
	}
	must(st.EditAsset(context.Background(), nil, key, e))
	log.Printf("asset %s updated", key)
}
