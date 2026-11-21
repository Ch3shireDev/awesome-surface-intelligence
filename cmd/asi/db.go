package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"asi/internal/findings"
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

func (d *dbRecorder) start(set string, profile any) {
	if d == nil {
		return
	}
	c, cancel := d.ctx()
	defer cancel()
	if err := d.st.CreateRun(c, d.runID, set, "manual", profile); err != nil {
		d.logf("db: create run: %v", err)
	}
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
		fmt.Fprintln(os.Stderr, "usage: asi db <migrate|import-targets|targets|runs> [flags]")
		os.Exit(2)
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("db "+sub, flag.ExitOnError)
	url := fs.String("db", os.Getenv("ASI_DATABASE_URL"), "PostgreSQL URL (env ASI_DATABASE_URL)")
	set := fs.String("set", "default", "target set name")
	file := fs.String("targets", "targets/targets.csv", "targets file (.csv/.json/.txt) for import-targets")
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
