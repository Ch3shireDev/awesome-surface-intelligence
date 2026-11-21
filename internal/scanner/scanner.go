// Package scanner runs nmap over many hosts using a worker pool with
// adaptively sized chunks and live progress reporting.
//
// Chunking strategy (see docs/guide/chunking.md):
//   - workers pull the next batch when they become free (no static pre-split),
//   - batch size = target chunk duration / observed seconds-per-host (EWMA),
//     clamped to [Min, Max] and shrunk near the end so all workers finish together,
//   - the observed seconds-per-host is saved and seeds the next run.
package scanner

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"asi/internal/nmapxml"
	"asi/internal/progress"
)

// Sizer decides how many hosts go into the next nmap process.
type Sizer struct {
	Fixed  int           // >0 disables adaptation
	Target time.Duration // desired wall time of one chunk
	Min    int
	Max    int
	Start  int

	mu   sync.Mutex
	ewma float64 // seconds per host
}

func (z *Sizer) SecPerHost() float64 { z.mu.Lock(); defer z.mu.Unlock(); return z.ewma }

func (z *Sizer) Seed(secPerHost float64) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if secPerHost > 0 {
		z.ewma = secPerHost
	}
}

func (z *Sizer) Observe(hosts int, d time.Duration) {
	if hosts == 0 {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	v := d.Seconds() / float64(hosts)
	if z.ewma == 0 {
		z.ewma = v
	} else {
		z.ewma = 0.6*z.ewma + 0.4*v
	}
}

func (z *Sizer) Next(remaining, parallel int) int {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := z.Fixed
	if n <= 0 {
		n = z.Start
		if z.ewma > 0 {
			n = int(math.Round(z.Target.Seconds() / z.ewma))
		}
		n = max(z.Min, min(z.Max, n))
		// tail balancing: don't let one worker take the whole rest
		if fair := int(math.Ceil(float64(remaining) / float64(max(1, parallel)))); fair < n {
			n = max(z.Min, fair)
		}
	}
	return max(1, min(n, remaining))
}

type PhaseConfig struct {
	Name         string
	Args         []string
	Parallel     int
	Sizer        *Sizer
	ChunkTimeout time.Duration
	OutDir       string
}

type ChunkResult struct {
	ID       int            `json:"id"`
	Hosts    []string       `json:"hosts"`
	Duration time.Duration  `json:"duration_ns"`
	XML      string         `json:"xml"`
	Error    string         `json:"error,omitempty"`
	Parsed   []nmapxml.Host `json:"-"`
}

var (
	reCompleted = regexp.MustCompile(`(\d+) hosts? completed \((\d+) up\)`)
	reAbout     = regexp.MustCompile(`About ([\d.]+)% done`)
)

// RunPhase scans ips with a pool of cfg.Parallel nmap processes.
// onDone is called (from worker goroutines) after each chunk finishes.
func RunPhase(ctx context.Context, cfg PhaseConfig, ips []string, tr *progress.Tracker, onDone func(ChunkResult)) []ChunkResult {
	os.MkdirAll(cfg.OutDir, 0o755)
	tr.Update(func(s *progress.State) {
		p := tr.Phase(cfg.Name)
		p.State, p.Hosts, p.HostsDone, p.Partial = "running", len(ips), 0, 0
	})
	t0 := time.Now()
	var (
		mu      sync.Mutex
		next    int
		results []ChunkResult
		wg      sync.WaitGroup
	)
	take := func() (int, []string) {
		mu.Lock()
		defer mu.Unlock()
		if next >= len(ips) || ctx.Err() != nil {
			return 0, nil
		}
		n := cfg.Sizer.Next(len(ips)-next, cfg.Parallel)
		batch := ips[next : next+n]
		next += n
		return next, batch
	}
	var chunkSeq int
	var seqMu sync.Mutex
	for w := 0; w < max(1, cfg.Parallel); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, batch := take()
				if batch == nil {
					return
				}
				seqMu.Lock()
				id := chunkSeq
				chunkSeq++
				seqMu.Unlock()
				r := runChunk(ctx, cfg, id, batch, tr)
				cfg.Sizer.Observe(len(batch), r.Duration)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
				if onDone != nil {
					onDone(r)
				}
			}
		}()
	}
	wg.Wait()

	state := "done"
	if next < len(ips) {
		state = "interrupted"
		tr.Logf("%s: window/interrupt - %d hosts not scanned", cfg.Name, len(ips)-next)
	}
	tr.Update(func(s *progress.State) {
		p := tr.Phase(cfg.Name)
		p.State, p.Seconds, p.SecPerHost = state, time.Since(t0).Seconds(), cfg.Sizer.SecPerHost()
		if state == "done" {
			p.Partial = float64(p.Hosts)
		}
	})
	writeTimings(filepath.Join(cfg.OutDir, "timings.csv"), results)
	return results
}

func runChunk(ctx context.Context, cfg PhaseConfig, id int, hosts []string, tr *progress.Tracker) ChunkResult {
	name := fmt.Sprintf("chunk_%04d", id)
	r := ChunkResult{ID: id, Hosts: hosts, XML: filepath.Join(cfg.OutDir, name+".xml")}
	ch := &progress.Chunk{ID: id, Phase: cfg.Name, Hosts: len(hosts), State: "running", Started: time.Now()}
	tr.Update(func(s *progress.State) {
		s.Chunks = append(s.Chunks, ch)
		tr.Phase(cfg.Name).ChunkSize = len(hosts)
	})

	cctx := ctx
	if cfg.ChunkTimeout > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, cfg.ChunkTimeout)
		defer cancel()
	}
	in := filepath.Join(cfg.OutDir, name+".targets")
	os.WriteFile(in, []byte(strings.Join(hosts, "\n")+"\n"), 0o644)
	args := append(append([]string{}, cfg.Args...), "--stats-every", "2s", "-oX", r.XML, "-iL", in)
	cmd := exec.CommandContext(cctx, "nmap", args...)
	logf, _ := os.Create(filepath.Join(cfg.OutDir, name+".log"))
	defer logf.Close()
	fmt.Fprintf(logf, "$ nmap %s\n", strings.Join(args, " "))
	cmd.Stderr = logf
	stdout, _ := cmd.StdoutPipe()

	t0 := time.Now()
	err := cmd.Start()
	if err == nil {
		sc := bufio.NewScanner(stdout)
		completed, pct := 0, 0.0
		for sc.Scan() {
			line := sc.Text()
			fmt.Fprintln(logf, line)
			if m := reCompleted.FindStringSubmatch(line); m != nil {
				completed, _ = strconv.Atoi(m[1])
			}
			if m := reAbout.FindStringSubmatch(line); m != nil {
				pct, _ = strconv.ParseFloat(m[1], 64)
			}
			n := float64(len(hosts))
			p := (float64(completed) + pct/100*(n-float64(completed))*0.95) / n
			tr.Update(func(s *progress.State) {
				if p > ch.Percent/100 && p < 1 {
					ch.Percent = p * 100
				}
				ch.HostsDone = completed
				recomputePartial(s, tr, cfg.Name)
			})
		}
		err = cmd.Wait()
	}
	r.Duration = time.Since(t0)
	final := "done"
	if err != nil {
		r.Error, final = err.Error(), "failed"
		if cctx.Err() != nil {
			r.Error, final = "killed: "+cctx.Err().Error(), "killed"
		}
	}
	run, _ := nmapxml.ParseFile(r.XML)
	r.Parsed = run.Hosts
	up, open := 0, 0
	for _, h := range run.Hosts {
		if h.Up() {
			up++
		}
		for _, p := range h.Ports {
			if p.State.State == "open" {
				open++
			}
		}
	}
	tr.Update(func(s *progress.State) {
		ch.State, ch.Percent, ch.HostsDone, ch.Up, ch.Open = final, 100, len(hosts), up, open
		ch.Seconds, ch.Error = r.Duration.Seconds(), r.Error
		p := tr.Phase(cfg.Name)
		p.HostsDone += len(hosts)
		recomputePartial(s, tr, cfg.Name)
	})
	tr.Logf("%s %s: %d hosts, %d up, %d open, %.1fs %s", cfg.Name, name, len(hosts), up, open, r.Duration.Seconds(), r.Error)
	return r
}

// must be called under tracker lock (inside Update)
func recomputePartial(s *progress.State, tr *progress.Tracker, phase string) {
	var part float64
	for _, c := range s.Chunks {
		if c.Phase == phase {
			part += float64(c.Hosts) * c.Percent / 100
		}
	}
	tr.Phase(phase).Partial = part
}

func writeTimings(path string, rs []ChunkResult) {
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"chunk", "hosts", "seconds", "sec_per_host", "error"})
	for _, r := range rs {
		s := r.Duration.Seconds()
		w.Write([]string{fmt.Sprintf("chunk_%04d", r.ID), strconv.Itoa(len(r.Hosts)),
			fmt.Sprintf("%.2f", s), fmt.Sprintf("%.3f", s/float64(max(1, len(r.Hosts)))), r.Error})
	}
	w.Flush()
}

// Confirm re-scans specific ports on specific hosts (one nmap per host, up to
// parallel at once). Used to double-check services that "disappeared" while the
// host is still up - a single lost probe must not close a finding.
func Confirm(ctx context.Context, ports map[string][]int, args []string, parallel int, outDir string) []nmapxml.Host {
	os.MkdirAll(outDir, 0o755)
	var (
		mu  sync.Mutex
		out []nmapxml.Host
		wg  sync.WaitGroup
	)
	sem := make(chan struct{}, max(1, parallel))
	for ip, ps := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string, ps []int) {
			defer wg.Done()
			defer func() { <-sem }()
			list := make([]string, len(ps))
			for i, p := range ps {
				list[i] = strconv.Itoa(p)
			}
			x := filepath.Join(outDir, strings.ReplaceAll(ip, ":", "_")+".xml")
			a := append(append([]string{}, args...), "-p", strings.Join(list, ","), "-oX", x, ip)
			exec.CommandContext(ctx, "nmap", a...).Run()
			r, _ := nmapxml.ParseFile(x)
			mu.Lock()
			out = append(out, r.Hosts...)
			mu.Unlock()
		}(ip, ps)
	}
	wg.Wait()
	return out
}
