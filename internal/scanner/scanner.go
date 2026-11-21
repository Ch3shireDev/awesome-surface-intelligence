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
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"asi/internal/nmapxml"
	"asi/internal/obs"
	"asi/internal/progress"
	"asi/internal/safety"
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
	Name         string // progress phase name (= stage)
	RunID        string
	Adapter      obs.Scanner     // which tool runs the chunks
	Stage        obs.StageConfig // rate, ports, extra args for the adapter
	Parallel     int
	Sizer        *Sizer
	ChunkTimeout time.Duration
	OutDir       string
	// OnStart is called when a chunk starts (e.g. to record it in the database).
	OnStart func(id int, targets []string)
	// Guard (SEC-8): checked again in the worker right before the tool starts - excluded or
	// out-of-scope IPs are dropped from the chunk and the final nmap command line is validated.
	Guard *safety.Policy
}

type ChunkResult struct {
	ID           int               `json:"id"`
	Hosts        []string          `json:"hosts"`
	Started      time.Time         `json:"started"`
	Duration     time.Duration     `json:"duration_ns"`
	Output       string            `json:"output"` // raw tool output file (evidence)
	Error        string            `json:"error,omitempty"`
	State        string            `json:"state"` // done | failed | killed
	Observations []obs.Observation `json:"-"`
}

// RunPhase scans targets with a pool of cfg.Parallel tool processes.
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
		seq     int
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
		id := seq
		seq++
		return id, batch
	}
	for w := 0; w < max(1, cfg.Parallel); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				id, batch := take()
				if batch == nil {
					return
				}
				if cfg.OnStart != nil {
					cfg.OnStart(id, batch)
				}
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

// Unscanned returns targets that no finished (done) chunk covered - for resuming
// in the next window and for the coverage rule in reconcile.
func Unscanned(all []string, rs []ChunkResult) []string {
	done := map[string]bool{}
	for _, r := range rs {
		if r.State == "done" {
			for _, h := range r.Hosts {
				done[h] = true
			}
		}
	}
	var out []string
	for _, ip := range all {
		if !done[ip] {
			out = append(out, ip)
		}
	}
	return out
}

func runChunk(ctx context.Context, cfg PhaseConfig, id int, hosts []string, tr *progress.Tracker) ChunkResult {
	name := fmt.Sprintf("chunk_%04d", id)
	r := ChunkResult{ID: id, Hosts: hosts, Started: time.Now()}
	ch := &progress.Chunk{ID: id, Phase: cfg.Name, Hosts: len(hosts), State: "running", Started: time.Now()}
	tr.Update(func(s *progress.State) {
		s.Chunks = append(s.Chunks, ch)
		tr.Phase(cfg.Name).ChunkSize = len(hosts)
	})

	if cfg.Guard != nil && cfg.Adapter.Tool() == "nmap" {
		allowed, blocked := cfg.Guard.Filter(hosts)
		for _, b := range blocked {
			tr.Logf("POLICY %s %s: %s blocked in worker - %s", cfg.Name, name, b.IP, b.Reason)
		}
		if len(blocked) > 0 {
			hosts, r.Hosts = allowed, allowed // blocked IPs are not covered by this chunk
			tr.Update(func(s *progress.State) { tr.Phase(cfg.Name).HostsDone += len(blocked); ch.Hosts = len(allowed) })
		}
		if len(hosts) == 0 {
			return blockedChunk(cfg, r, ch, "policy: every target of the chunk is blocked", tr)
		}
	}

	cctx := ctx
	if cfg.ChunkTimeout > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, cfg.ChunkTimeout)
		defer cancel()
	}
	c := obs.Chunk{ID: id, RunID: cfg.RunID, Stage: cfg.Adapter.Stage(), Targets: hosts, Dir: cfg.OutDir, Name: name,
		TargetsFile: filepath.Join(cfg.OutDir, name+".targets")}
	os.WriteFile(c.TargetsFile, []byte(strings.Join(hosts, "\n")+"\n"), 0o644)
	cmd, spec := cfg.Adapter.Command(cctx, c, cfg.Stage)
	if cfg.Guard != nil && cfg.Adapter.Tool() == "nmap" {
		args, err := cfg.Guard.Enforce(cmd.Args[1:], safety.Opts{Final: true, TargetsFile: c.TargetsFile, MaxProcRate: cfg.Stage.RatePPS})
		if err != nil {
			return blockedChunk(cfg, r, ch, "policy: "+err.Error(), tr)
		}
		cmd.Args = append(cmd.Args[:1], args...)
	}
	r.Output = spec.Path
	logf, _ := os.Create(filepath.Join(cfg.OutDir, name+".log"))
	defer logf.Close()
	fmt.Fprintf(logf, "$ %s\n", strings.Join(cmd.Args, " "))
	cmd.Stderr = logf
	stdout, _ := cmd.StdoutPipe()
	var stdoutBuf strings.Builder // tools that report on stdout (spec.Path == "")
	pp, hasProgress := cfg.Adapter.(obs.ProgressParser)

	t0 := time.Now()
	err := cmd.Start()
	if err == nil {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		completed, pct := 0, 0.0
		for sc.Scan() {
			line := sc.Text()
			if spec.Path == "" {
				stdoutBuf.WriteString(line + "\n")
				continue
			}
			fmt.Fprintln(logf, line)
			if !hasProgress {
				continue
			}
			cpl, pc, ok := pp.ParseProgress(line)
			if !ok {
				continue
			}
			if cpl >= 0 {
				completed = cpl
			}
			if pc >= 0 {
				pct = pc
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
	r.State = "done"
	if err != nil {
		r.Error, r.State = err.Error(), "failed"
		if cctx.Err() != nil {
			r.Error, r.State = "killed: "+cctx.Err().Error(), "killed"
		}
	}
	var raw io.Reader = strings.NewReader(stdoutBuf.String())
	if spec.Path != "" {
		if f, ferr := os.Open(spec.Path); ferr == nil {
			defer f.Close()
			raw = f
		}
	}
	r.Observations, _ = cfg.Adapter.Parse(raw)
	up, open := 0, 0
	for _, o := range r.Observations {
		switch o.Kind {
		case obs.KindHost:
			up++
		case obs.KindPort:
			open++
		}
	}
	tr.Update(func(s *progress.State) {
		ch.State, ch.Percent, ch.HostsDone, ch.Up, ch.Open = r.State, 100, len(hosts), up, open
		ch.Seconds, ch.Error = r.Duration.Seconds(), r.Error
		p := tr.Phase(cfg.Name)
		p.HostsDone += len(hosts)
		recomputePartial(s, tr, cfg.Name)
	})
	tr.Logf("%s %s: %d targets, %d up, %d open, %.1fs %s", cfg.Name, name, len(hosts), up, open, r.Duration.Seconds(), r.Error)
	return r
}

// blockedChunk finishes a chunk the safety policy did not let run.
func blockedChunk(cfg PhaseConfig, r ChunkResult, ch *progress.Chunk, why string, tr *progress.Tracker) ChunkResult {
	r.State, r.Error = "failed", why // chunks.status has no "blocked"; the error says "policy: ..."
	tr.Update(func(s *progress.State) {
		ch.State, ch.Percent, ch.Error = "failed", 100, why
		recomputePartial(s, tr, cfg.Name)
	})
	tr.Logf("POLICY %s chunk_%04d not started: %s", cfg.Name, r.ID, why)
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
func Confirm(ctx context.Context, ports map[string][]int, args []string, parallel int, outDir string, guard *safety.Policy, procRate int, logf func(string, ...any)) []nmapxml.Host {
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
			base := filepath.Join(outDir, strings.ReplaceAll(ip, ":", "_"))
			x, tf := base+".xml", base+".targets"
			os.WriteFile(tf, []byte(ip+"\n"), 0o644)
			a := append(append([]string{}, args...), "-p", strings.Join(list, ","), "-oX", x, "-iL", tf)
			if guard != nil {
				if ok, why := guard.Check(ip); !ok {
					logf("POLICY confirm: %s blocked - %s", ip, why)
					return
				}
				var err error
				if a, err = guard.Enforce(a, safety.Opts{Final: true, TargetsFile: tf, MaxProcRate: procRate}); err != nil {
					logf("POLICY confirm %s: %v", ip, err)
					return
				}
			}
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
