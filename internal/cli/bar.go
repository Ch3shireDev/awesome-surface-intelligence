// Package cli renders the live progress bar in the terminal.
package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"asi/internal/progress"
)

type Bar struct {
	tr      *progress.Tracker
	out     io.Writer
	tty     bool
	logSeen int
	lines   int
	stop    chan struct{}
	done    chan struct{}
}

func NewBar(tr *progress.Tracker) *Bar {
	fi, _ := os.Stderr.Stat()
	return &Bar{tr: tr, out: os.Stderr, tty: fi != nil && fi.Mode()&os.ModeCharDevice != 0,
		stop: make(chan struct{}), done: make(chan struct{})}
}

func (b *Bar) Start() {
	go func() {
		defer close(b.done)
		every := 200 * time.Millisecond
		if !b.tty {
			every = 10 * time.Second
		}
		t := time.NewTicker(every)
		logT := time.NewTicker(200 * time.Millisecond)
		for {
			select {
			case <-b.stop:
				b.render(true)
				return
			case <-logT.C:
				if !b.tty {
					b.flushLogs(b.tr.Snapshot())
				}
			case <-t.C:
				b.render(false)
			}
		}
	}()
}

func (b *Bar) Stop() { close(b.stop); <-b.done }

func (b *Bar) newLogs(s progress.State) []string {
	n := min(s.LogSeq-b.logSeen, len(s.Log))
	b.logSeen = s.LogSeq
	if n <= 0 {
		return nil
	}
	return s.Log[len(s.Log)-n:]
}

func (b *Bar) flushLogs(s progress.State) {
	for _, l := range b.newLogs(s) {
		fmt.Fprintln(b.out, l)
	}
}

func (b *Bar) render(final bool) {
	s := b.tr.Snapshot()
	if !b.tty {
		b.flushLogs(s)
		fmt.Fprintln(b.out, statusLine(s))
		return
	}
	var w strings.Builder
	// erase previous bar
	for i := 0; i < b.lines; i++ {
		w.WriteString("\033[1A\033[2K")
	}
	w.WriteString("\r\033[2K")
	// new log lines go above the bar
	for _, l := range b.newLogs(s) {
		w.WriteString(l + "\n")
	}
	lines := []string{barLine(s), runningLine(s)}
	if final {
		lines = []string{barLine(s)}
	}
	for _, l := range lines {
		w.WriteString(l + "\n")
	}
	b.lines = len(lines)
	fmt.Fprint(b.out, w.String())
}

func barLine(s progress.State) string {
	const width = 30
	fill := int(s.Percent / 100 * width)
	bar := strings.Repeat("█", fill) + strings.Repeat("░", width-fill)
	phase := ""
	for _, p := range s.Phases {
		if p.State == "running" {
			phase = fmt.Sprintf("%s %d/%d hosts, chunk=%d", p.Name, int(p.Partial), p.Hosts, p.ChunkSize)
		}
	}
	if phase == "" {
		phase = s.Status
	}
	eta := "--:--"
	if s.ETA > 0 {
		eta = dur(s.ETA)
	}
	return fmt.Sprintf("\033[1m%5.1f%%\033[0m %s │ %s │ up %d │ open %d │ %s ETA %s",
		s.Percent, bar, phase, s.HostsUp, s.Open, dur(s.Elapsed), eta)
}

func runningLine(s progress.State) string {
	var run []*progress.Chunk
	for _, c := range s.Chunks {
		if c.State == "running" {
			run = append(run, c)
		}
	}
	sort.Slice(run, func(i, j int) bool { return run[i].ID < run[j].ID })
	parts := []string{}
	for _, c := range run {
		parts = append(parts, fmt.Sprintf("#%d[%d] %3.0f%%", c.ID, c.Hosts, c.Percent))
	}
	up := ""
	if s.Upload.State != "idle" {
		up = fmt.Sprintf(" │ dojo: %s (%d)", s.Upload.State, s.Upload.Batches)
	}
	return "  \033[2mworkers: " + strings.Join(parts, "  ") + up + "\033[0m"
}

func statusLine(s progress.State) string {
	return fmt.Sprintf("[progress] %.1f%% status=%s up=%d open=%d elapsed=%s eta=%s",
		s.Percent, s.Status, s.HostsUp, s.Open, dur(s.Elapsed), dur(s.ETA))
}

func dur(sec float64) string {
	d := time.Duration(sec) * time.Second
	return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}
