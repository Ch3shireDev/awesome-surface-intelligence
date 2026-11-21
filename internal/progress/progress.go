// Package progress keeps the live state of a scan run. The same snapshot feeds
// the CLI progress bar, the web panel (SSE) and events.ndjson on disk.
package progress

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Chunk struct {
	ID        int       `json:"id"`
	Phase     string    `json:"phase"` // discovery | services
	Hosts     int       `json:"hosts"`
	State     string    `json:"state"` // running | done | failed | killed
	Percent   float64   `json:"percent"`
	HostsDone int       `json:"hosts_done"`
	Up        int       `json:"up"`
	Open      int       `json:"open"`
	Started   time.Time `json:"started"`
	Seconds   float64   `json:"seconds"`
	Error     string    `json:"error,omitempty"`
}

type Phase struct {
	Name       string  `json:"name"`
	State      string  `json:"state"` // pending | running | done | skipped
	Hosts      int     `json:"hosts"`
	HostsDone  int     `json:"hosts_done"` // finished chunks
	Partial    float64 `json:"partial"`    // finished + in-flight fraction of running chunks
	ChunkSize  int     `json:"chunk_size"` // current (adaptive) size
	SecPerHost float64 `json:"sec_per_host"`
	Seconds    float64 `json:"seconds"`
}

type Upload struct {
	State   string         `json:"state"` // idle | running | done | failed
	Batches int            `json:"batches"`
	Last    string         `json:"last,omitempty"`
	TestURL string         `json:"test_url,omitempty"`
	Delta   map[string]int `json:"delta,omitempty"`
}

type Service struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Interest string `json:"interest"`
	Domains  string `json:"domains,omitempty"`
}

type State struct {
	RunID    string    `json:"run_id"`
	Started  time.Time `json:"started"`
	Elapsed  float64   `json:"elapsed"`
	Percent  float64   `json:"percent"`
	ETA      float64   `json:"eta"`
	Status   string    `json:"status"` // planning | running | done | interrupted
	Window   string    `json:"window,omitempty"`
	Parallel int       `json:"parallel"`
	Targets  int       `json:"targets"`
	Skipped  int       `json:"skipped"`
	HostsUp  int       `json:"hosts_up"`
	Open     int       `json:"open"`
	Phases   []*Phase  `json:"phases"`
	Chunks   []*Chunk  `json:"chunks"`
	Upload   Upload    `json:"upload"`
	Services []Service `json:"services"` // newest first, capped
	Log      []string  `json:"log"`
	LogSeq   int       `json:"log_seq"` // total lines ever logged (Log keeps the last 200)
}

type Tracker struct {
	mu    sync.Mutex
	s     State
	dirty bool
	subs  map[chan []byte]struct{}
	ev    *os.File
}

func New(runID string, parallel int, eventsPath string) *Tracker {
	t := &Tracker{subs: map[chan []byte]struct{}{}}
	t.s = State{RunID: runID, Started: time.Now(), Status: "planning", Parallel: parallel,
		Phases: []*Phase{{Name: "discovery", State: "pending"}, {Name: "services", State: "pending"}},
		Upload: Upload{State: "idle"}, Chunks: []*Chunk{}, Services: []Service{}, Log: []string{}}
	if eventsPath != "" {
		t.ev, _ = os.Create(eventsPath)
	}
	go t.loop()
	return t
}

// Update mutates state under lock and marks it for broadcast.
func (t *Tracker) Update(f func(s *State)) {
	t.mu.Lock()
	f(&t.s)
	t.dirty = true
	t.mu.Unlock()
}

func (t *Tracker) Phase(name string) *Phase {
	for _, p := range t.s.Phases {
		if p.Name == name {
			return p
		}
	}
	return nil
}

func (t *Tracker) Logf(format string, a ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, a...)
	t.Update(func(s *State) {
		s.Log = append(s.Log, line)
		s.LogSeq++
		if len(s.Log) > 200 {
			s.Log = s.Log[len(s.Log)-200:]
		}
	})
	if t.ev != nil {
		b, _ := json.Marshal(map[string]any{"t": time.Now(), "log": line})
		t.mu.Lock()
		t.ev.Write(append(b, '\n'))
		t.mu.Unlock()
	}
}

func (t *Tracker) AddServices(svcs []Service) {
	t.Update(func(s *State) {
		s.Services = append(svcs, s.Services...)
		if len(s.Services) > 500 {
			s.Services = s.Services[:500]
		}
	})
}

// Snapshot returns a consistent copy with derived fields (percent, ETA) computed.
func (t *Tracker) Snapshot() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked()
}

func (t *Tracker) snapshotLocked() State {
	s := t.s
	s.Elapsed = time.Since(s.Started).Seconds()
	// weights: discovery is cheap per host, services are where the time goes
	w := map[string]float64{"discovery": 0.25, "services": 0.75}
	var pct float64
	for _, p := range s.Phases {
		switch p.State {
		case "done", "skipped":
			pct += w[p.Name]
		case "running":
			if p.Hosts > 0 {
				pct += w[p.Name] * p.Partial / float64(p.Hosts)
			}
		}
	}
	if s.Status == "done" {
		pct = 1
	}
	s.Percent = pct * 100
	if pct > 0.02 && pct < 1 {
		s.ETA = s.Elapsed / pct * (1 - pct)
	}
	// deep-copy slices of pointers so the caller can't race with writers
	ph := make([]*Phase, len(s.Phases))
	for i, p := range s.Phases {
		c := *p
		ph[i] = &c
	}
	s.Phases = ph
	ch := make([]*Chunk, len(s.Chunks))
	for i, c := range s.Chunks {
		cc := *c
		ch[i] = &cc
	}
	s.Chunks = ch
	s.Services = append([]Service(nil), s.Services...)
	s.Log = append([]string(nil), s.Log...)
	return s
}

func (t *Tracker) JSON() []byte {
	b, _ := json.Marshal(t.Snapshot())
	return b
}

// Subscribe returns a channel receiving JSON snapshots (max ~4/s).
func (t *Tracker) Subscribe() (chan []byte, func()) {
	ch := make(chan []byte, 4)
	t.mu.Lock()
	t.subs[ch] = struct{}{}
	t.mu.Unlock()
	ch <- t.JSON()
	return ch, func() {
		t.mu.Lock()
		delete(t.subs, ch)
		t.mu.Unlock()
	}
}

func (t *Tracker) loop() {
	tick := time.NewTicker(250 * time.Millisecond)
	beat := time.NewTicker(1 * time.Second) // keep elapsed/ETA moving even without changes
	for {
		select {
		case <-tick.C:
		case <-beat.C:
			t.mu.Lock()
			t.dirty = true
			t.mu.Unlock()
		}
		t.mu.Lock()
		if !t.dirty {
			t.mu.Unlock()
			continue
		}
		t.dirty = false
		s := t.snapshotLocked()
		b, _ := json.Marshal(s)
		for ch := range t.subs {
			select {
			case ch <- b:
			default: // slow client: drop frame, next one is a full snapshot anyway
			}
		}
		t.mu.Unlock()
	}
}

func (t *Tracker) Close() {
	if t.ev != nil {
		b, _ := json.Marshal(map[string]any{"t": time.Now(), "final": t.Snapshot()})
		t.mu.Lock()
		t.ev.Write(append(b, '\n'))
		t.ev.Close()
		t.ev = nil
		t.mu.Unlock()
	}
}
