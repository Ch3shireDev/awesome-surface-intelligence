// Package web serves the live progress panel and run history.
package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"asi/internal/findings"
	"asi/internal/progress"
)

//go:embed panel.html
var panel []byte

type Server struct {
	Tracker    *progress.Tracker // nil when not scanning (history-only mode)
	ResultsDir string
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(panel)
	})
	m.HandleFunc("GET /api/live", s.live)
	m.HandleFunc("GET /api/events", s.events)
	m.HandleFunc("GET /api/runs", s.runs)
	m.HandleFunc("GET /api/runs/{id}", s.run)
	m.HandleFunc("GET /api/diff", s.diff)
	return m
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	if s.Tracker == nil { // history mode: show the final state of the latest run
		for _, r := range ListRuns(s.ResultsDir) {
			if b, err := os.ReadFile(filepath.Join(s.ResultsDir, r.ID, "final_state.json")); err == nil {
				w.Header().Set("Content-Type", "application/json")
				w.Write(b)
				return
			}
		}
		writeJSON(w, map[string]any{"status": "idle"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.Tracker.JSON())
}

// Server-Sent Events: full snapshot on every change (<= 4/s).
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok || s.Tracker == nil {
		http.Error(w, "no live scan", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch, unsub := s.Tracker.Subscribe()
	defer unsub()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

type RunSummary struct {
	ID       string  `json:"id"`
	Started  string  `json:"started"`
	Duration float64 `json:"duration_s"`
	Targets  int     `json:"targets"`
	HostsUp  int     `json:"hosts_up"`
	Open     int     `json:"open"`
	High     int     `json:"interest_high"`
	Medium   int     `json:"interest_medium"`
	Status   string  `json:"status"`
	DojoTest string  `json:"dojo_test,omitempty"`
}

func ListRuns(dir string) []RunSummary {
	m, _ := filepath.Glob(filepath.Join(dir, "*", "run.json"))
	var out []RunSummary
	for _, f := range m {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var rs RunSummary
		if json.Unmarshal(b, &rs) == nil && rs.ID != "" {
			out = append(out, rs)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (s *Server) runs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, ListRuns(s.ResultsDir))
}

func (s *Server) runDir(id string) (string, bool) {
	if id == "" || filepath.Base(id) != id {
		return "", false
	}
	d := filepath.Join(s.ResultsDir, id)
	_, err := os.Stat(filepath.Join(d, "run.json"))
	return d, err == nil
}

func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	d, ok := s.runDir(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	svcs, _ := findings.Load(filepath.Join(d, "services.json"))
	var summary map[string]any
	b, _ := os.ReadFile(filepath.Join(d, "run.json"))
	json.Unmarshal(b, &summary)
	writeJSON(w, map[string]any{"run": summary, "services": svcs})
}

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	a, ok1 := s.runDir(r.URL.Query().Get("from"))
	b, ok2 := s.runDir(r.URL.Query().Get("to"))
	if !ok1 || !ok2 {
		http.Error(w, "from/to must be run ids", http.StatusBadRequest)
		return
	}
	d, err := DiffRuns(a, b)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, d)
}

// DiffRuns compares services.json + hosts_up.json of two run directories.
func DiffRuns(a, b string) (findings.Diff, error) {
	sa, err := findings.Load(filepath.Join(a, "services.json"))
	if err != nil {
		return findings.Diff{}, err
	}
	sb, err := findings.Load(filepath.Join(b, "services.json"))
	if err != nil {
		return findings.Diff{}, err
	}
	return findings.Compare(filepath.Base(a), filepath.Base(b), sa, sb, loadUp(a), loadUp(b)), nil
}

func loadUp(dir string) []string {
	var up []string
	b, _ := os.ReadFile(filepath.Join(dir, "hosts_up.json"))
	json.Unmarshal(b, &up)
	return up
}
