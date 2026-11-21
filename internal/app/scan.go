package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"asi/internal/scanner/nmap"
	"asi/internal/store"
	"asi/internal/targets"
)

type scanProc struct {
	cmd      *exec.Cmd
	Started  time.Time `json:"started"`
	Set      string    `json:"set"`
	Args     []string  `json:"args"`
	By       string    `json:"by"`
	LogPath  string    `json:"-"`
	Finished time.Time `json:"finished,omitempty"`
	ExitErr  string    `json:"exit_error,omitempty"`
	done     chan struct{}
}

type ScanStatus struct {
	Running  bool      `json:"running"`
	Started  time.Time `json:"started,omitempty"`
	Finished time.Time `json:"finished,omitempty"`
	Set      string    `json:"set,omitempty"`
	By       string    `json:"by,omitempty"`
	Args     []string  `json:"args,omitempty"`
	ExitErr  string    `json:"exit_error,omitempty"`
	LogTail  []string  `json:"log_tail,omitempty"`
}

func (a *App) scanStatus() ScanStatus {
	a.mu.Lock()
	p := a.scan
	a.mu.Unlock()
	if p == nil {
		return ScanStatus{}
	}
	st := ScanStatus{Started: p.Started, Set: p.Set, By: p.By, Args: p.Args}
	select {
	case <-p.done:
		st.Finished, st.ExitErr = p.Finished, p.ExitErr
	default:
		st.Running = true
	}
	st.LogTail = tail(p.LogPath, 15)
	return st
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func tail(path string, n int) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := ansi.ReplaceAllString(string(b), "")
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.Contains(l, "█") && !strings.HasPrefix(l, "workers:") {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

func (a *App) currentScan(w http.ResponseWriter, r *http.Request, u store.User) {
	writeJSON(w, 200, a.scanStatus())
}

type ScanRequest struct {
	Set      string `json:"set"`
	Parallel int    `json:"parallel"`
	Rate     int    `json:"rate"`
	Ports    string `json:"ports"`  // "top100" | "top1000" | "22,80,443,8000-8100"
	Window   string `json:"window"` // "" | "30m" | "2h"
	Upload   string `json:"upload"` // off | end | live
}

var rePorts = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*$`)

// Hard limits of the GUI (the CLI operator can go further deliberately).
const (
	maxParallel = 32
	maxRate     = 5000
)

func (req ScanRequest) args(targetsFile, results, live string) ([]string, error) {
	if req.Parallel < 1 || req.Parallel > maxParallel {
		return nil, fmt.Errorf("równoległość 1-%d", maxParallel)
	}
	if req.Rate < 1 || req.Rate > maxRate {
		return nil, fmt.Errorf("tempo 1-%d pps", maxRate)
	}
	svc := strings.Replace(nmap.DefaultServicesArgs, "--top-ports 1000", "", 1)
	switch {
	case req.Ports == "top100":
		svc += " --top-ports 100"
	case req.Ports == "top1000" || req.Ports == "":
		svc += " --top-ports 1000"
	case rePorts.MatchString(req.Ports):
		svc += " -p " + req.Ports
	default:
		return nil, fmt.Errorf("porty: top100, top1000 albo lista np. 22,80,443,8000-8100")
	}
	args := []string{"scan", "-targets", targetsFile, "-out", results, "-ui", live, "-ui-wait=false",
		"-parallel", strconv.Itoa(req.Parallel), "-rate", strconv.Itoa(req.Rate), "-nmap", strings.Join(strings.Fields(svc), " ")}
	if req.Window != "" {
		d, err := time.ParseDuration(req.Window)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			return nil, fmt.Errorf("okno: od 1m do 24h, np. 30m, 2h")
		}
		args = append(args, "-window", d.String())
	}
	switch req.Upload {
	case "", "off", "end", "live":
		if req.Upload != "" {
			args = append(args, "-upload", req.Upload)
		}
	default:
		return nil, fmt.Errorf("upload: off, end albo live")
	}
	return args, nil
}

func (a *App) startScan(w http.ResponseWriter, r *http.Request, u store.User) {
	var req ScanRequest
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) != nil {
		fail(w, 400, "bad request")
		return
	}
	req.Set = setName(req.Set)
	if req.Parallel == 0 {
		req.Parallel = 5
	}
	if req.Rate == 0 {
		req.Rate = 300
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.scan != nil {
		select {
		case <-a.scan.done:
		default:
			fail(w, http.StatusConflict, errBusy.Error())
			return
		}
	}
	ts, err := a.St.Targets(r.Context(), req.Set)
	if err != nil || len(ts) == 0 {
		fail(w, 400, "zbiór celów "+req.Set+" jest pusty - dodaj cele w zakładce Cele")
		return
	}
	// the scan reads a frozen copy of the set from the database
	inDir := filepath.Join(a.ResultsDir, "inputs")
	os.MkdirAll(inDir, 0o700)
	stamp := time.Now().Format("20060102-150405")
	tf := filepath.Join(inDir, stamp+"-"+safe(req.Set)+".json")
	if err := targets.SaveJSON(tf, ts); err != nil {
		fail(w, 500, err.Error())
		return
	}
	args, err := req.args(tf, a.ResultsDir, a.LiveAddr)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	logPath := filepath.Join(inDir, stamp+".log")
	lf, err := os.Create(logPath)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	cmd := exec.CommandContext(context.Background(), a.Self, args...)
	cmd.Dir = a.WorkDir
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		lf.Close()
		fail(w, 500, err.Error())
		return
	}
	p := &scanProc{cmd: cmd, Started: time.Now(), Set: req.Set, Args: args[1:], By: u.Username, LogPath: logPath, done: make(chan struct{})}
	a.scan = p
	go func() {
		err := cmd.Wait()
		lf.Close()
		p.Finished = time.Now()
		if err != nil {
			p.ExitErr = err.Error()
		}
		close(p.done)
	}()
	a.St.Audit(r.Context(), &u.ID, "scan_start", "target_set", req.Set, req)
	writeJSON(w, 200, a.statusLocked())
}

func (a *App) statusLocked() ScanStatus {
	p := a.scan
	return ScanStatus{Running: true, Started: p.Started, Set: p.Set, By: p.By, Args: p.Args}
}

// stopScan sends SIGINT: asi scan stops gracefully, keeps partial results (run = partial).
func (a *App) stopScan(w http.ResponseWriter, r *http.Request, u store.User) {
	a.mu.Lock()
	p := a.scan
	a.mu.Unlock()
	if p == nil || p.cmd.Process == nil {
		fail(w, 404, "no scan")
		return
	}
	select {
	case <-p.done:
		fail(w, 409, "scan already finished")
		return
	default:
	}
	p.cmd.Process.Signal(os.Interrupt)
	a.St.Audit(r.Context(), &u.ID, "scan_stop", "target_set", p.Set, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func safe(s string) string {
	return regexp.MustCompile(`[^a-zA-Z0-9_-]`).ReplaceAllString(s, "_")
}

func writeAssetsCSV(w io.Writer, as []store.Asset) {
	c := csv.NewWriter(w)
	c.Write([]string{"key", "kind", "ip", "port", "state", "flapping", "service", "first_seen", "last_seen",
		"seen_count", "consecutive_misses", "user_tags", "user_note"})
	for _, x := range as {
		svc := ""
		if x.Kind == "port" {
			svc = portService(x).Fingerprint()
		}
		c.Write([]string{x.Key, x.Kind, x.IP, strconv.Itoa(x.Port), x.State, strconv.FormatBool(x.Flapping), svc,
			x.FirstSeen.Format(time.RFC3339), x.LastSeen.Format(time.RFC3339), strconv.Itoa(x.SeenCount),
			strconv.Itoa(x.ConsecutiveMisses), strings.Join(x.UserTags, ";"), x.UserNote})
	}
	c.Flush()
}
