package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	cancel   bool
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
	if err := a.launch(r.Context(), req, u.Username, launchOpts{}); err != nil {
		code := 400
		if err == errBusy {
			code = http.StatusConflict
		}
		fail(w, code, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "scan_start", "target_set", req.Set, req)
	writeJSON(w, 200, a.scanStatus())
}

type launchOpts struct {
	ResumeRun  string // continue this partial run instead of scanning the whole set
	ScheduleID int64
}

// launch starts `asi scan` as a subprocess (one at a time). Used by the GUI,
// by "resume" and by the scheduler.
func (a *App) launch(ctx context.Context, req ScanRequest, by string, o launchOpts) error {
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
			return errBusy
		}
	}
	inDir := filepath.Join(a.ResultsDir, "inputs")
	os.MkdirAll(inDir, 0o700)
	stamp := time.Now().Format("20060102-150405")
	tf := ""
	if o.ResumeRun == "" {
		ts, err := a.St.Targets(ctx, req.Set)
		if err != nil || len(ts) == 0 {
			return fmt.Errorf("zbiór celów %s jest pusty - dodaj cele w zakładce Cele", req.Set)
		}
		// the scan reads a frozen copy of the set from the database
		tf = filepath.Join(inDir, stamp+"-"+safe(req.Set)+".json")
		if err := targets.SaveJSON(tf, ts); err != nil {
			return err
		}
	}
	args, err := req.args(tf, a.ResultsDir, a.LiveAddr)
	if err != nil {
		return err
	}
	if o.ResumeRun != "" { // replace "-targets <file>" with "-resume <run>"
		args[1], args[2] = "-resume", o.ResumeRun
	}
	if o.ScheduleID > 0 {
		args = append(args, "-schedule-id", strconv.FormatInt(o.ScheduleID, 10), "-trigger", "schedule")
	}
	logPath := filepath.Join(inDir, stamp+".log")
	lf, err := os.Create(logPath)
	if err != nil {
		return err
	}
	cmd := exec.Command(a.Self, args...)
	cmd.Dir = a.WorkDir
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		lf.Close()
		return err
	}
	p := &scanProc{cmd: cmd, Started: time.Now(), Set: req.Set, Args: args[1:], By: by, LogPath: logPath, done: make(chan struct{})}
	if o.ResumeRun != "" {
		p.Set = "wznowienie " + o.ResumeRun
	}
	a.scan = p
	go func() {
		err := cmd.Wait()
		lf.Close()
		p.Finished = time.Now()
		if err != nil {
			p.ExitErr = err.Error()
		}
		close(p.done)
		if p.cancel { // cancelled: the run must not be resumed later
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			id, err := a.St.LatestRunSince(c, p.Started)
			if err == nil {
				err = a.St.CancelRun(c, id)
			}
			if err != nil {
				log.Printf("cancel: could not mark run cancelled: %v", err)
			}
		}
	}()
	return nil
}

// resumeRun: POST /api/v1/runs/{id}/resume - continue a partial run now.
func (a *App) resumeRun(w http.ResponseWriter, r *http.Request, u store.User) {
	var req ScanRequest
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) // optional parallel/rate/window
	id := r.PathValue("id")
	if err := a.launch(r.Context(), req, u.Username, launchOpts{ResumeRun: id}); err != nil {
		code := 400
		if err == errBusy {
			code = http.StatusConflict
		}
		fail(w, code, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "scan_resume", "run", id, req)
	writeJSON(w, 200, a.scanStatus())
}

func (a *App) statusLocked() ScanStatus {
	p := a.scan
	return ScanStatus{Running: true, Started: p.Started, Set: p.Set, By: p.By, Args: p.Args}
}

// stopScan (pause) sends SIGINT: asi scan stops gracefully, keeps partial results
// (run = partial) and its pending targets can be resumed. ?cancel=1 also drops the pending
// targets (run = cancelled).
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
	action := "scan_pause"
	if r.URL.Query().Get("cancel") == "1" {
		p.cancel, action = true, "scan_cancel"
	}
	p.cmd.Process.Signal(os.Interrupt)
	a.St.Audit(r.Context(), &u.ID, action, "target_set", p.Set, nil)
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
