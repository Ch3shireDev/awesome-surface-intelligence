package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"asi/internal/schedule"
	"asi/internal/store"
)

// RunScheduler fires due schedules (DEV-5). Each firing starts a scan with the
// schedule's window; if the previous window of this schedule left targets
// unscanned (run = partial), the new window first RESUMES them (VISION 4.5:
// "deferred chunks return at the start of the next window"). A firing that finds
// another scan running is skipped and recorded in last_error.
func (a *App) RunScheduler(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		a.tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *App) tick(ctx context.Context, now time.Time) {
	due, err := a.St.DueSchedules(ctx, now)
	if err != nil {
		log.Printf("scheduler: %v", err)
		return
	}
	for _, sc := range due {
		next := nextRun(sc.Cron, now)
		var req ScanRequest
		json.Unmarshal(sc.Params, &req)
		req.Set = sc.Set
		req.Window = fmt.Sprintf("%dm", sc.WindowMinutes)

		opts := launchOpts{ScheduleID: sc.ID}
		if prev, pending, err := a.St.Resumable(ctx, sc.ID); err == nil && prev != "" {
			opts.ResumeRun = prev
			log.Printf("scheduler: %s resumes %d targets of %s", sc.Name, len(pending), prev)
		}
		msg := ""
		if err := a.launch(ctx, req, "harmonogram:"+sc.Name, opts); err != nil {
			msg = "pominięty: " + err.Error()
			log.Printf("scheduler: %s %s", sc.Name, msg)
		} else {
			log.Printf("scheduler: started %s (window %dm, next %s)", sc.Name, sc.WindowMinutes, fmtNext(next))
			a.St.Audit(ctx, nil, "scan_scheduled", "schedule", sc.Name, map[string]any{"resume_of": opts.ResumeRun})
		}
		a.St.MarkScheduleFired(ctx, sc.ID, now, next, msg)
	}
}

func nextRun(cron string, from time.Time) *time.Time {
	spec, err := schedule.Parse(cron)
	if err != nil {
		return nil
	}
	n := spec.Next(from)
	if n.IsZero() {
		return nil
	}
	return &n
}

func fmtNext(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.DateTime)
}

// ---------------------------------------------------------------- API

func (a *App) listSchedules(w http.ResponseWriter, r *http.Request, u store.User) {
	l, err := a.St.Schedules(r.Context())
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if l == nil {
		l = []store.Schedule{}
	}
	writeJSON(w, 200, map[string]any{"schedules": l, "server_time": time.Now(), "tz": time.Now().Format("MST -07:00")})
}

func (a *App) saveSchedule(w http.ResponseWriter, r *http.Request, u store.User) {
	var sc store.Schedule
	if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&sc) != nil {
		fail(w, 400, "bad request")
		return
	}
	if id := r.PathValue("id"); id != "" {
		sc.ID, _ = strconv.ParseInt(id, 10, 64)
	}
	sc.Name, sc.Set = strings.TrimSpace(sc.Name), setName(sc.Set)
	if sc.Name == "" || len(sc.Name) > 80 {
		fail(w, 400, "nazwa wymagana (max 80 znaków)")
		return
	}
	if sc.WindowMinutes < 1 || sc.WindowMinutes > 1440 {
		fail(w, 400, "okno: 1-1440 minut")
		return
	}
	spec, err := schedule.Parse(sc.Cron)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var req ScanRequest
	if len(sc.Params) > 0 {
		if json.Unmarshal(sc.Params, &req) != nil {
			fail(w, 400, "params")
			return
		}
	}
	if req.Parallel == 0 {
		req.Parallel = 5
	}
	if req.Rate == 0 {
		req.Rate = 300
	}
	req.Window = ""
	if _, err := req.args("x", a.ResultsDir, a.LiveAddr); err != nil { // same validation as a manual scan
		fail(w, 400, err.Error())
		return
	}
	sc.Params, _ = json.Marshal(req)
	var next *time.Time
	if n := spec.Next(time.Now()); !n.IsZero() {
		next = &n
	}
	saved, err := a.St.SaveSchedule(r.Context(), sc, next, &u.ID)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "schedule_save", "schedule", saved.Name, map[string]any{"cron": saved.Cron, "window_minutes": saved.WindowMinutes, "enabled": saved.Enabled})
	writeJSON(w, 200, saved)
}

func (a *App) deleteSchedule(w http.ResponseWriter, r *http.Request, u store.User) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.St.DeleteSchedule(r.Context(), id); err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "schedule_delete", "schedule", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// cronPreview: GET /api/v1/schedules/preview?cron=... -> next 5 starts (form helper)
func (a *App) cronPreview(w http.ResponseWriter, r *http.Request, u store.User) {
	spec, err := schedule.Parse(r.URL.Query().Get("cron"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var out []time.Time
	t := time.Now()
	for i := 0; i < 5; i++ {
		t = spec.Next(t)
		if t.IsZero() {
			break
		}
		out = append(out, t)
	}
	writeJSON(w, 200, out)
}
