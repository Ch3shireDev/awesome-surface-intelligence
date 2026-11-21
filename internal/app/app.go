// Package app is the ASI web application (DEV-4): login, dashboard, assets with
// editing, target form (manual + CSV/JSON), scan start/stop and live progress.
//
// Like MISP, the GUI is a wrapper over CLI commands and the database: a scan is
// `asi scan ...` started as a subprocess; its own live panel is reverse-proxied
// under /live/. Data comes from asi-db (internal/store).
package app

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"asi/internal/findings"
	"asi/internal/importer"
	"asi/internal/obs"
	"asi/internal/store"
	"asi/internal/targets"
)

//go:embed ui.html
var uiHTML []byte

type App struct {
	St         *store.Store
	ResultsDir string // where `asi scan -out` writes
	WorkDir    string // scans run here (targets/, results/)
	Self       string // path of the asi binary
	LiveAddr   string // 127.0.0.1:8091 - live panel of the running scan
	SessionTTL time.Duration
	Secure     bool // set Secure on cookies (behind TLS)

	mu   sync.Mutex
	scan *scanProc
}

const cookieName = "asi_session"

type ctxUser struct{}

// ---------------------------------------------------------------- routing

func (a *App) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'self'")
		w.Write(uiHTML)
	})
	m.HandleFunc("POST /api/v1/login", a.login)
	m.HandleFunc("POST /api/v1/logout", a.logout)

	m.Handle("GET /api/v1/me", a.need("viewer", a.me))
	m.Handle("GET /api/v1/dashboard", a.need("viewer", a.dashboard))
	m.Handle("GET /api/v1/assets", a.need("viewer", a.assets))
	m.Handle("PATCH /api/v1/asset", a.need("analyst", a.editAsset))
	m.Handle("GET /api/v1/asset/events", a.need("viewer", a.assetEvents))
	m.Handle("GET /api/v1/asset/observations", a.need("viewer", a.assetObservations))
	m.Handle("GET /api/v1/runs", a.need("viewer", a.runs))
	m.Handle("GET /api/v1/runs/{id}/events", a.need("viewer", a.runEvents))
	m.Handle("GET /api/v1/diff", a.need("viewer", a.diffRuns))
	m.Handle("GET /api/v1/target-sets", a.need("viewer", a.targetSets))
	m.Handle("GET /api/v1/targets", a.need("viewer", a.listTargets))
	m.Handle("POST /api/v1/targets", a.need("operator", a.addTargets))
	m.Handle("POST /api/v1/targets/import", a.need("operator", a.importTargets))
	m.Handle("POST /api/v1/targets/extract", a.need("operator", a.extractTargets))
	m.Handle("PUT /api/v1/targets/{id}", a.need("analyst", a.updateTarget)) // DEV-12: edycja istniejących celów
	m.Handle("DELETE /api/v1/targets/{id}", a.need("operator", a.deleteTarget))
	m.Handle("GET /api/v1/scans/current", a.need("viewer", a.currentScan))
	m.Handle("POST /api/v1/scans", a.need("operator", a.startScan))
	m.Handle("POST /api/v1/scans/current/stop", a.need("operator", a.stopScan))
	m.Handle("POST /api/v1/runs/{id}/resume", a.need("operator", a.resumeRun))
	m.Handle("POST /api/v1/results/import", a.need("operator", a.importResults))
	m.Handle("GET /api/v1/schedules", a.need("viewer", a.listSchedules))
	m.Handle("GET /api/v1/schedules/preview", a.need("viewer", a.cronPreview))
	m.Handle("POST /api/v1/schedules", a.need("operator", a.saveSchedule))
	m.Handle("PUT /api/v1/schedules/{id}", a.need("analyst", a.saveSchedule)) // DEV-12: edycja istniejącego harmonogramu
	m.Handle("DELETE /api/v1/schedules/{id}", a.need("operator", a.deleteSchedule))
	m.Handle("GET /api/v1/export/{file}", a.need("viewer", a.exportAssets))
	m.Handle("GET /api/v1/audit", a.need("admin", a.audit))
	m.Handle("GET /api/v1/users", a.need("admin", a.users))
	m.Handle("POST /api/v1/users", a.need("admin", a.createUser))
	m.Handle("PATCH /api/v1/users/{id}", a.need("admin", a.updateUser))
	m.Handle("DELETE /api/v1/users/{id}", a.need("admin", a.deleteUser))
	m.Handle("GET /api/v1/tokens", a.need("viewer", a.tokens))
	m.Handle("POST /api/v1/tokens", a.need("viewer", a.createToken))
	m.Handle("DELETE /api/v1/tokens/{id}", a.need("viewer", a.deleteToken))
	m.Handle("/live/", a.need("viewer", a.live))
	return securityHeaders(m)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// need: authentication (cookie or Bearer token) + role check + CSRF guard.
func (a *App) need(role string, h func(http.ResponseWriter, *http.Request, store.User)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, fromCookie := "", false
		if c, err := r.Cookie(cookieName); err == nil {
			tok, fromCookie = c.Value, true
		}
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tok, fromCookie = strings.TrimPrefix(h, "Bearer "), false
		}
		if tok == "" {
			fail(w, http.StatusUnauthorized, "login required")
			return
		}
		u, err := a.St.UserByToken(r.Context(), tok)
		if err != nil {
			fail(w, http.StatusUnauthorized, "session expired")
			return
		}
		// CSRF: state-changing requests authenticated by cookie must carry a custom
		// header, which a cross-site form cannot set (plus SameSite=Strict cookie).
		if fromCookie && r.Method != http.MethodGet && r.Header.Get("X-ASI") != "1" {
			fail(w, http.StatusForbidden, "missing X-ASI header")
			return
		}
		if !u.Can(role) {
			fail(w, http.StatusForbidden, "role "+u.Role+" cannot do this (needs "+role+")")
			return
		}
		h(w, r, u)
	})
}

// ---------------------------------------------------------------- auth

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
		fail(w, 400, "bad request")
		return
	}
	u, tok, err := a.St.Login(r.Context(), in.Username, in.Password, a.SessionTTL)
	if err != nil {
		time.Sleep(400 * time.Millisecond) // slow down guessing
		a.St.Audit(r.Context(), nil, "login_failed", "user", in.Username, nil)
		fail(w, http.StatusUnauthorized, "nieprawidłowy login lub hasło")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: a.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(a.SessionTTL.Seconds())})
	a.St.Audit(r.Context(), &u.ID, "login", "user", u.Username, nil)
	writeJSON(w, 200, u)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.St.RevokeToken(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) me(w http.ResponseWriter, r *http.Request, u store.User) { writeJSON(w, 200, u) }

// ---------------------------------------------------------------- dashboard

type interesting struct {
	Key      string   `json:"key"`
	Service  string   `json:"service"`
	Interest string   `json:"interest"`
	Reason   string   `json:"reason"`
	State    string   `json:"state"`
	Tags     []string `json:"tags"`
	Score    int      `json:"score,omitempty"`
}

func portService(as store.Asset) findings.Service {
	ip, proto, port := obs.SplitKey(as.Key)
	var d obs.ServiceData
	json.Unmarshal(as.Current, &d)
	return findings.Service{IP: ip, Port: port, Proto: proto, Name: d.Name, Product: d.Product, Version: d.Version, TLS: d.TLS}
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request, u store.User) {
	ctx := r.Context()
	all, err := a.St.Assets(ctx, store.AssetFilter{Limit: 100000})
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	counts := map[string]map[string]int{"host": {}, "port": {}}
	var hot, unstable []interesting
	for _, as := range all {
		counts[as.Kind][as.State]++
		if as.Flapping {
			counts[as.Kind]["flapping"]++
		}
		var it interesting
		if as.Kind == "port" {
			s := portService(as)
			s.Interest, s.Reason = findings.Score(s)
			v := verdictOf(as)
			v.Apply(&s)
			lvl, why := s.Interest, s.Reason
			it = interesting{Key: as.Key, Service: strings.TrimSpace(s.Fingerprint()), Interest: lvl, Reason: why, State: as.State, Tags: as.UserTags}
			if (as.State == "active" || as.State == "new") && lvl != "low" && !v.Dismissed() {
				hot = append(hot, it)
			}
		} else {
			it = interesting{Key: as.Key, State: as.State, Tags: as.UserTags}
		}
		if as.Flapping || as.State == "missing" || as.State == "gone" {
			if as.Flapping {
				it.Reason = "flapping"
			}
			unstable = append(unstable, it)
		}
	}
	// custom signatures (nuclei, SEC-5): everything above "info" is an analyst-relevant finding
	dismissed, levelOverride := map[string]bool{}, map[string]string{}
	for _, as := range all {
		v := verdictOf(as)
		if v.Dismissed() {
			dismissed[as.Key] = true
		}
		if v.Interest != "" {
			levelOverride[as.Key] = v.Interest // analyst's level applies to the whole asset, signatures too
		}
	}
	if _, sigs, err := a.St.LatestSignatures(ctx); err == nil {
		sevLevel := map[string]string{"critical": "high", "high": "high", "medium": "medium", "low": "medium"}
		for _, o := range sigs {
			var d obs.SignatureData
			o.Decode(&d)
			lvl, ok := sevLevel[d.Severity]
			if lo, has := levelOverride[o.AssetKey]; has {
				lvl, ok = lo, lo != "low"
			}
			if !ok || dismissed[o.AssetKey] {
				continue
			}
			reason := "sygnatura " + d.ID
			if len(d.Extract) > 0 {
				reason += ": " + strings.Join(d.Extract, ", ")
			}
			hot = append(hot, interesting{Key: o.AssetKey, Service: d.Name, Interest: lvl, Reason: reason, State: "active"})
		}
	}
	runs, _ := a.St.Runs(ctx, 20)
	var latest *store.Run
	var events []store.Event
	var newKeys []string
	latestID := ""
	if len(runs) > 0 {
		latest = &runs[0]
		latestID = latest.ID
		events, _ = a.St.Events(ctx, latest.ID, "", 200)
		newKeys, _ = a.St.EventAssetKeys(ctx, latest.ID, []string{"new", "reappeared"})
	}
	timeline, _ := a.St.EventCounts(ctx, 20)
	ins := a.buildInsights(ctx, all)
	if len(ins.Ranked) > 0 || len(hot) == 0 {
		hot = hot[:0]
		for _, x := range ins.Ranked {
			hot = append(hot, interesting{Key: x.Key, Service: x.Service, Interest: x.Interest, Reason: x.Reason, State: x.State, Tags: x.Tags, Score: x.Score})
		}
	}
	writeJSON(w, 200, map[string]any{
		"groups": ins.Groups, "time_patterns": ins.Patterns,
		"counts": counts, "interesting": hot, "unstable": unstable, "latest_run": latest,
		"latest_events": events, "latest_new": map[string]any{"run": latestID, "count": len(newKeys), "keys": newKeys},
		"timeline": timeline, "scan": a.scanStatus(),
		"slow_http_ms": slowHTTPThresholdMs(),
	})
}

// parseEventTypes keeps only the event types the schema allows (asset_events.type CHECK).
func parseEventTypes(v string) []string {
	allowed := map[string]bool{"new": true, "reappeared": true, "changed": true, "missing": true, "gone": true, "flapping": true}
	out := []string{}
	for _, t := range strings.Split(v, ",") {
		if t = strings.TrimSpace(t); allowed[t] {
			out = append(out, t)
		}
	}
	return out
}

const defaultSlowHTTPMs = 500

func slowHTTPThresholdMs() int {
	if v := strings.TrimSpace(os.Getenv("ASI_HTTP_SLOW_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultSlowHTTPMs
}

func assetHTTPMs(as store.Asset) int {
	if len(as.HTTP) == 0 {
		return 0
	}
	var d obs.HTTPData
	if json.Unmarshal(as.HTTP, &d) != nil {
		return 0
	}
	return d.ResponseTimeMs
}

// ---------------------------------------------------------------- assets

func (a *App) assets(w http.ResponseWriter, r *http.Request, u store.User) {
	q := r.URL.Query()
	f := store.AssetFilter{State: q.Get("state"), Kind: q.Get("kind"), Search: q.Get("q"), Flapping: q.Get("flapping") == "1", Limit: 5000}
	// "nowe w ostatnim skanie" to zmiany, nie stan: ?run=<id>&events=new,reappeared
	if run := strings.TrimSpace(q.Get("run")); run != "" {
		f.RunID, f.Events = run, parseEventTypes(q.Get("events"))
		if len(f.Events) == 0 {
			f.Events = []string{"new", "reappeared"}
		}
	}
	svcQ := strings.ToLower(q.Get("svc")) // group link: service/product text instead of key
	slowOnly := q.Get("slow") == "1"
	if svcQ != "" || slowOnly {
		f.Kind, f.Limit = "port", 100000
		if svcQ != "" {
			f.Search = ""
		}
	}
	as, err := a.St.Assets(r.Context(), f)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	type row struct {
		store.Asset
		Interest string `json:"interest,omitempty"`
		Reason   string `json:"reason,omitempty"`
		Service  string `json:"service,omitempty"`
		Verdict  string `json:"verdict,omitempty"`
		HTTPMs   int    `json:"http_ms,omitempty"`
		SlowHTTP bool   `json:"slow_http,omitempty"`
	}
	if svcQ != "" {
		kept := as[:0]
		for _, x := range as {
			if strings.Contains(strings.ToLower(portService(x).Fingerprint()), svcQ) {
				kept = append(kept, x)
			}
		}
		as = kept
	}
	slowMs := slowHTTPThresholdMs()
	out := make([]row, 0, len(as))
	for _, x := range as {
		item := row{Asset: x}
		if x.Kind == "port" {
			s := portService(x)
			s.Interest, s.Reason = findings.Score(s)
			verdictOf(x).Apply(&s)
			item.Interest, item.Reason, item.Verdict = s.Interest, s.Reason, s.Verdict
			item.Service = strings.TrimSpace(s.Fingerprint())
			if ms := assetHTTPMs(x); ms > 0 {
				item.HTTPMs = ms
				item.SlowHTTP = ms >= slowMs
			}
		}
		if slowOnly && !item.SlowHTTP {
			continue
		}
		out = append(out, item)
	}
	writeJSON(w, 200, out)
}

func (a *App) editAsset(w http.ResponseWriter, r *http.Request, u store.User) {
	key := r.URL.Query().Get("key")
	var e store.AssetEdit
	if key == "" || json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&e) != nil {
		fail(w, 400, "bad request")
		return
	}
	if e.Overrides != nil {
		var v findings.Verdict
		if json.Unmarshal(*e.Overrides, &v) != nil || !v.Valid() {
			fail(w, 400, "ocena analityka: status false_positive|accepted|\"\", interest high|medium|low|\"\"")
			return
		}
		norm, _ := json.Marshal(v) // store only known fields
		raw := json.RawMessage(norm)
		e.Overrides = &raw
	}
	if e.Note != nil && len(*e.Note) > 4000 {
		fail(w, 400, "note too long")
		return
	}
	if err := a.St.EditAsset(r.Context(), &u.ID, key, e); err != nil {
		fail(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) assetEvents(w http.ResponseWriter, r *http.Request, u store.User) {
	ev, err := a.St.Events(r.Context(), "", r.URL.Query().Get("key"), 500)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ev)
}

func (a *App) assetObservations(w http.ResponseWriter, r *http.Request, u store.User) {
	os, err := a.St.AssetObservations(r.Context(), r.URL.Query().Get("key"), "http", "signature")
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, os)
}

func (a *App) runs(w http.ResponseWriter, r *http.Request, u store.User) {
	rs, err := a.St.Runs(r.Context(), 100)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rs)
}

func verdictOf(as store.Asset) findings.Verdict {
	var v findings.Verdict
	json.Unmarshal(as.UserOverrides, &v)
	return v
}

// diffRuns: GET /api/v1/diff?from=A&to=B - compare any two runs (PDF minimum: "porównanie dwóch skanów").
func (a *App) diffRuns(w http.ResponseWriter, r *http.Request, u store.User) {
	d, err := a.St.DiffRuns(r.Context(), r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, d)
}

func (a *App) runEvents(w http.ResponseWriter, r *http.Request, u store.User) {
	ev, err := a.St.Events(r.Context(), r.PathValue("id"), "", 5000)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ev)
}

// ---------------------------------------------------------------- targets (form)

func (a *App) targetSets(w http.ResponseWriter, r *http.Request, u store.User) {
	s, err := a.St.TargetSets(r.Context())
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if len(s) == 0 {
		s = []string{"default"}
	}
	writeJSON(w, 200, s)
}

func setName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	return s
}

func (a *App) listTargets(w http.ResponseWriter, r *http.Request, u store.User) {
	ts, err := a.St.TargetRows(r.Context(), setName(r.URL.Query().Get("set")))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ts)
}

// validTarget: IP, CIDR or hostname - nothing else reaches the scanner.
var reHost = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func validTarget(v string) error {
	if _, err := targets.ParseAddrOrPrefix(v); err == nil {
		return nil
	}
	if reHost.MatchString(v) {
		return nil
	}
	return fmt.Errorf("%q nie jest adresem IP, zakresem CIDR ani domeną", v)
}

func (a *App) saveTargets(w http.ResponseWriter, r *http.Request, u store.User, set string, ts []targets.Target, how string) {
	var bad []string
	var ok []targets.Target
	for _, t := range ts {
		t.Target = strings.TrimSpace(t.Target)
		if t.Target == "" {
			continue
		}
		if err := validTarget(t.Target); err != nil {
			bad = append(bad, err.Error())
			continue
		}
		ok = append(ok, t)
	}
	n, err := a.St.MergeTargets(r.Context(), set, ok) // add/import never wipes tags or notes
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, how, "target_set", set, map[string]any{"written": n, "rejected": len(bad)})
	writeJSON(w, 200, map[string]any{"written": n, "rejected": bad})
}

func (a *App) addTargets(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Set     string           `json:"set"`
		Text    string           `json:"text"` // one target per line
		Targets []targets.Target `json:"targets"`
		Tags    []string         `json:"tags"`
		Owner   string           `json:"owner"`
		Note    string           `json:"note"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in) != nil {
		fail(w, 400, "bad request")
		return
	}
	ts := in.Targets
	for _, line := range strings.FieldsFunc(in.Text, func(c rune) bool { return c == '\n' || c == ',' || c == ';' || c == ' ' }) {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			ts = append(ts, targets.Target{Target: line, Enabled: true, Tags: in.Tags, Owner: in.Owner, Note: in.Note})
		}
	}
	a.saveTargets(w, r, u, setName(in.Set), ts, "targets_add")
}

func (a *App) importTargets(w http.ResponseWriter, r *http.Request, u store.User) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, 400, "file required")
		return
	}
	defer f.Close()
	ext := strings.ToLower(filepath.Ext(hdr.Filename))
	if ext != ".csv" && ext != ".json" && ext != ".txt" {
		fail(w, 400, "tylko .csv, .json albo .txt")
		return
	}
	tmp, err := os.CreateTemp("", "asi-import-*"+ext)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	io.Copy(tmp, f)
	tmp.Close()
	ts, err := targets.Load(tmp.Name())
	if err != nil {
		fail(w, 400, "nie da się wczytać pliku: "+err.Error())
		return
	}
	a.saveTargets(w, r, u, setName(r.FormValue("set")), ts, "targets_import")
}

func (a *App) updateTarget(w http.ResponseWriter, r *http.Request, u store.User) {
	var t store.TargetRow
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&t) != nil || validTarget(t.Value) != nil {
		fail(w, 400, "bad request")
		return
	}
	// DEV-12: PUT edytuje ISTNIEJĄCY cel (rola analyst wystarcza). Zmiana samej wartości
	// to w praktyce usunięcie starego i dodanie nowego, więc wymaga operatora.
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	cur, err := a.St.TargetValueByID(r.Context(), id)
	if err != nil {
		fail(w, 404, "nie ma celu o tym id")
		return
	}
	if cur != t.Value {
		fail(w, 400, "zmiana wartości celu = usunięcie i dodanie (rola operator); edytuj tagi, notatkę, właściciela")
		return
	}
	_, err = a.St.UpsertTargets(r.Context(), setName(t.Set), []targets.Target{{Target: t.Value, Asset: t.Asset,
		Owner: t.Owner, Tags: t.Tags, Enabled: t.Enabled, Note: t.Note}})
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "target_edit", "target", t.Value, map[string]any{"enabled": t.Enabled, "tags": t.Tags})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) deleteTarget(w http.ResponseWriter, r *http.Request, u store.User) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	v, err := a.St.DeleteTarget(r.Context(), id)
	if err != nil {
		fail(w, 404, "not found")
		return
	}
	a.St.Audit(r.Context(), &u.ID, "target_delete", "target", v, nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- import of scan results (DEV-6)

func (a *App) importResults(w http.ResponseWriter, r *http.Request, u store.User) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, 400, "file required")
		return
	}
	defer f.Close()
	data, err := importer.ReadAll(f, 64<<20)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	o := importer.Options{Coverage: r.FormValue("coverage"), By: &u.ID}
	if v := r.FormValue("at"); v != "" {
		if t, err := time.Parse("2006-01-02T15:04", v); err == nil {
			o.At = t
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			o.At = t
		} else {
			fail(w, 400, "data: RRRR-MM-DDTHH:MM")
			return
		}
	}
	if o.Coverage != "" && o.Coverage != "auto" && o.Coverage != "none" {
		fail(w, 400, "coverage: auto albo none")
		return
	}
	s, err := importer.Import(r.Context(), a.St, filepath.Base(hdr.Filename), data, o)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "results_import", "run", s.RunID, map[string]any{"file": hdr.Filename, "format": s.Format, "observations": s.Obs})
	writeJSON(w, 200, s)
}

// ---------------------------------------------------------------- export (DEV-6 subset)

func (a *App) exportAssets(w http.ResponseWriter, r *http.Request, u store.User) {
	as, err := a.St.Assets(r.Context(), store.AssetFilter{Limit: 1000000})
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	name := "asi-assets-" + time.Now().Format("20060102-150405")
	format := strings.TrimPrefix(r.PathValue("file"), "assets.")
	switch format {
	case "json":
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		writeJSON(w, 200, as)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
		writeAssetsCSV(w, as)
	default:
		fail(w, 404, "json or csv")
	}
	a.St.Audit(r.Context(), &u.ID, "export", "assets", format, map[string]int{"rows": len(as)})
}

// ---------------------------------------------------------------- admin

func (a *App) audit(w http.ResponseWriter, r *http.Request, u store.User) {
	l, err := a.St.AuditLog(r.Context(), 300)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, l)
}

func (a *App) users(w http.ResponseWriter, r *http.Request, u store.User) {
	l, err := a.St.Users(r.Context())
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, l)
}

// updateUser: PATCH /api/v1/users/{id} (DEV-11). Admin changes role, blocks an
// account or resets its password without knowing the old one. Blocking or a password
// change revokes every session and API token of that user, so the effect is immediate.
func (a *App) updateUser(w http.ResponseWriter, r *http.Request, admin store.User) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		fail(w, 400, "bad user id")
		return
	}
	var in struct {
		Role     string `json:"role"`
		Disabled *bool  `json:"disabled"`
		Password string `json:"password"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in) != nil {
		fail(w, 400, "bad request")
		return
	}
	u, err := a.St.UpdateUser(r.Context(), id, store.UserUpdate{Role: in.Role, Disabled: in.Disabled, Password: in.Password})
	if err != nil {
		status := 400
		if errors.Is(err, store.ErrLastAdmin) {
			status = http.StatusConflict
		}
		fail(w, status, err.Error())
		return
	}
	details := map[string]any{"role": u.Role, "disabled": u.Disabled, "password_reset": in.Password != ""}
	a.St.Audit(r.Context(), &admin.ID, "user_update", "user", u.Username, details)
	writeJSON(w, 200, u)
}

// deleteUser: DELETE /api/v1/users/{id} (DEV-11). The last active admin cannot be
// deleted; tokens go with the account.
func (a *App) deleteUser(w http.ResponseWriter, r *http.Request, admin store.User) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id <= 0 {
		fail(w, 400, "bad user id")
		return
	}
	if err := a.St.DeleteUser(r.Context(), id); err != nil {
		status := 400
		if errors.Is(err, store.ErrLastAdmin) {
			status = http.StatusConflict
		}
		fail(w, status, err.Error())
		return
	}
	a.St.Audit(r.Context(), &admin.ID, "user_delete", "user", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- tokens (DEV-3)

// reqToken returns the token that authenticated the request: cookie first, then
// Bearer (same precedence as need()).
func reqToken(r *http.Request) string {
	tok := ""
	if c, err := r.Cookie(cookieName); err == nil {
		tok = c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimPrefix(h, "Bearer ")
	}
	return tok
}

func (a *App) tokens(w http.ResponseWriter, r *http.Request, u store.User) {
	l, err := a.St.Tokens(r.Context(), u.ID, reqToken(r))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, l)
}

// createToken issues an API token for the logged-in user. The plain value is
// returned once and never stored (only its sha256 hash is).
func (a *App) createToken(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Name string
		Days int
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
		fail(w, 400, "bad request")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "api"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	if in.Days < 0 {
		in.Days = 0
	}
	if in.Days > 3650 {
		in.Days = 3650
	}
	tok, err := a.St.NewToken(r.Context(), u.ID, name, time.Duration(in.Days)*24*time.Hour)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "token_create", "token", name, map[string]int{"days": in.Days})
	writeJSON(w, 200, map[string]any{"token": tok, "name": name, "days": in.Days})
}

func (a *App) deleteToken(w http.ResponseWriter, r *http.Request, u store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	ok, err := a.St.DeleteToken(r.Context(), u.ID, id)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if !ok {
		fail(w, 404, "nie ma takiego tokenu")
		return
	}
	a.St.Audit(r.Context(), &u.ID, "token_revoke", "token", strconv.FormatInt(id, 10), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) createUser(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct{ Username, Password, Role string }
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil || len(in.Password) < 10 || in.Username == "" {
		fail(w, 400, "username i hasło (min. 10 znaków) wymagane")
		return
	}
	nu, err := a.St.CreateUser(r.Context(), in.Username, in.Password, in.Role)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.St.Audit(r.Context(), &u.ID, "user_create", "user", nu.Username, map[string]string{"role": nu.Role})
	writeJSON(w, 200, nu)
}

// ---------------------------------------------------------------- live panel proxy

func (a *App) live(w http.ResponseWriter, r *http.Request, u store.User) {
	if !a.scanStatus().Running && !strings.HasSuffix(r.URL.Path, "/live/") {
		fail(w, 404, "no running scan")
		return
	}
	target, _ := url.Parse("http://" + a.LiveAddr)
	p := httputil.NewSingleHostReverseProxy(target)
	p.FlushInterval = -1 // SSE
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<p style="font:14px system-ui;padding:20px">Brak aktywnego skanu. Uruchom skan w zakładce Skany.</p>`)
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/live")
	r2.Header.Del("Cookie") // the scan panel does not need our session
	p.ServeHTTP(w, r2)
}

var errBusy = errors.New("skan już trwa")

func init() { log.SetFlags(log.Ltime) }
