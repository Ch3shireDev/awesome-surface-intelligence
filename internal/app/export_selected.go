package app

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"asi/internal/dojo"
	"asi/internal/findings"
	"asi/internal/obs"
	"asi/internal/siem"
	"asi/internal/store"
)

const selectedTestTitle = "asi-selected"

// POST /api/v1/export/selected {"keys":[...],"to":"csv|json|dojo|siem"}: only the chosen assets.
func (a *App) exportSelected(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Keys []string `json:"keys"`
		To   string   `json:"to"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in) != nil || len(in.Keys) == 0 {
		fail(w, 400, "zaznacz co najmniej jeden asset")
		return
	}
	switch in.To {
	case "csv", "json":
	case "dojo", "siem": // leaves ASI for another system
		if !u.Can("operator") {
			fail(w, 403, "role "+u.Role+" cannot do this (needs operator)")
			return
		}
	default:
		fail(w, 400, "to: csv, json, dojo albo siem")
		return
	}
	ctx := r.Context()
	all, err := a.St.Assets(ctx, store.AssetFilter{Limit: 1000000})
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	as := pickAssets(all, in.Keys)
	if len(as) == 0 {
		fail(w, 404, "nie ma takich assetów")
		return
	}
	var svcs []findings.Service
	if in.To == "dojo" || in.To == "siem" {
		sigs := map[string][]obs.SignatureData{}
		if _, list, err := a.St.LatestSignatures(ctx); err == nil {
			for _, o := range list {
				var d obs.SignatureData
				if o.Decode(&d) == nil {
					sigs[o.AssetKey] = append(sigs[o.AssetKey], d)
				}
			}
		}
		svcs = selectedServices(as, sigs)
	}
	switch in.To {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		writeAssetsCSV(w, as)
	case "json":
		writeJSON(w, 200, as)
	case "dojo":
		if len(svcs) == 0 {
			fail(w, 400, "do DefectDojo trafiają porty: zaznacz co najmniej jeden port")
			return
		}
		env := func(k, def string) string {
			if v := os.Getenv(k); v != "" {
				return v
			}
			return def
		}
		c := &dojo.Client{URL: strings.TrimRight(env("DD_URL", "http://localhost:"+env("DD_PORT", "8080")), "/"),
			Token: env("DD_TOKEN", os.Getenv("DD_API_KEY"))}
		if c.Token == "" {
			if c.Token, err = c.Login(env("DD_ADMIN_USER", "admin"), os.Getenv("DD_ADMIN_PASSWORD")); err != nil {
				fail(w, 502, "DefectDojo: logowanie nieudane")
				return
			}
		}
		// own test and close_old=false: a selection must never close anything
		res, err := c.Reimport("asi-selected.json", findings.GenericJSON(svcs), dojo.Target{
			ScanType: "Generic Findings Import", ProductType: env("DD_PRODUCT_TYPE", "Research and Development"),
			Product: env("DD_PRODUCT", "ASI PoC"), Engagement: "discovery", TestTitle: selectedTestTitle,
			Tags: []string{"asi", selectedTestTitle}}, false)
		if err != nil {
			fail(w, 502, "DefectDojo: "+err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"sent": len(svcs), "test": res.Test})
	case "siem":
		byKey := map[string]findings.Service{}
		for _, s := range svcs {
			byKey[obs.PortKey(s.IP, s.Proto, s.Port)] = s
		}
		evs := make([]siem.Event, 0, len(as))
		for _, x := range as {
			e := siem.Event{At: time.Now().UTC(), Type: "selected", Key: x.Key, State: x.State, RunID: x.LastSeenRun}
			if s, ok := byKey[x.Key]; ok {
				e.Service, e.Severity = strings.TrimSpace(s.Fingerprint()), s.Interest
			}
			evs = append(evs, e)
		}
		if err := siem.Send(ctx, siem.URL(), evs); err != nil {
			code := 502
			if err == siem.ErrNotConfigured {
				code = 409
			}
			fail(w, code, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"sent": len(evs)})
	}
	a.St.Audit(ctx, &u.ID, "export_selected", "assets", in.To, map[string]int{"rows": len(as)})
}

func pickAssets(all []store.Asset, keys []string) []store.Asset {
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var out []store.Asset
	for _, x := range all {
		if want[x.Key] {
			out = append(out, x)
		}
	}
	return out
}

// selectedServices ranks the chosen ports like the panel: HTTP, signatures, analyst's verdict.
func selectedServices(as []store.Asset, sigs map[string][]obs.SignatureData) []findings.Service {
	var out []findings.Service
	for _, x := range as {
		if x.Kind != "port" {
			continue
		}
		s := portService(x)
		var web *findings.WebInfo
		if len(x.HTTP) > 0 {
			var wi findings.WebInfo
			if json.Unmarshal(x.HTTP, &wi) == nil {
				web = &wi
			}
		}
		v := verdictOf(x)
		rk := findings.Rank(findings.ScoreInput{Service: s, HTTP: web, Sigs: sigs[x.Key], Verdict: v}, time.Now())
		s.Interest, s.Score, s.Reason = rk.Level, rk.Score, strings.Join(rk.Reasons, " · ")
		v.Apply(&s)
		out = append(out, s)
	}
	return out
}
