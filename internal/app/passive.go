package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"asi/internal/passive"
	"asi/internal/store"
	"asi/internal/targets"
)

// POST /api/v1/passive {"domain","inventory","set","save"}: candidates from CT logs, DNS and
// (opt-in) a passive inventory. save adds only names not in the set yet, always enabled=false.
func (a *App) passiveSources(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Domain    string `json:"domain"`
		Set       string `json:"set"`
		Inventory bool   `json:"inventory"`
		Save      bool   `json:"save"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&in) != nil {
		fail(w, 400, "bad request")
		return
	}
	res, err := passive.New().Find(r.Context(), in.Domain, in.Inventory)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	set, written := setName(in.Set), 0
	if in.Save {
		have, err := a.St.Targets(r.Context(), set)
		if err != nil {
			fail(w, 500, err.Error())
			return
		}
		add := newCandidates(res.Records, have)
		if len(add) > 0 {
			if written, err = a.St.MergeTargets(r.Context(), set, add); err != nil {
				fail(w, 500, err.Error())
				return
			}
		}
	}
	a.St.Audit(r.Context(), &u.ID, "passive_sources", "domain", res.Domain,
		map[string]any{"names": len(res.Records), "inventory": in.Inventory, "written": written, "set": set})
	writeJSON(w, 200, map[string]any{"result": res, "written": written})
}

// newCandidates never touches an existing target and never enables scanning.
func newCandidates(rs []passive.Record, have []targets.Target) []targets.Target {
	known := map[string]bool{}
	for _, t := range have {
		known[strings.ToLower(t.Target)] = true
	}
	var out []targets.Target
	for _, r := range rs {
		if known[r.Name] {
			continue
		}
		note := "źródła pasywne: " + strings.Join(r.Sources, ", ")
		if len(r.Ports) > 0 {
			var ps []string
			for _, p := range r.Ports {
				ps = append(ps, strconv.Itoa(p))
			}
			note += "; porty wg inwentarza: " + strings.Join(ps, ",")
		}
		out = append(out, targets.Target{Target: r.Name, Tags: []string{"passive"}, Note: note, Enabled: false})
	}
	return out
}
