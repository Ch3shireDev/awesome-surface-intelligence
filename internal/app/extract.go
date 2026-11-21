package app

import (
	"encoding/json"
	"io"
	"net/http"

	"asi/internal/store"
	"asi/internal/targetsai"
)

// POST /api/v1/targets/extract {"text": "...", "engine": "auto|llm|regex"}
// Proposes targets from free text (LLM or regex). Saves nothing: the GUI shows the
// proposal for review and then sends the accepted rows to POST /api/v1/targets.
func (a *App) extractTargets(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct{ Text, Engine string }
	if json.NewDecoder(io.LimitReader(r.Body, targetsai.MaxInput*2)).Decode(&in) != nil {
		fail(w, 400, "bad request")
		return
	}
	res, err := targetsai.Extract(r.Context(), targetsai.FromEnv(), in.Text, in.Engine)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	// audit without the text itself (it can hold real addresses and names)
	a.St.Audit(r.Context(), &u.ID, "targets_extract", "engine", res.Engine, map[string]any{"bytes": len(in.Text), "found": len(res.Targets)})
	writeJSON(w, 200, map[string]any{"engine": res.Engine, "warnings": res.Warnings, "targets": res.Targets, "csv": targetsai.CSV(res.Targets)})
}
