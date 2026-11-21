package dojo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"asi/internal/store"
)

// ChangesTestTitle is the stable DefectDojo test that holds ASI change conditions.
const ChangesTestTitle = "asi-changes"

// ChangesJSON builds the "asi-changes" report (Generic Findings Import) from the
// asset states and events kept by reconcile (VISION 4.7). It is STATE based: a
// finding stays in the report while its condition lasts, so a reimport with
// close_old_findings closes it in DefectDojo exactly when the condition ends.
//
//	missing   asset stopped answering, below the "gone" threshold  -> Info  (until back / gone)
//	gone      disappearance confirmed by N consecutive misses     -> Info  (until it reappears)
//	flapping  asset keeps disappearing and coming back            -> Low   (until it settles)
//	changed   the LATEST change of a live asset (e.g. new version) -> Low  (until the next change)
//
// DefectDojo matches Generic findings by hash of title+description (+cwe, line,
// file_path), so descriptions contain only values that are stable while the
// condition lasts (no miss counters, no "now"). `service` is never set: the
// reimporter only closes findings whose service matches the report's.
func ChangesJSON(assets []store.Asset, events []store.Event) []byte {
	byKey := make(map[string]store.Asset, len(assets))
	for _, a := range assets {
		byKey[a.Key] = a
	}
	out := struct {
		Findings []changeFinding `json:"findings"`
	}{Findings: []changeFinding{}}

	for _, a := range assets {
		switch a.State {
		case "missing":
			out.Findings = append(out.Findings, stateFinding(a, "missing", "Info"))
		case "gone":
			out.Findings = append(out.Findings, stateFinding(a, "gone", "Info"))
		}
		if a.Flapping {
			out.Findings = append(out.Findings, stateFinding(a, "flapping", "Low"))
		}
	}

	// latest "changed" event per asset, only while the asset is live and only if the change
	// was not reverted afterwards (LAB-T8: a backend outage behind a proxy flips the fingerprint
	// and flips it back - the asset is then flagged as flapping, not as changed)
	latest := map[string]store.Event{}
	for _, e := range events {
		if e.Type != "changed" && e.Type != "reverted" {
			continue
		}
		if cur, ok := latest[e.Key]; !ok || e.At.After(cur.At) || (e.At.Equal(cur.At) && e.Type == "reverted") {
			latest[e.Key] = e
		}
	}
	for k, e := range latest {
		if e.Type == "reverted" {
			delete(latest, k)
		}
	}
	keys := make([]string, 0, len(latest))
	for k := range latest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a, ok := byKey[k]
		if !ok || a.State == "missing" || a.State == "gone" {
			continue
		}
		out.Findings = append(out.Findings, changedFinding(a, latest[k]))
	}

	b, _ := json.MarshalIndent(out, "", "  ")
	return b
}

type changeFinding struct {
	Title          string           `json:"title"`
	Description    string           `json:"description"`
	Severity       string           `json:"severity"`
	UniqueID       string           `json:"unique_id_from_tool"`
	Endpoints      []changeEndpoint `json:"endpoints"`
	Tags           []string         `json:"tags"`
	Active         bool             `json:"active"`
	DynamicFinding bool             `json:"dynamic_finding"`
	Date           string           `json:"date,omitempty"`
}

// no "protocol": DD limits it to 10 chars and nmap service names are longer.
type changeEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
}

func subject(a store.Asset) (noun, where string) {
	if a.Kind == "host" || a.Port == 0 {
		return "Host", fmt.Sprintf("Host `%s`", a.IP)
	}
	proto := "tcp"
	if parts := strings.Split(a.Key, "/"); len(parts) == 3 {
		proto = parts[1]
	}
	return "Usługa", fmt.Sprintf("Usługa `%d/%s` na `%s`", a.Port, proto, a.IP)
}

func label(a store.Asset) string {
	noun, _ := subject(a)
	l := noun + " " + a.IP
	if a.Port != 0 {
		l = fmt.Sprintf("%s %s:%d", noun, a.IP, a.Port)
		if parts := strings.Split(a.Key, "/"); len(parts) == 3 {
			l += "/" + parts[1]
		}
		if n := serviceName(a.Current); n != "" {
			l += " (" + n + ")"
		}
	}
	return l
}

// texts per condition; [0] host (masculine), [1] service (feminine) - Polish grammar.
var stateTexts = map[string][2][2]string{ // kind -> {host, service} -> {title, description}
	"missing": {
		{"nie odpowiada (do potwierdzenia)", "przestał odpowiadać. Zniknięcie nie jest jeszcze potwierdzone: ASI czeka na kolejne braki (próg) i skan potwierdzający."},
		{"nie odpowiada (do potwierdzenia)", "przestała odpowiadać. Zniknięcie nie jest jeszcze potwierdzone: ASI czeka na kolejne braki (próg) i skan potwierdzający."},
	},
	"gone": {
		{"zniknął (potwierdzone)", "nie odpowiada w kolejnych przebiegach powyżej progu braków, więc ASI uznało go za zniknięty. Finding zamknie się sam, gdy host wróci."},
		{"zniknęła (potwierdzone)", "nie odpowiada w kolejnych przebiegach powyżej progu braków, więc ASI uznało ją za zniknętą. Finding zamknie się sam, gdy usługa wróci."},
	},
	"flapping": {
		{"niestabilny (flapping)", "wielokrotnie znikał i wracał w ostatnich przebiegach: może działać tylko w części doby albo być niestabilny. Wynik pojedynczego skanu jest dla niego niepewny."},
		{"niestabilna (flapping)", "wielokrotnie znikała i wracała w ostatnich przebiegach: może działać tylko w części doby albo być niestabilna. Wynik pojedynczego skanu jest dla niej niepewny."},
	},
}

func stateFinding(a store.Asset, kind, sev string) changeFinding {
	_, where := subject(a)
	g := 1
	if a.Kind == "host" || a.Port == 0 {
		g = 0
	}
	txt := stateTexts[kind][g]
	var d strings.Builder
	fmt.Fprintf(&d, "%s %s\n\n", where, txt[1])
	d.WriteString("| pole | wartość |\n|---|---|\n")
	fmt.Fprintf(&d, "| asset | `%s` |\n", a.Key)
	fmt.Fprintf(&d, "| pierwszy raz widziany | %s |\n", utc(a.FirstSeen))
	if kind != "flapping" {
		fmt.Fprintf(&d, "| ostatnio widziany | %s (przebieg `%s`) |\n", utc(a.LastSeen), a.LastSeenRun)
	}
	stateRows(&d, a.Current, "ostatni znany stan")
	return changeFinding{
		Title:       label(a) + ": " + txt[0],
		Description: d.String(),
		Severity:    sev,
		UniqueID:    "asi-change:" + kind + ":" + a.Key,
		Endpoints:   endpoints(a),
		Tags:        tags(a, kind),
		Active:      true, DynamicFinding: true,
	}
}

func changedFinding(a store.Asset, e store.Event) changeFinding {
	noun, where := subject(a)
	verb := "zmieniła się"
	if noun == "Host" {
		verb = "zmienił się"
	}
	var d strings.Builder
	fmt.Fprintf(&d, "%s %s w przebiegu `%s` (%s).\n\n", where, verb, e.RunID, utc(e.At))
	before, after := fields(e.Before), fields(e.After)
	names := map[string]bool{}
	for k := range before {
		names[k] = true
	}
	for k := range after {
		names[k] = true
	}
	ks := make([]string, 0, len(names))
	for k := range names {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	d.WriteString("| pole | przed | po |\n|---|---|---|\n")
	for _, k := range ks {
		mark := ""
		if before[k] != after[k] {
			mark = " **≠**"
		}
		fmt.Fprintf(&d, "| %s%s | %s | %s |\n", k, mark, cell(before[k]), cell(after[k]))
	}
	return changeFinding{
		Title:       label(a) + ": zmiana",
		Description: d.String(),
		Severity:    "Low",
		UniqueID:    "asi-change:changed:" + a.Key + "@" + e.RunID,
		Endpoints:   endpoints(a),
		Tags:        tags(a, "changed"),
		Active:      true, DynamicFinding: true,
		Date: e.At.UTC().Format("2006-01-02"),
	}
}

func endpoints(a store.Asset) []changeEndpoint {
	return []changeEndpoint{{Host: a.IP, Port: a.Port}}
}

func tags(a store.Asset, kind string) []string {
	t := []string{"asi", "asi-change", "change-" + kind}
	return append(t, a.UserTags...) // edits made in ASI travel to DefectDojo
}

func fields(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		out["value"] = string(raw)
		return out
	}
	for k, v := range m {
		if k == "method" { // nmap detection method, not a property of the service
			continue
		}
		out[k] = fmt.Sprint(v)
	}
	return out
}

func stateRows(d *strings.Builder, raw json.RawMessage, title string) {
	f := fields(raw)
	ks := make([]string, 0, len(f))
	for k := range f {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		fmt.Fprintf(d, "| %s: %s | %s |\n", title, k, cell(f[k]))
	}
}

func serviceName(raw json.RawMessage) string {
	var v struct {
		Name string `json:"name"`
	}
	json.Unmarshal(raw, &v)
	return v.Name
}

func cell(s string) string {
	if s == "" {
		return "–"
	}
	return "`" + strings.ReplaceAll(s, "|", "\\|") + "`"
}

func utc(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
