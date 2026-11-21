package dojo

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asi/internal/store"
)

type report struct {
	Findings []map[string]any `json:"findings"`
}

func parse(t *testing.T, b []byte) report {
	t.Helper()
	var r report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b)
	}
	return r
}

var t0 = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

func port(key, state string, cur string) store.Asset {
	parts := strings.Split(key, "/")
	p := 0
	for _, c := range parts[2] {
		p = p*10 + int(c-'0')
	}
	return store.Asset{Key: key, Kind: "port", IP: parts[0], Port: p, State: state,
		FirstSeen: t0, LastSeen: t0.Add(time.Hour), LastSeenRun: "run-2", Current: json.RawMessage(cur)}
}

func TestChangesConditions(t *testing.T) {
	assets := []store.Asset{
		port("192.0.2.10/tcp/22", "active", `{"name":"ssh","product":"OpenSSH","version":"9.6"}`),
		port("192.0.2.10/tcp/80", "missing", `{"name":"http"}`),
		port("192.0.2.11/tcp/443", "gone", `{"name":"https","product":"nginx"}`),
		{Key: "192.0.2.12", Kind: "host", IP: "192.0.2.12", State: "gone", FirstSeen: t0, LastSeen: t0, LastSeenRun: "run-1"},
	}
	flap := port("192.0.2.13/tcp/8080", "active", `{"name":"http-proxy"}`)
	flap.Flapping = true
	flap.UserTags = []string{"prod"}
	assets = append(assets, flap)

	events := []store.Event{
		{Key: "192.0.2.10/tcp/22", Type: "changed", RunID: "run-1", At: t0,
			Before: json.RawMessage(`{"name":"ssh","version":"8.9"}`), After: json.RawMessage(`{"name":"ssh","version":"9.4"}`)},
		{Key: "192.0.2.10/tcp/22", Type: "changed", RunID: "run-3", At: t0.Add(2 * time.Hour),
			Before: json.RawMessage(`{"name":"ssh","version":"9.4"}`), After: json.RawMessage(`{"name":"ssh","version":"9.6"}`)},
		// change of an asset that is gone now: covered by the "gone" finding, not repeated
		{Key: "192.0.2.11/tcp/443", Type: "changed", RunID: "run-1", At: t0,
			Before: json.RawMessage(`{"name":"https"}`), After: json.RawMessage(`{"name":"https","product":"nginx"}`)},
		{Key: "192.0.2.10/tcp/80", Type: "missing", RunID: "run-3", At: t0},
	}

	r := parse(t, ChangesJSON(assets, events))
	byUID := map[string]map[string]any{}
	for _, f := range r.Findings {
		byUID[f["unique_id_from_tool"].(string)] = f
		if _, bad := f["service"]; bad {
			t.Errorf("%s: 'service' must not be set (reimport would never close it)", f["title"])
		}
		for _, ep := range f["endpoints"].([]any) {
			if _, bad := ep.(map[string]any)["protocol"]; bad {
				t.Errorf("%s: endpoint protocol must not be set (DD limit 10 chars)", f["title"])
			}
		}
	}
	want := map[string]string{
		"asi-change:missing:192.0.2.10/tcp/80":       "Info",
		"asi-change:gone:192.0.2.11/tcp/443":         "Info",
		"asi-change:gone:192.0.2.12":                 "Info",
		"asi-change:flapping:192.0.2.13/tcp/8080":    "Low",
		"asi-change:changed:192.0.2.10/tcp/22@run-3": "Low",
	}
	if len(r.Findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %v", len(r.Findings), len(want), keys(byUID))
	}
	for uid, sev := range want {
		f, ok := byUID[uid]
		if !ok {
			t.Errorf("missing finding %s (have %v)", uid, keys(byUID))
			continue
		}
		if f["severity"] != sev {
			t.Errorf("%s severity = %v, want %s", uid, f["severity"], sev)
		}
	}

	ch := byUID["asi-change:changed:192.0.2.10/tcp/22@run-3"]["description"].(string)
	if !strings.Contains(ch, "`9.4`") || !strings.Contains(ch, "`9.6`") || strings.Contains(ch, "8.9") {
		t.Errorf("changed must show the LATEST change 9.4 -> 9.6:\n%s", ch)
	}
	if got := byUID["asi-change:gone:192.0.2.12"]["title"]; got != "Host 192.0.2.12: zniknął (potwierdzone)" {
		t.Errorf("host title = %q", got)
	}
	if got := byUID["asi-change:gone:192.0.2.11/tcp/443"]["title"]; got != "Usługa 192.0.2.11:443/tcp (https): zniknęła (potwierdzone)" {
		t.Errorf("service title = %q", got)
	}
	tags := byUID["asi-change:flapping:192.0.2.13/tcp/8080"]["tags"].([]any)
	if len(tags) == 0 || tags[len(tags)-1] != "prod" {
		t.Errorf("user tags from ASI should travel to DD, got %v", tags)
	}
}

// DefectDojo matches Generic findings on reimport by hash(title, description, ...).
// While a condition lasts, the finding text must not change - otherwise every run would
// close the old finding and open a new one.
func TestChangesStableWhileConditionLasts(t *testing.T) {
	a := port("192.0.2.20/tcp/3389", "missing", `{"name":"ms-wbt-server"}`)
	a.ConsecutiveMisses, a.SeenCount = 1, 5
	first := parse(t, ChangesJSON([]store.Asset{a}, nil)).Findings[0]
	a.ConsecutiveMisses, a.SeenCount, a.HoursSeen = 2, 5, 0xff
	second := parse(t, ChangesJSON([]store.Asset{a}, nil)).Findings[0]
	for _, k := range []string{"title", "description"} {
		if first[k] != second[k] {
			t.Errorf("%s changed between runs:\n%v\n---\n%v", k, first[k], second[k])
		}
	}
}

func TestChangesEmpty(t *testing.T) {
	r := parse(t, ChangesJSON([]store.Asset{port("192.0.2.30/tcp/22", "active", `{}`)}, nil))
	if len(r.Findings) != 0 {
		t.Fatalf("active asset without events must give no findings, got %v", r.Findings)
	}
	if !strings.Contains(string(ChangesJSON(nil, nil)), `"findings": []`) {
		t.Fatal("empty report must still be a valid Generic report with an empty list")
	}
}

func keys(m map[string]map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestChangesRevertedIsNotACurrentChange(t *testing.T) {
	a := port("192.0.2.40/tcp/8085", "active", `{"name":"http","product":"Apache httpd"}`)
	a.Flapping = true
	ev := []store.Event{
		{Key: a.Key, Type: "changed", RunID: "run-2", At: t0, Before: json.RawMessage(`{"product":"Apache httpd"}`), After: json.RawMessage(`{"product":"Traefik"}`)},
		{Key: a.Key, Type: "reverted", RunID: "run-3", At: t0.Add(time.Hour), Before: json.RawMessage(`{"product":"Traefik"}`), After: json.RawMessage(`{"product":"Apache httpd"}`)},
	}
	r := parse(t, ChangesJSON([]store.Asset{a}, ev))
	for _, f := range r.Findings {
		if strings.Contains(f["unique_id_from_tool"].(string), ":changed:") {
			t.Fatalf("a reverted change must not stay open as 'changed': %v", f["title"])
		}
	}
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0]["unique_id_from_tool"].(string), ":flapping:") {
		t.Fatalf("want only the flapping condition, got %v", r.Findings)
	}
}
