package targetsai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asi/internal/targets"
)

// Inventory-like text with RFC 5737 / example.* data only.
const sample = `Serwery (doc/infra/fleet.md):
 Host  │ Publiczny IP  │ Tailscale IP   │ Zadania
 edge  │ 192.0.2.10    │ 100.101.1.2    │ proxy api.example.com
 db    │ 198.51.100.7  │ —              │ Postgres
Domeny: example.com (api., www.), shop.example.org
Siec wewnetrzna: 10.50.0.0/24, cv.
   example.net
`

func byTarget(ts []targets.Target) map[string]targets.Target {
	m := map[string]targets.Target{}
	for _, t := range ts {
		m[t.Target] = t
	}
	return m
}

func TestRegex(t *testing.T) {
	r := Regex(sample)
	m := byTarget(r.Targets)
	for _, want := range []string{"192.0.2.10", "198.51.100.7", "100.101.1.2", "10.50.0.0/24", "api.example.com", "example.com", "shop.example.org"} {
		if _, ok := m[want]; !ok {
			t.Errorf("missing %s in %v", want, r.Targets)
		}
	}
	if _, ok := m["fleet.md"]; ok {
		t.Error("file name taken as a domain")
	}
	if m["100.101.1.2"].Enabled || m["10.50.0.0/24"].Enabled {
		t.Error("internal addresses must be disabled")
	}
	if !m["192.0.2.10"].Enabled {
		t.Error("public address should stay enabled")
	}
}

func TestNormalizeRejectsInvented(t *testing.T) {
	in := []targets.Target{
		{Target: "203.0.113.99", Enabled: true}, // not in text
		{Target: "https://www.example.com/login", Enabled: true},
		{Target: "cv.example.net", Enabled: true}, // broken by a line wrap
		{Target: "evil.example.com", Enabled: true},
		{Target: "not a host", Enabled: true},
		{Target: "192.0.2.10", Tags: []string{"Hetzner"}, Enabled: true},
		{Target: "192.0.2.10", Tags: []string{"edge"}, Enabled: true},
	}
	out, warns := Normalize(in, sample)
	m := byTarget(out)
	if _, ok := m["203.0.113.99"]; ok {
		t.Error("invented IP kept")
	}
	if _, ok := m["evil.example.com"]; ok {
		t.Error("invented subdomain kept")
	}
	if _, ok := m["www.example.com"]; !ok {
		t.Error("abbreviated subdomain www. should be accepted")
	}
	if _, ok := m["cv.example.net"]; !ok {
		t.Error("line-wrapped domain should be accepted")
	}
	if got := m["192.0.2.10"].Tags; len(got) != 2 || got[0] != "hetzner" {
		t.Errorf("duplicates not merged: %v", got)
	}
	if len(warns) != 2 {
		t.Errorf("want 2 warnings (invented, invalid), got %v", warns)
	}
}

func TestLLM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" || r.Header.Get("Authorization") != "Bearer k" {
			http.Error(w, "bad", 400)
			return
		}
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		if req["model"] != "deepseek-flash" {
			http.Error(w, "model", 400)
			return
		}
		content := `{"targets":[
		 {"target":"192.0.2.10","asset":"edge","tags":["hetzner","publiczny"],"enabled":true,"note":"proxy"},
		 {"target":"100.101.1.2","asset":"edge","tags":["tailscale"],"enabled":true,"note":""},
		 {"target":"api.example.com","asset":"edge","tags":["domena"],"enabled":true,"note":"API"},
		 {"target":"203.0.113.5","asset":"ghost","enabled":true}]}`
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"content": content}, "finish_reason": "stop"}}})
	}))
	defer srv.Close()
	c := Config{BaseURL: srv.URL, APIKey: "k", Model: "deepseek-flash"}
	r, err := Extract(context.Background(), c, sample, "auto")
	if err != nil {
		t.Fatal(err)
	}
	m := byTarget(r.Targets)
	if r.Engine != "deepseek-flash" || m["192.0.2.10"].Asset != "edge" {
		t.Fatalf("unexpected result %+v", r)
	}
	if m["100.101.1.2"].Enabled {
		t.Error("tailscale address enabled by the model must be forced off")
	}
	if _, ok := m["203.0.113.5"]; ok {
		t.Error("hallucinated target kept")
	}
	if x, ok := m["198.51.100.7"]; !ok || x.Enabled {
		t.Error("target missed by the model should be added from regex, disabled")
	}
	if !strings.Contains(CSV(r.Targets), "target,asset,owner,tags,enabled,note\n") {
		t.Error("csv header")
	}
}

func TestAutoFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) }))
	defer srv.Close()
	r, err := Extract(context.Background(), Config{BaseURL: srv.URL, APIKey: "k", Model: "m"}, sample, "auto")
	if err != nil || r.Engine != "regex" || len(r.Warnings) == 0 {
		t.Fatalf("want regex fallback with warning, got %+v %v", r, err)
	}
	if _, err := Extract(context.Background(), Config{}, sample, "llm"); err == nil {
		t.Error("llm without key must fail")
	}
}
