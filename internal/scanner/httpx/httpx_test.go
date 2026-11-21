package httpx

import (
	"context"
	"os"
	"strings"
	"testing"

	"asi/internal/findings"
	"asi/internal/obs"
)

func TestParseLab(t *testing.T) {
	f, err := os.Open("testdata/lab.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os, err := (&Adapter{}).Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]HTTPData{}
	for _, o := range os {
		if o.Kind != obs.KindHTTP {
			t.Fatalf("kind %s", o.Kind)
		}
		var d HTTPData
		o.Decode(&d)
		by[o.AssetKey] = d
	}
	if len(by) != 4 { // 4 lab URLs, truncated line dropped
		t.Fatalf("want 4 observations, got %d: %v", len(by), by)
	}
	wp := by["192.0.2.11/tcp/80"]
	if !contains(wp.Tech, "WordPress:6.4.2") {
		t.Errorf("wordpress tech: %v", wp.Tech)
	}
	prod := by["192.0.2.10/tcp/443"]
	if prod.TLSSubject == "" || !prod.TLSSelfSigned || !contains(prod.Cookies, "PHPSESSID") {
		t.Errorf("web-prod TLS/cookies: %+v", prod)
	}
	if v := prod.Headers["x-powered-by"]; len(v) == 0 || !strings.Contains(v[0], "PHP/7.4") {
		t.Errorf("x-powered-by: %v", prod.Headers)
	}
	st := by["192.0.2.12/tcp/8080"]
	if !strings.Contains(st.Title, "STAGING") || len(st.Headers["x-environment"]) == 0 {
		t.Errorf("staging: %+v", st)
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func TestCookieNames(t *testing.T) {
	got := cookieNames([]string{"PHPSESSID=abc; Path=/; HttpOnly, wordpress_test_cookie=WP%20Cookie; path=/", "staging_session=1; Secure"})
	if strings.Join(got, ",") != "PHPSESSID,staging_session,wordpress_test_cookie" {
		t.Fatalf("cookies: %v", got)
	}
}

func TestURLs(t *testing.T) {
	u := URLs([]findings.Service{
		{IP: "192.0.2.10", Port: 80, Proto: "tcp", Name: "http"},
		{IP: "192.0.2.10", Port: 443, Proto: "tcp", Name: "http", TLS: true},
		{IP: "192.0.2.12", Port: 8888, Proto: "tcp", Name: "sun-answerbook"},
		{IP: "192.0.2.13", Port: 6379, Proto: "tcp", Name: "redis"},
		{IP: "192.0.2.14", Port: 22, Proto: "tcp", Name: "ssh"},
	})
	if strings.Join(u, " ") != "http://192.0.2.10 https://192.0.2.10 http://192.0.2.12:8888" {
		t.Fatalf("urls: %v", u)
	}
}

func TestCommand(t *testing.T) {
	cmd, spec := (&Adapter{}).Command(context.Background(), obs.Chunk{Dir: "/x", Name: "chunk_0001", TargetsFile: "/x/t", Targets: []string{"a", "b"}},
		obs.StageConfig{RatePPS: 40})
	a := strings.Join(cmd.Args, " ")
	for _, w := range []string{"-l /x/t", "-o /x/chunk_0001.jsonl", "-rl 40", "-t 2", "-nfs", "-rt", "-maxr 0"} {
		if !strings.Contains(a, w) {
			t.Errorf("missing %q in %s", w, a)
		}
	}
	if strings.Contains(a, " -fr") || spec.Format != "jsonl" {
		t.Errorf("must not follow redirects: %s", a)
	}
}

func TestResponseTimeOutsideFP(t *testing.T) {
	mk := func(tm string) obs.Observation {
		raw := `{"port":"8085","url":"http://192.0.2.20:8085","input":"http://192.0.2.20:8085","title":"Shop","scheme":"http","webserver":"nginx","host":"192.0.2.20","host_ip":"192.0.2.20","status_code":200,"time":"` + tm + `","failed":false}`
		os, err := (&Adapter{}).Parse(strings.NewReader(raw + "\n"))
		if err != nil || len(os) != 1 {
			t.Fatalf("parse %s: len=%d err=%v", tm, len(os), err)
		}
		return os[0]
	}
	cases := []struct {
		raw  string
		want int
	}{
		{"400µs", 1},
		{"18.4ms", 18},
		{"650.2ms", 650},
		{"1.25s", 1250},
	}
	var firstFP string
	for _, tc := range cases {
		o := mk(tc.raw)
		var d HTTPData
		if err := o.Decode(&d); err != nil {
			t.Fatal(err)
		}
		if d.ResponseTimeMs != tc.want {
			t.Errorf("time %q: got %d ms, want %d", tc.raw, d.ResponseTimeMs, tc.want)
		}
		if firstFP == "" {
			firstFP = o.FPHash
		} else if o.FPHash != firstFP {
			t.Fatalf("latency change (%s) altered FPHash: %s != %s", tc.raw, o.FPHash, firstFP)
		}
	}
}

func TestURLsLabPorts(t *testing.T) {
	u := URLs([]findings.Service{
		{IP: "127.0.0.1", Port: 8787, Proto: "tcp", Name: "unknown"},
		{IP: "127.0.0.1", Port: 8474, Proto: "tcp", Name: "unknown"},
		{IP: "127.0.0.1", Port: 15673, Proto: "tcp", Name: "unknown"},
		{IP: "127.0.0.1", Port: 15432, Proto: "tcp", Name: "postgresql"},
	})
	want := "http://127.0.0.1:8787 http://127.0.0.1:8474 http://127.0.0.1:15673"
	if strings.Join(u, " ") != want {
		t.Fatalf("lab urls: got %q, want %q", strings.Join(u, " "), want)
	}
}
