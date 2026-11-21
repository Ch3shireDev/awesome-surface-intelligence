package nuclei

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
	got := map[string]obs.SignatureData{}
	for _, o := range os {
		var d obs.SignatureData
		o.Decode(&d)
		got[o.AssetKey+" "+d.ID] = d
	}
	want := map[string]string{ // key -> expected extract or severity
		"192.0.2.13/tcp/6379 asi-redis-noauth":               "high",
		"192.0.2.10/tcp/80 asi-php-outdated":                 "7.4.33",
		"192.0.2.12/tcp/8080 asi-version-endpoint":           "2.3.1-rc1",
		"192.0.2.11/tcp/80 asi-html-generator":               "WordPress 6.4.2",
		"192.0.2.12/tcp/8080 asi-staging-environment:header": "staging",
		"192.0.2.12/tcp/8080 asi-admin-panel":                "Admin Panel - Login",
		"192.0.2.10/tcp/443 asi-session-cookies:php":         "PHPSESSID",
	}
	for k, v := range want {
		d, ok := got[k]
		if !ok {
			t.Errorf("missing %s (have %d hits)", k, len(got))
			continue
		}
		if d.Severity != v && !strings.Contains(strings.Join(d.Extract, ","), v) {
			t.Errorf("%s: want %q got sev=%s extract=%v", k, v, d.Severity, d.Extract)
		}
	}
}

func TestTargetsAndCommand(t *testing.T) {
	h := obs.New(obs.KindHTTP, "192.0.2.10/tcp/80", "httpx", obs.HTTPData{URL: "http://192.0.2.10"}, 90)
	tg := Targets([]obs.Observation{h}, []findings.Service{{IP: "192.0.2.13", Port: 6379, Proto: "tcp", Name: "redis"},
		{IP: "192.0.2.14", Port: 22, Proto: "tcp", Name: "ssh"}})
	if strings.Join(tg, " ") != "http://192.0.2.10 192.0.2.13:6379" {
		t.Fatalf("targets: %v", tg)
	}
	cmd, _ := (&Adapter{Templates: "/repo/signatures"}).Command(context.Background(),
		obs.Chunk{Dir: "/x", Name: "c", TargetsFile: "/x/t"}, obs.StageConfig{RatePPS: 500})
	a := strings.Join(cmd.Args, " ")
	for _, w := range []string{"-t /repo/signatures", "-ni", "-etags " + ExcludedTags, "-rl 50"} {
		if !strings.Contains(a, w) {
			t.Errorf("missing %q in %s", w, a)
		}
	}
}

// Every template in the repo must be detection-only: no POST bodies with credentials,
// no excluded tags, id prefixed asi-.
func TestTemplatesAreSafe(t *testing.T) {
	for _, dir := range []string{"../../../signatures/http", "../../../signatures/network"} {
		es, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			b, _ := os.ReadFile(dir + "/" + e.Name())
			s := strings.ToLower(string(b))
			if !strings.HasPrefix(s, "id: asi-") {
				t.Errorf("%s: id must start with asi-", e.Name())
			}
			for _, bad := range []string{"method: post", "method: put", "method: delete", "password=", "{{interactsh", "payloads:", "attack:"} {
				if strings.Contains(s, bad) {
					t.Errorf("%s: forbidden %q (signatures are detection-only)", e.Name(), bad)
				}
			}
			for _, tag := range strings.Split(ExcludedTags, ",") {
				if strings.Contains(s, "tags: ") && strings.Contains(strings.SplitN(strings.SplitN(s, "tags: ", 2)[1], "\n", 2)[0], tag) {
					t.Errorf("%s: excluded tag %s", e.Name(), tag)
				}
			}
		}
	}
}
