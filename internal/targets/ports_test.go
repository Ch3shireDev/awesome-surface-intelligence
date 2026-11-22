package targets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePorts(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "auto": "", "default": "", " ALL ": "all", "lab": "all", "top100": "top100",
		"443,22;80": "22,80,443", "22, 23": "22,23", "8000-8100,8050,8101": "8000-8101", "80 80": "80",
	} {
		if got, err := NormalizePorts(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"0", "65536", "90-80", "22 -oX /tmp/x", "--script=vuln", "u:53", ",", "+22", "1-2-3"} {
		if got, err := NormalizePorts(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestMergePorts(t *testing.T) {
	for _, c := range []struct {
		a, b, want string
		lost       bool
	}{
		{"", "22", "22", false}, {"22", "", "22", false}, {"22,80", "443", "22,80,443", false},
		{"top100", "top1000", "top1000", false}, {"all", "22", "all", false}, {"22", "all", "all", false},
		{"top1000", "8787", "top1000", true}, {"8787", "top100", "top100", true},
	} {
		if got, lost := mergePorts(c.a, c.b); got != c.want || lost != c.lost {
			t.Errorf("%q+%q = %q,%v", c.a, c.b, got, lost)
		}
	}
}

func TestPlanPorts(t *testing.T) {
	for name, body := range map[string]string{
		"t.csv":  "target,ports,note\n192.0.2.0/30,443,\n192.0.2.1,22;80,\n192.0.2.9,,\n192.0.2.10,99999,\n",
		"t.json": `{"targets":[{"target":"192.0.2.0/30","ports":"443","enabled":true},{"target":"192.0.2.1","ports":"22,80","enabled":true},{"target":"192.0.2.9","enabled":true},{"target":"192.0.2.10","ports":"99999","enabled":true}]}`,
	} {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ts, err := Load(p)
		if err != nil {
			t.Fatal(err)
		}
		pl, got := BuildPlan(ts, PlanOptions{}), map[string]string{}
		for _, h := range pl.Hosts {
			got[h.IP] = h.Ports
		}
		if got["192.0.2.0"] != "443" || got["192.0.2.1"] != "22,80,443" || got["192.0.2.9"] != "" {
			t.Errorf("%s: %v", name, got)
		}
		if _, ok := got["192.0.2.10"]; ok || len(pl.Skipped) != 1 {
			t.Errorf("%s: invalid ports must skip the target: %+v", name, pl.Skipped)
		}
	}
}
