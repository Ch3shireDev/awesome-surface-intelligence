package nmap

import (
	"strings"
	"testing"
	"time"

	"asi/internal/safety"
)

func TestFitTimeout(t *testing.T) {
	full, _, err := ApplyPorts(DefaultServicesArgs, "auto", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args   string
		pps    int
		hosts  int
		raised bool
	}{
		{full, 1000, 4, false}, // new defaults
		{full, 300, 1, false},
		{full, 60, 1, true}, // 5 processes / 300 pps, still stored in old schedules
		{DefaultServicesArgs, 60, 17, false},
		{DefaultServicesArgs, 1000, 295, false},
	} {
		got, hosts, to := FitTimeout(c.args, c.pps)
		if hosts != c.hosts || (to > 0) != c.raised {
			t.Errorf("%d pps: hosts=%d timeout=%v (%s)", c.pps, hosts, to, got)
		}
		if c.raised {
			if need := 65535 * time.Second / time.Duration(c.pps); to <= need || strings.Contains(got, "10m") {
				t.Errorf("timeout %v does not cover %v: %s", to, need, got)
			}
			if _, err := safety.Default().Enforce(strings.Fields(got), safety.Opts{}); err != nil {
				t.Errorf("policy rejects fitted args: %v", err)
			}
		} else if got != c.args {
			t.Errorf("args changed without need: %s", got)
		}
	}
}
