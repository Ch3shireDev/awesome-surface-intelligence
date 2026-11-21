package scanner

import (
	"strings"
	"testing"

	"asi/internal/obs"
)

func TestDropTimedOut(t *testing.T) {
	r := ChunkResult{Hosts: []string{"192.0.2.10", "192.0.2.11"}, State: "done",
		Observations: []obs.Observation{{AssetKey: "192.0.2.10"}, {AssetKey: "192.0.2.11/tcp/22"}}}
	dropTimedOut(&r, []string{"192.0.2.10"})
	if len(r.Hosts) != 1 || r.Hosts[0] != "192.0.2.11" {
		t.Fatalf("timed-out host must leave coverage: %v", r.Hosts)
	}
	if len(r.Observations) != 1 || r.Observations[0].AssetKey != "192.0.2.11/tcp/22" {
		t.Fatalf("observations of the timed-out host must go: %v", r.Observations)
	}
	if r.State != "done" || !strings.Contains(r.Error, "host timeout") || len(r.TimedOut) != 1 {
		t.Fatalf("partly timed-out chunk: state=%s error=%q timedOut=%v", r.State, r.Error, r.TimedOut)
	}
	// still listed as not covered -> pending / resume
	if u := Unscanned([]string{"192.0.2.10", "192.0.2.11"}, []ChunkResult{r}); len(u) != 1 || u[0] != "192.0.2.10" {
		t.Fatalf("Unscanned = %v, want the timed-out host", u)
	}

	all := ChunkResult{Hosts: []string{"192.0.2.12"}, State: "done"}
	dropTimedOut(&all, []string{"192.0.2.12"})
	if all.State != "failed" || len(all.Hosts) != 0 {
		t.Fatalf("chunk with only timed-out hosts must fail: %+v", all)
	}
}
