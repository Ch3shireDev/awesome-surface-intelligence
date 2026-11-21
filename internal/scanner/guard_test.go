package scanner

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"asi/internal/obs"
	"asi/internal/progress"
	"asi/internal/safety"
)

// fakeNmap reports itself as nmap but runs "echo" with the given extra args.
type fakeNmap struct{ extra []string }

func (f fakeNmap) Stage() obs.Stage { return obs.StageServices }
func (f fakeNmap) Tool() string     { return "nmap" }
func (f fakeNmap) Command(ctx context.Context, c obs.Chunk, cfg obs.StageConfig) (*exec.Cmd, obs.OutputSpec) {
	args := append([]string{"-sT"}, f.extra...)
	args = append(args, "--max-rate", "10", "-iL", c.TargetsFile)
	return exec.CommandContext(ctx, "echo", args...), obs.OutputSpec{}
}
func (f fakeNmap) Parse(io.Reader) ([]obs.Observation, error) { return nil, nil }

func runGuarded(t *testing.T, a obs.Scanner, ips []string) ChunkResult {
	t.Helper()
	dir := t.TempDir()
	tr := progress.New("t", 1, filepath.Join(dir, "events.ndjson"))
	rs := RunPhase(context.Background(), PhaseConfig{Name: "services", Adapter: a, Stage: obs.StageConfig{RatePPS: 10},
		Parallel: 1, Sizer: &Sizer{Fixed: 10}, OutDir: dir, Guard: safety.Default()}, ips, tr, nil)
	if len(rs) != 1 {
		t.Fatalf("chunks: %d", len(rs))
	}
	return rs[0]
}

func TestWorkerDropsExcludedIPs(t *testing.T) {
	r := runGuarded(t, fakeNmap{}, []string{"192.0.2.1", "169.254.169.254"})
	if r.State != "done" || strings.Join(r.Hosts, ",") != "192.0.2.1" {
		t.Fatalf("state %s hosts %v err %s", r.State, r.Hosts, r.Error)
	}
	r = runGuarded(t, fakeNmap{}, []string{"224.0.0.1"})
	if r.State != "failed" || !strings.HasPrefix(r.Error, "policy:") {
		t.Fatalf("all-blocked chunk: %s %s", r.State, r.Error)
	}
}

func TestWorkerRejectsSmuggledTarget(t *testing.T) {
	r := runGuarded(t, fakeNmap{extra: []string{"198.51.100.7"}}, []string{"192.0.2.1"})
	if r.State != "failed" || !strings.Contains(r.Error, "not a flag") {
		t.Fatalf("smuggled target: %s %s", r.State, r.Error)
	}
}
