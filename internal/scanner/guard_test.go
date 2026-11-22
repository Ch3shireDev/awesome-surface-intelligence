package scanner

import (
	"context"
	"io"
	"net/netip"
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

// echoNmap prints its command line, so the test can read what nmap would get.
type echoNmap struct{ fakeNmap }

func (e echoNmap) Parse(r io.Reader) ([]obs.Observation, error) {
	b, _ := io.ReadAll(r)
	return []obs.Observation{{Kind: "cmd", AssetKey: string(b)}}, nil
}

func TestWorkerSelfChunkExcludesOwnPorts(t *testing.T) {
	dir := t.TempDir()
	tr := progress.New("t", 2, filepath.Join(dir, "events.ndjson"))
	pol := safety.Default()
	pol.Self = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	pol.SelfPorts, _ = safety.ParsePorts("8080,8090")
	rs := RunPhase(context.Background(), PhaseConfig{Name: "services", Adapter: echoNmap{}, Stage: obs.StageConfig{RatePPS: 10},
		Parallel: 2, Sizer: &Sizer{Fixed: 10}, OutDir: dir, Guard: pol}, []string{"192.0.2.1", "127.0.0.1", "192.0.2.2"}, tr, nil)
	if len(rs) != 2 {
		t.Fatalf("chunks: %d", len(rs))
	}
	for _, r := range rs {
		cmd := r.Observations[0].AssetKey
		self := strings.Join(r.Hosts, ",") == "127.0.0.1"
		if self != strings.Contains(cmd, "--exclude-ports 8080,8090") {
			t.Errorf("hosts %v: cmd %q", r.Hosts, cmd)
		}
	}
}

// fixedObsAdapter returns a fixed set of observations regardless of tool output,
// used to verify defense-in-depth post-parse filtering across nmap/httpx/nuclei.
type fixedObsAdapter struct {
	tool string
	obs  []obs.Observation
}

func (f fixedObsAdapter) Stage() obs.Stage { return obs.StageHTTP }
func (f fixedObsAdapter) Tool() string     { return f.tool }
func (f fixedObsAdapter) Command(ctx context.Context, c obs.Chunk, cfg obs.StageConfig) (*exec.Cmd, obs.OutputSpec) {
	return exec.CommandContext(ctx, "echo", "ok"), obs.OutputSpec{}
}
func (f fixedObsAdapter) Parse(io.Reader) ([]obs.Observation, error) { return f.obs, nil }

func TestWorkerFiltersSelfPortObservations(t *testing.T) {
	dir := t.TempDir()
	tr := progress.New("t", 1, filepath.Join(dir, "events.ndjson"))
	pol := safety.Default()
	pol.Self = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("198.51.100.5/32"), // local interface IP
	}
	pol.SelfPorts, _ = safety.ParsePorts("5433,8080,8090")

	in := []obs.Observation{
		obs.New(obs.KindHost, "127.0.0.1", "nmap", obs.HostData{Up: true}, 100, "up"),
		obs.New(obs.KindPort, "127.0.0.1/tcp/8080", "nmap", obs.PortData{State: "open"}, 100, "open"),
		obs.New(obs.KindService, "127.0.0.1/tcp/8080", "nmap", obs.ServiceData{Name: "http"}, 100, "http"),
		obs.New(obs.KindPort, "127.0.0.1/tcp/8787", "nmap", obs.PortData{State: "open"}, 100, "open"),
		obs.New(obs.KindHTTP, "198.51.100.5/tcp/8090", "httpx", obs.HTTPData{URL: "http://198.51.100.5:8090"}, 100, "8090"),
		obs.New(obs.KindHTTP, "198.51.100.5/tcp/8787", "httpx", obs.HTTPData{URL: "http://198.51.100.5:8787"}, 100, "8787"),
		obs.New(obs.KindPort, "192.0.2.10/tcp/8080", "nmap", obs.PortData{State: "open"}, 100, "open"),
		obs.New(obs.KindHTTP, "192.0.2.10/tcp/8090", "httpx", obs.HTTPData{URL: "http://192.0.2.10:8090"}, 100, "8090"),
	}
	rs := RunPhase(context.Background(), PhaseConfig{
		Name: "http", Adapter: fixedObsAdapter{tool: "httpx", obs: in},
		Parallel: 1, Sizer: &Sizer{Fixed: 10}, OutDir: dir, Guard: pol,
	}, []string{"http://127.0.0.1:8787", "http://192.0.2.10:8080"}, tr, nil)
	if len(rs) != 1 {
		t.Fatalf("chunks: %d", len(rs))
	}
	got := map[string]bool{}
	for _, o := range rs[0].Observations {
		got[string(o.Kind)+":"+o.AssetKey] = true
	}
	for _, mustDrop := range []string{
		"port:127.0.0.1/tcp/8080",
		"service:127.0.0.1/tcp/8080",
		"http:198.51.100.5/tcp/8090",
	} {
		if got[mustDrop] {
			t.Errorf("self-port observation was NOT filtered: %s", mustDrop)
		}
	}
	for _, mustKeep := range []string{
		"host:127.0.0.1",
		"port:127.0.0.1/tcp/8787",
		"http:198.51.100.5/tcp/8787",
		"port:192.0.2.10/tcp/8080",
		"http:192.0.2.10/tcp/8090",
	} {
		if !got[mustKeep] {
			t.Errorf("valid observation was wrongly dropped: %s", mustKeep)
		}
	}
}

func TestWorkerSelfExcludeOffAndUserExcludeMerge(t *testing.T) {
	// SelfPorts=nil (ASI_SELF_PORTS=off): no --exclude-ports on 127.0.0.1
	dir := t.TempDir()
	tr := progress.New("t", 1, filepath.Join(dir, "events.ndjson"))
	polOff := safety.Default()
	polOff.Self = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	polOff.SelfPorts = nil
	rs := RunPhase(context.Background(), PhaseConfig{Name: "services", Adapter: echoNmap{}, Stage: obs.StageConfig{RatePPS: 10},
		Parallel: 1, Sizer: &Sizer{Fixed: 10}, OutDir: dir, Guard: polOff}, []string{"127.0.0.1"}, tr, nil)
	if len(rs) != 1 || strings.Contains(rs[0].Observations[0].AssetKey, "--exclude-ports") {
		t.Fatalf("off mode should not add --exclude-ports: %+v", rs)
	}

	// User passes --exclude-ports 9100 on 127.0.0.1: worker merges into a single --exclude-ports flag
	pol := safety.Default()
	pol.Self = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	pol.SelfPorts, _ = safety.ParsePorts("8080,8090")
	rs = RunPhase(context.Background(), PhaseConfig{Name: "services",
		Adapter: echoNmap{fakeNmap{extra: []string{"--exclude-ports", "9100"}}}, Stage: obs.StageConfig{RatePPS: 10},
		Parallel: 1, Sizer: &Sizer{Fixed: 10}, OutDir: dir, Guard: pol}, []string{"127.0.0.1"}, tr, nil)
	if len(rs) != 1 || rs[0].State != "done" {
		t.Fatalf("merge run failed: %+v", rs)
	}
	cmd := rs[0].Observations[0].AssetKey
	if strings.Count(cmd, "--exclude-ports") != 1 || !strings.Contains(cmd, "--exclude-ports 8080,8090,9100") {
		t.Fatalf("expected single merged --exclude-ports, got: %q", cmd)
	}
}

type groupNmap struct {
	echoNmap
}

func TestPhaseKeepsPortGroupsApart(t *testing.T) {
	dir := t.TempDir()
	tr := progress.New("t", 3, filepath.Join(dir, "events.ndjson"))
	pol := safety.Default()
	pol.Self = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	pol.SelfPorts, _ = safety.ParsePorts("18090")
	ports := map[string]string{"127.0.0.1": "22", "192.0.2.1": "22", "192.0.2.3": "443"} // the rest: default
	in := []string{"192.0.2.1", "127.0.0.2", "192.0.2.2", "127.0.0.1", "192.0.2.3", "192.0.2.4"}
	rs := RunPhase(context.Background(), PhaseConfig{Name: "services", Adapter: echoNmap{}, Stage: obs.StageConfig{RatePPS: 10},
		Parallel: 3, Sizer: &Sizer{Fixed: 10}, OutDir: dir, Guard: pol,
		Group: func(ip string) string { return ports[ip] },
		AdapterFor: func(g string) obs.Scanner {
			if g == "" {
				return echoNmap{}
			}
			return groupNmap{echoNmap{fakeNmap{extra: []string{"-p", g}}}}
		}}, in, tr, nil)
	seen := 0
	for _, r := range rs {
		cmd := r.Observations[0].AssetKey
		for _, ip := range r.Hosts {
			seen++
			if p := ports[ip]; (p == "" && strings.Contains(cmd, "-p ")) || (p != "" && !strings.Contains(cmd, "-p "+p)) {
				t.Errorf("%s: wrong ports in %q", ip, cmd)
			}
			if strings.HasPrefix(ip, "127.") != strings.Contains(cmd, "--exclude-ports") {
				t.Errorf("%s: wrong self-port exclusion in %q", ip, cmd)
			}
		}
	}
	if seen != len(in) || len(rs) != 5 {
		t.Fatalf("hosts %d/%d, chunks %d", seen, len(in), len(rs))
	}
}
