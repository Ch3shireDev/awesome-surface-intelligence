package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckScopeAndExclusions(t *testing.T) {
	p := Default()
	p.Scope, _ = parsePrefixes([]string{"192.0.2.0/24", "127.0.0.1"})
	ex, _ := parsePrefixes([]string{"192.0.2.13"})
	p.Exclude = append(ex, p.Exclude...)
	cases := map[string]bool{
		"192.0.2.10":      true,
		"127.0.0.1":       true,
		"192.0.2.13":      false, // user exclusion beats scope
		"198.51.100.1":    false, // outside scope
		"169.254.169.254": false, // cloud metadata, builtin
		"224.0.0.1":       false, // multicast
		"255.255.255.255": false,
		"not-an-ip":       false,
	}
	for ip, want := range cases {
		if ok, why := p.Check(ip); ok != want {
			t.Errorf("%s: ok=%v (%s), want %v", ip, ok, why, want)
		}
	}
	allowed, blocked := p.Filter([]string{"192.0.2.1", "192.0.2.13", "203.0.113.5"})
	if len(allowed) != 1 || len(blocked) != 2 {
		t.Fatalf("filter: %v %v", allowed, blocked)
	}
}

func TestFromEnvFilesAndLimits(t *testing.T) {
	dir := t.TempDir()
	ex := filepath.Join(dir, "exclude.txt")
	os.WriteFile(ex, []byte("# printers\n192.0.2.50\n198.51.100.0/28 # dmz\n"), 0o600)
	t.Setenv("ASI_EXCLUDE_FILE", ex)
	t.Setenv("ASI_SCOPE_FILE", filepath.Join(dir, "missing.txt"))
	t.Setenv("ASI_EXCLUDE", "203.0.113.7")
	t.Setenv("ASI_MAX_RATE", "500")
	t.Setenv("ASI_ALLOWED_PORTS", "1-1024,8000-8999")
	p, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.0.2.50", "198.51.100.3", "203.0.113.7"} {
		if ok, _ := p.Check(ip); ok {
			t.Errorf("%s should be excluded", ip)
		}
	}
	if ok, _ := p.Check("198.51.100.20"); !ok {
		t.Errorf("198.51.100.20 should be allowed")
	}
	rate, par, notes := p.Limits(5000, 10)
	if rate != 500 || par != 10 || len(notes) != 1 {
		t.Fatalf("limits: %d %d %v", rate, par, notes)
	}
	if _, par, _ = p.Limits(3, 10); par != 3 {
		t.Fatalf("parallel must not exceed rate: %d", par)
	}
	t.Setenv("ASI_SCAN_PROFILE", "root")
	if _, err := FromEnv(); err == nil {
		t.Fatal("bad profile accepted")
	}
}

func TestPorts(t *testing.T) {
	a, _ := ParsePorts("8000-8100,22,80,79-81")
	if a.String() != "22,79-81,8000-8100" {
		t.Fatalf("normalize: %s", a)
	}
	allow, _ := ParsePorts("1-1024")
	if got := a.Intersect(allow).String(); got != "22,79-81" {
		t.Fatalf("intersect: %s", got)
	}
	if _, err := ParsePorts("0,70000"); err == nil {
		t.Fatal("bad ports accepted")
	}
}

const (
	defDiscovery = "-sn -n -PS21,22,25,80,443,3389,8080,8443 -T4 --max-retries 1"
	defServices  = "-sT -sV --version-light -Pn --top-ports 1000 -T4 --max-retries 2 --host-timeout 10m --open"
)

func enforce(t *testing.T, p *Policy, args string) (string, error) {
	t.Helper()
	out, err := p.Enforce(strings.Fields(args), Opts{})
	return strings.Join(out, " "), err
}

func TestEnforceDefaultsPass(t *testing.T) {
	p := Default()
	for _, a := range []string{defDiscovery, defServices,
		"-sT -sV --version-light -Pn -p 22,23,80,443,6379,8000,8080 -T4 --max-retries 2 --open"} {
		got, err := enforce(t, p, a)
		if err != nil {
			t.Fatalf("%q: %v", a, err)
		}
		if got != a && !strings.Contains(a, "-p ") {
			t.Errorf("default args changed:\n %s\n %s", a, got)
		}
	}
}

// LAB-2: drugi przebieg identyfikacji (--version-all) musi przechodzić allowlistę -
// nmap z --version-light nie probkuje nieznanych portów (PostgreSQL na 15432 zostawał bez usługi).
func TestEnforceVersionAll(t *testing.T) {
	p := Default()
	a := "-sT -sV --version-all -Pn -T3 --max-retries 2 --host-timeout 2m --max-rate 50 -p 15432,8888"
	if _, err := p.Enforce(strings.Fields(a), Opts{}); err != nil {
		t.Fatalf("--version-all odrzucone: %v", err)
	}
	// to nadal detekcja, nie exploitacja: skrypty NSE poza allowlistą zostają zablokowane
	if _, err := p.Enforce(strings.Fields("-sV --version-all --script vuln"), Opts{}); err == nil {
		t.Fatal("--script vuln przepuszczony")
	}
}

func TestEnforceRejects(t *testing.T) {
	p := Default()
	for _, a := range []string{
		"-sT 8.8.8.8",            // smuggled target
		"-sT -iR 100",            // random targets
		"-sT -iL /etc/hosts",     // extra target list in profile args
		"-sT --min-rate 100000",  // bypass rate limit
		"-T5 -sT",                // insane timing
		"-sT -D 192.0.2.1",       // decoys
		"-sT --script vuln",      // intrusive NSE
		"-sT --script discovery", // category with brute forcers
		"-sT --script=http-title,ftp-brute",
		"-sT --script-args newtargets",
		"-sV --allports", // printers
		"-sT -oN /tmp/x", // file write
		"-sU -p 53",      // UDP disabled by default
		"-sT --unknown-flag",
	} {
		if got, err := enforce(t, p, a); err == nil {
			t.Errorf("%q accepted: %s", a, got)
		}
	}
}

func TestEnforcePortsAllowList(t *testing.T) {
	p := Default()
	p.Ports, _ = ParsePorts("1-1024,8080")
	got, err := enforce(t, p, "-sT -p 22,80,3389,8000-8100 --open")
	if err != nil || !strings.HasSuffix(got, "-p 22,80,8080") {
		t.Fatalf("cut -p: %q %v", got, err)
	}
	got, _ = enforce(t, p, "-sT -p22,3389")
	if !strings.HasSuffix(got, "-p 22") {
		t.Fatalf("attached -p: %q", got)
	}
	if _, err = enforce(t, p, "-sT -p 3389"); err == nil {
		t.Fatal("-p fully outside the allow-list accepted")
	}
	// no -p: the allow-list is added and nmap's default top-1000 is kept
	got, _ = enforce(t, p, "-sT -sV")
	if got != "-sT -sV --top-ports 1000 -p 1-1024,8080" {
		t.Fatalf("inject: %q", got)
	}
	got, _ = enforce(t, p, "-sT -F")
	if got != "-sT --top-ports 100 -p 1-1024,8080" {
		t.Fatalf("-F: %q", got)
	}
	// ping probes cut too, discovery gets no -p
	got, _ = enforce(t, p, defDiscovery)
	if got != "-sn -n -PS21-22,25,80,443,8080 -T4 --max-retries 1" {
		t.Fatalf("discovery: %q", got)
	}
}

func TestEnforceProfilesAndUDP(t *testing.T) {
	p := Default()
	p.Profile = ProfileUnprivileged
	if _, err := enforce(t, p, "-sS -Pn"); err == nil {
		t.Fatal("-sS accepted in unprivileged profile")
	}
	if _, err := enforce(t, p, "-sn -PE"); err == nil {
		t.Fatal("ICMP ping accepted in unprivileged profile")
	}
	got, _ := enforce(t, p, defServices)
	if !strings.HasSuffix(got, "--unprivileged") {
		t.Fatalf("unprivileged flag missing: %q", got)
	}

	p = Default()
	p.AllowUDP = true
	got, err := enforce(t, p, "-sS -sU -p T:22,80,U:53,123,161,500")
	if err != nil || !strings.HasSuffix(got, "-p T:22,80,U:53,123,161") {
		t.Fatalf("udp cut: %q %v", got, err)
	}
	got, _ = enforce(t, p, "-sU -p 53,80")
	if !strings.HasSuffix(got, "-p T:53,80,U:53") {
		t.Fatalf("unprefixed ports with -sU: %q", got)
	}
	got, _ = enforce(t, p, "-sU -sV --version-light")
	if !strings.HasSuffix(got, "--top-ports 1000 -p T:1-65535,U:53,123,161") {
		t.Fatalf("udp inject: %q", got)
	}
}

func TestEnforceFinal(t *testing.T) {
	p := Default()
	base := strings.Fields(defServices)
	ok := append(append([]string{}, base...), "--max-rate", "60", "--stats-every", "2s", "-oX", "r/c.xml", "-iL", "r/c.targets")
	if _, err := p.Enforce(ok, Opts{Final: true, TargetsFile: "r/c.targets", MaxProcRate: 60}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Enforce(ok, Opts{Final: true, TargetsFile: "r/c.targets", MaxProcRate: 50}); err == nil {
		t.Fatal("rate above per-process limit accepted")
	}
	if _, err := p.Enforce(ok, Opts{Final: true, TargetsFile: "other", MaxProcRate: 60}); err == nil {
		t.Fatal("foreign -iL accepted")
	}
	noRate := append(append([]string{}, base...), "-iL", "r/c.targets")
	if _, err := p.Enforce(noRate, Opts{Final: true, TargetsFile: "r/c.targets", MaxProcRate: 60}); err == nil {
		t.Fatal("missing --max-rate accepted")
	}
}
