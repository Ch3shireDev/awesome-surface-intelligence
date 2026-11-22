package safety

import (
	"strings"
	"testing"
)

func TestSelfPortsFromEnv(t *testing.T) {
	t.Setenv("ASI_SCOPE_FILE", "/nonexistent")
	t.Setenv("ASI_EXCLUDE_FILE", "/nonexistent")
	t.Setenv("DD_PORT", "18080")
	t.Setenv("ASI_WEB_ADDR", "127.0.0.1:18090")
	t.Setenv("ASI_LIVE_ADDR", "")
	t.Setenv("ASI_DB_PORT", "")
	t.Setenv("ASI_SELF_IPS", "203.0.113.10")
	p, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if got := p.SelfPorts.String(); got != "5433,18080,18090" {
		t.Fatalf("self ports: %s", got)
	}
	p.AddSelfPorts("127.0.0.1:9999", "")
	if !p.SelfPorts.Contains(9999) {
		t.Fatal("-ui port not added")
	}
	// "Obcy" adres nie moze byc zaszyty na sztywno: host moze sam miec adres z zakresu
	// dokumentacyjnego (np. mostek labu docker/lab to 192.0.2.1/24), wtedy slusznie jest
	// uwazany za wlasny. Wybieramy pierwszy dokumentacyjny, ktorego ten host nie ma.
	foreign := ""
	for _, c := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1", "192.0.2.77"} {
		if !p.IsSelf(c) {
			foreign = c
			break
		}
	}
	if foreign == "" {
		t.Skip("host ma wszystkie adresy dokumentacyjne uzyte w tescie")
	}
	for ip, want := range map[string]bool{"127.0.0.1": true, "127.0.0.53": true, "::1": true,
		"203.0.113.10": true, foreign: false, "bad": false} {
		if p.IsSelf(ip) != want {
			t.Errorf("IsSelf(%s) != %v", ip, want)
		}
	}
	self, rest := p.SplitSelf([]string{foreign, "127.0.0.1", "203.0.113.10"})
	if strings.Join(self, ",") != "127.0.0.1,203.0.113.10" || strings.Join(rest, ",") != foreign {
		t.Fatalf("split: %v %v (obcy=%s)", self, rest, foreign)
	}

	t.Setenv("ASI_SELF_PORTS", "off")
	if p, _ = FromEnv(); p.SelfPorts != nil {
		t.Fatalf("off: %s", p.SelfPorts)
	}
	if self, _ := p.SplitSelf([]string{"127.0.0.1"}); self != nil {
		t.Fatal("split with self ports off")
	}
	p.AddSelfPorts("127.0.0.1:9999")
	if p.SelfPorts != nil {
		t.Fatal("AddSelfPorts re-enabled self ports that were switched off")
	}
	t.Setenv("ASI_SELF_PORTS", "false")
	if p, err = FromEnv(); err != nil || p.SelfPorts != nil {
		t.Fatalf("false: %v %v", p, err)
	}
	t.Setenv("ASI_SELF_PORTS", "auto")
	if p, err = FromEnv(); err != nil || p.SelfPorts.String() != "5433,18080,18090" {
		t.Fatalf("auto: %v %v", p, err)
	}
	t.Setenv("ASI_SELF_PORTS", "22,8080")
	if p, _ = FromEnv(); p.SelfPorts.String() != "22,8080" {
		t.Fatalf("explicit: %s", p.SelfPorts)
	}
	// IsSelfPort checks loopback, self-IP, proto, port, and remote IP
	if !p.IsSelfPort("127.0.0.1", "tcp", 8080) || !p.IsSelfPort("::1", "tcp", 8080) || !p.IsSelfPort("203.0.113.10", "tcp", 8080) {
		t.Fatal("IsSelfPort should match self IP + own TCP port")
	}
	if p.IsSelfPort("127.0.0.1", "tcp", 8787) || p.IsSelfPort("127.0.0.1", "udp", 8080) || p.IsSelfPort(foreign, "tcp", 8080) {
		t.Fatal("IsSelfPort false positive")
	}
}

func TestSubtract(t *testing.T) {
	a, _ := ParsePorts("1-100,8000-8100")
	ex, _ := ParsePorts("50,8000,8050-8060,9000")
	if got := a.Subtract(ex).String(); got != "1-49,51-100,8001-8049,8061-8100" {
		t.Fatalf("subtract: %s", got)
	}
	if a.Subtract(nil).String() != a.String() {
		t.Fatal("subtract nil")
	}
}

func TestEnforceExcludesOwnPorts(t *testing.T) {
	p := Default()
	own, _ := ParsePorts("5433,8080,8090-8091")
	o := Opts{ExcludePorts: own}
	run := func(args string) (string, error) {
		out, err := p.Enforce(strings.Fields(args), o)
		return strings.Join(out, " "), err
	}
	// top ports: nmap drops our ports and picks the top N among the rest
	got, err := run(defServices)
	if err != nil || !strings.HasSuffix(got, "--exclude-ports 5433,8080,8090-8091") {
		t.Fatalf("top ports: %q %v", got, err)
	}
	// explicit -p: cut, and only our ports -> nothing to scan
	got, _ = run("-sT -Pn -p 22,80,8080,8090")
	if !strings.Contains(got, "-p 22,80 ") {
		t.Fatalf("explicit -p: %q", got)
	}
	if _, err = run("-sT -Pn -p 8080,8090"); err == nil {
		t.Fatal("-p with only own ports accepted")
	}
	// discovery: ping probes to our ports dropped, no --exclude-ports with -sn
	got, _ = run(defDiscovery)
	if got != "-sn -n -PS21-22,25,80,443,3389,8443 -T4 --max-retries 1" {
		t.Fatalf("discovery: %q", got)
	}
	// without ExcludePorts nothing changes
	if out, _ := p.Enforce(strings.Fields(defServices), Opts{}); strings.Join(out, " ") != defServices {
		t.Fatalf("no exclusion: %v", out)
	}
	// user --exclude-ports merged into a single --exclude-ports (nmap aborts if passed twice)
	got, err = run("-sT -Pn --top-ports 1000 --exclude-ports 9100")
	if err != nil {
		t.Fatalf("merge --exclude-ports: %v", err)
	}
	if n := strings.Count(got, "--exclude-ports"); n != 1 {
		t.Fatalf("expected exactly one --exclude-ports, got %d in %q", n, got)
	}
	if !strings.HasSuffix(got, "--exclude-ports 5433,8080,8090-8091,9100") {
		t.Fatalf("merged --exclude-ports: %q", got)
	}
	// with -sU enabled, TCP-only self exclusions use T: prefix so UDP ports stay intact
	pUDP := Default()
	pUDP.AllowUDP = true
	outUDP, err := pUDP.Enforce(strings.Fields("-sS -sU -Pn -p T:80,8080,U:53,123"), Opts{ExcludePorts: own})
	if err != nil {
		t.Fatalf("udp + self exclude: %v", err)
	}
	joinedUDP := strings.Join(outUDP, " ")
	if !strings.Contains(joinedUDP, "-p T:80,U:53,123") || !strings.HasSuffix(joinedUDP, "--exclude-ports T:5433,8080,8090-8091") {
		t.Fatalf("udp + self exclude args: %q", joinedUDP)
	}
	// bare -PS (defaults to port 80) is dropped when port 80 is excluded
	own80, _ := ParsePorts("80")
	outBare, err := p.Enforce(strings.Fields("-sn -n -PS"), Opts{ExcludePorts: own80})
	if err != nil || strings.Contains(strings.Join(outBare, " "), "-PS") {
		t.Fatalf("bare -PS with port 80 excluded: %v %v", outBare, err)
	}
}
