package nmap

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"asi/internal/obs"
	"asi/internal/safety"
)

const sample = `<?xml version="1.0"?><nmaprun>
<host><status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="www.example.org" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.27" tunnel="ssl" method="probed" conf="10"/></port>
<port protocol="tcp" portid="8888"><state state="open" reason="syn-ack"/><service name="sun-answerbook" method="table" conf="3"/></port>
<port protocol="tcp" portid="25"><state state="closed" reason="reset"/></port>
</ports></host>
<host><status state="down" reason="no-response"/><address addr="192.0.2.11" addrtype="ipv4"/></host>
<host><status state="up" reason="syn-ack"/><address addr="192.0.2.12"`

func TestParseServices(t *testing.T) {
	os, err := Services(DefaultServicesArgs).Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	count := map[obs.Kind]int{}
	for _, o := range os {
		count[o.Kind]++
	}
	// 1 host up (down host ignored, truncated last host dropped), 2 open ports, 2 services
	if count[obs.KindHost] != 1 || count[obs.KindPort] != 2 || count[obs.KindService] != 2 {
		t.Fatalf("counts: %v", count)
	}
	for _, o := range os {
		if o.Kind == obs.KindService && o.AssetKey == "192.0.2.10/tcp/443" {
			var d obs.ServiceData
			o.Decode(&d)
			if !d.TLS || d.Product != "nginx" || o.Confidence != 100 {
				t.Fatalf("service: %+v conf=%d", d, o.Confidence)
			}
		}
		if o.Kind == obs.KindService && o.AssetKey == "192.0.2.10/tcp/8888" && o.Confidence != 30 {
			t.Fatalf("port-table guess should have low confidence, got %d", o.Confidence)
		}
	}
}

func TestFPChangesWithVersion(t *testing.T) {
	a := obs.New(obs.KindService, "k", "nmap", nil, 100, "http", "nginx", "1.27")
	b := obs.New(obs.KindService, "k", "nmap", nil, 100, "http", "nginx", "1.28")
	if a.FPHash == b.FPHash {
		t.Fatal("fp must change with version")
	}
}

func TestCommandRateAndPorts(t *testing.T) {
	cmd, spec := Services(DefaultServicesArgs).Command(context.Background(),
		obs.Chunk{Dir: "/tmp/x", Name: "chunk_0001", TargetsFile: "/tmp/x/t"},
		obs.StageConfig{RatePPS: 60, Ports: []int{22, 443}})
	a := strings.Join(cmd.Args, " ")
	for _, want := range []string{"--max-rate 60", "-p 22,443", "-oX /tmp/x/chunk_0001.xml", "-iL /tmp/x/t"} {
		if !strings.Contains(a, want) {
			t.Errorf("missing %q in %s", want, a)
		}
	}
	if strings.Contains(a, "--top-ports") || spec.Format != "nmap-xml" {
		t.Errorf("ports must replace --top-ports: %s", a)
	}
	if p, _, ok := (&Adapter{}).ParseProgress("Stats: 0:00:05 elapsed; 3 hosts completed (2 up), 1 undergoing"); !ok || p != 3 {
		t.Errorf("progress parse")
	}
}

func TestApplyPorts(t *testing.T) {
	// auto: small target set (<= 16 hosts) switches to full TCP
	got, note, err := ApplyPorts(DefaultServicesArgs, "auto", 1)
	if err != nil || !strings.Contains(got, "-p 1-65535") || strings.Contains(got, "--top-ports") || note == "" {
		t.Fatalf("auto 1 host: got=%q note=%q err=%v", got, note, err)
	}
	got, _, err = ApplyPorts(DefaultServicesArgs, "auto", SmallTargetAutoFullMax)
	if err != nil || !strings.Contains(got, "-p 1-65535") {
		t.Fatalf("auto %d hosts: got=%q err=%v", SmallTargetAutoFullMax, got, err)
	}
	// auto: > 16 hosts stays on --top-ports 1000
	got, note, err = ApplyPorts(DefaultServicesArgs, "auto", SmallTargetAutoFullMax+1)
	if err != nil || !strings.Contains(got, "--top-ports 1000") || strings.Contains(got, "-p 1-65535") || note != "" {
		t.Fatalf("auto 17 hosts: got=%q note=%q err=%v", got, note, err)
	}
	// auto: explicit -p in baseArgs is preserved (e.g. make demo)
	base := "-sT -sV -Pn -p 22,80,443 --open"
	got, _, err = ApplyPorts(base, "auto", 1)
	if err != nil || got != base {
		t.Fatalf("auto explicit -p: got=%q want=%q err=%v", got, base, err)
	}
	// attached -p- is also preserved
	baseAll := "-sT -sV -Pn -p- --open"
	got, _, err = ApplyPorts(baseAll, "auto", 100)
	if err != nil || got != baseAll {
		t.Fatalf("auto explicit -p-: got=%q err=%v", got, err)
	}
	// profiles: all / lab / allowed / top100 / custom
	for _, prof := range []string{"all", "lab", "allowed", "-"} {
		got, _, err = ApplyPorts(DefaultServicesArgs, prof, 500)
		if err != nil || !strings.Contains(got, "-p 1-65535") || strings.Contains(got, "--top-ports") {
			t.Fatalf("profile %s: got=%q err=%v", prof, got, err)
		}
	}
	got, _, err = ApplyPorts(DefaultServicesArgs, "top100", 1)
	if err != nil || !strings.Contains(got, "--top-ports 100") || strings.Contains(got, "-p ") {
		t.Fatalf("top100: got=%q err=%v", got, err)
	}
	got, _, err = ApplyPorts(DefaultServicesArgs, "80,443,8787,15432", 100)
	if err != nil || !strings.Contains(got, "-p 80,443,8787,15432") {
		t.Fatalf("custom: got=%q err=%v", got, err)
	}
	if _, _, err = ApplyPorts(DefaultServicesArgs, "invalid;rm", 1); err == nil {
		t.Fatal("expected error for invalid port spec")
	}
}

func TestApplyPortsWithSafetyPolicy(t *testing.T) {
	got, _, err := ApplyPorts(DefaultServicesArgs, "auto", 1)
	if err != nil {
		t.Fatal(err)
	}
	// without ASI_ALLOWED_PORTS: full TCP passes safety policy
	pol := safety.Default()
	enforced, err := pol.Enforce(strings.Fields(got), safety.Opts{})
	if err != nil || !strings.Contains(strings.Join(enforced, " "), "-p 1-65535") {
		t.Fatalf("enforce unrestricted: %v err=%v", enforced, err)
	}
	// with ASI_ALLOWED_PORTS: full TCP intersects cleanly with the allow-list (no --top-ports truncation)
	pol.Ports, _ = safety.ParsePorts("80,443,8787,15432")
	enforced, err = pol.Enforce(strings.Fields(got), safety.Opts{})
	joined := strings.Join(enforced, " ")
	if err != nil || !strings.Contains(joined, "-p 80,443,8787,15432") || strings.Contains(joined, "--top-ports") {
		t.Fatalf("enforce allow-list: %q err=%v", joined, err)
	}
}

func TestTopPortsPlusRisky(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap not installed")
	}
	l := TopPortsPlusRisky(100)
	if !strings.Contains(l, ",6379") || !strings.HasPrefix(l, "7,") && !strings.Contains(l, "80") {
		t.Fatalf("list: %.80s", l)
	}
	cmd, _ := Services(DefaultServicesArgs).Command(context.Background(), obs.Chunk{Dir: "/x", Name: "c", TargetsFile: "/x/t"}, obs.StageConfig{})
	a := strings.Join(cmd.Args, " ")
	if strings.Contains(a, "--top-ports") || !strings.Contains(a, "27017") {
		t.Fatalf("services scan must cover risky ports: %.200s", a)
	}
	cmd, _ = Services(DefaultServicesArgs+" -p 22").Command(context.Background(), obs.Chunk{Dir: "/x", Name: "c", TargetsFile: "/x/t"}, obs.StageConfig{})
	if a := strings.Join(cmd.Args, " "); strings.Contains(a, "27017") {
		t.Fatalf("explicit -p must win: %s", a)
	}
}
