package nmap

import (
	"context"
	"strings"
	"testing"

	"asi/internal/obs"
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
