package nmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asi/internal/nmapxml"
)

// Shape of the real LAB-5 output: one host nmap gave up on (no ports at all, exit 0)
// and one host scanned normally.
const timedOutXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -sV --host-timeout 10m">
<host starttime="1" endtime="1303" timedout="true"><status state="up" reason="user-set"/>
<address addr="192.0.2.10" addrtype="ipv4"/></host>
<host starttime="1" endtime="40"><status state="up" reason="user-set"/>
<address addr="192.0.2.11" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh"/></port></ports></host>
<runstats><finished elapsed="1303.21" exit="success"/></runstats>
</nmaprun>`

func TestTimedOutHostIsNotScanned(t *testing.T) {
	run, err := nmapxml.Parse(strings.NewReader(timedOutXML))
	if err != nil {
		t.Fatal(err)
	}
	if !run.Hosts[0].TimedOut || run.Hosts[1].TimedOut {
		t.Fatalf("timedout attr not parsed: %+v", run.Hosts)
	}
	for _, o := range FromHosts(run.Hosts) {
		if strings.HasPrefix(o.AssetKey, "192.0.2.10") {
			t.Fatalf("timed-out host must give no observations (not even 'up'), got %s %s", o.Kind, o.AssetKey)
		}
	}
	p := filepath.Join(t.TempDir(), "chunk.xml")
	os.WriteFile(p, []byte(timedOutXML), 0o644)
	if got := (&Adapter{}).TimedOutHosts(p); len(got) != 1 || got[0] != "192.0.2.10" {
		t.Fatalf("TimedOutHosts = %v", got)
	}
}
