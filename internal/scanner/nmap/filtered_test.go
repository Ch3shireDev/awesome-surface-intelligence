package nmap

import (
	"strings"
	"testing"

	"asi/internal/findings"
	"asi/internal/nmapxml"
)

func TestFiltered(t *testing.T) {
	r, err := nmapxml.Parse(strings.NewReader(`<nmaprun>
<host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/><ports>
 <port protocol="tcp" portid="22"><state state="open"/></port>
 <port protocol="tcp" portid="80"><state state="filtered" reason="no-response"/></port>
 <port protocol="tcp" portid="443"><state state="closed" reason="reset"/></port></ports></host>
<host><status state="up"/><address addr="192.0.2.21" addrtype="ipv4"/><ports><extraports state="filtered" count="40"/></ports></host>
<host><status state="up"/><address addr="192.0.2.23" addrtype="ipv4"/><ports><extraports state="closed" count="40"/></ports></host>
<host timedout="true"><status state="up"/><address addr="192.0.2.22" addrtype="ipv4"/></host></nmaprun>`))
	if err != nil {
		t.Fatal(err)
	}
	got := Filtered(r.Hosts, map[string][]int{"192.0.2.20": {22, 80, 443}, "192.0.2.21": {8787}, "192.0.2.22": {1}, "192.0.2.23": {9}})
	if len(got) != 2 || got[0].AssetKey != "192.0.2.20/tcp/80" || got[1].AssetKey != "192.0.2.21/tcp/8787" {
		t.Fatalf("filtered = %+v", got)
	}
	if s := findings.FromObservations(got, nil); len(s) != 0 {
		t.Fatalf("a filtered port is not a service: %+v", s)
	}
}
