package importer

import (
	"strings"
	"testing"

	"asi/internal/obs"
)

func kinds(r Result) map[obs.Kind]int {
	m := map[obs.Kind]int{}
	for _, o := range r.Observations {
		m[o.Kind]++
	}
	return m
}

func TestNmapXML(t *testing.T) {
	x := `<?xml version="1.0"?><nmaprun><scaninfo type="connect" protocol="tcp" numservices="3" services="22,80,443"/>
<host><status state="up" reason="syn-ack"/><address addr="192.0.2.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/></port></ports></host>
<host><status state="down"/><address addr="192.0.2.11" addrtype="ipv4"/></host></nmaprun>`
	r, err := Parse("scan.xml", []byte(x))
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != "nmap-xml" || !r.Exact || r.Ports != "22,80,443" || len(r.Hosts) != 2 {
		t.Fatalf("%+v", r)
	}
	if k := kinds(r); k[obs.KindHost] != 1 || k[obs.KindService] != 1 {
		t.Fatalf("kinds %v", k)
	}
}

func TestCSVGeneric(t *testing.T) {
	c := "IP,Port,Protocol,Service,Product,Version,State\n192.0.2.10,443,tcp,https,nginx,1.27,open\n192.0.2.10,8080,,http,,,open\nnot-an-ip,22,tcp,ssh,,,open\n192.0.2.12,23,tcp,telnet,,,closed\n"
	r, err := Parse("wyniki.csv", []byte(c))
	if err != nil {
		t.Fatal(err)
	}
	k := kinds(r)
	if k[obs.KindHost] != 1 || k[obs.KindPort] != 2 || k[obs.KindService] != 2 || len(r.Skipped) != 1 {
		t.Fatalf("kinds %v skipped %v", k, r.Skipped)
	}
	if r.Ports != "443,8080" || r.Exact {
		t.Fatalf("coverage must be the listed ports only: %q", r.Ports)
	}
}

func TestCSVAsiExportRoundtrip(t *testing.T) {
	c := "key,kind,ip,port,state,flapping,service,first_seen,last_seen,seen_count,consecutive_misses,user_tags,user_note\n" +
		"192.0.2.10,host,192.0.2.10,0,active,false,,x,x,1,0,,\n" +
		"192.0.2.10/tcp/22,port,192.0.2.10,22,active,false,ssh OpenSSH 10.6,x,x,1,0,,\n" +
		"192.0.2.11/tcp/80,port,192.0.2.11,80,gone,false,http nginx,x,x,1,3,,\n"
	r, err := Parse("asi-assets.csv", []byte(c))
	if err != nil {
		t.Fatal(err)
	}
	var svc obs.ServiceData
	for _, o := range r.Observations {
		if o.Kind == obs.KindService {
			o.Decode(&svc)
		}
	}
	if svc.Name != "ssh" || svc.Product != "OpenSSH" || svc.Version != "10.6" {
		t.Fatalf("service split: %+v", svc)
	}
	if k := kinds(r); k[obs.KindPort] != 1 { // gone row is not an observation
		t.Fatalf("kinds %v", k)
	}
}

func TestJSONWrapped(t *testing.T) {
	j := `{"results":[{"host":"198.51.100.5","port":3306,"service":"mysql"},{"ip":"198.51.100.6"}]}`
	r, err := Parse("x.json", []byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(r); k[obs.KindHost] != 2 || k[obs.KindService] != 1 {
		t.Fatalf("kinds %v", k)
	}
}

func TestObservationsJSON(t *testing.T) {
	o := obs.New(obs.KindService, "203.0.113.9/tcp/443", "nmap", obs.ServiceData{Name: "https"}, 100, "https")
	b := `[{"kind":"service","asset_key":"203.0.113.9/tcp/443","data":` + string(o.Data) + `,"fp_hash":"` + o.FPHash + `","confidence":100,"tool":"nmap"}]`
	r, err := Parse("observations.json", []byte(b))
	if err != nil || r.Format != "asi-observations" || len(r.Observations) != 1 {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestNucleiJSONL(t *testing.T) {
	l := `{"template-id":"asi-redis-noauth","info":{"name":"Redis","severity":"high"},"ip":"192.0.2.13","port":"6379","matched-at":"192.0.2.13:6379"}` + "\n"
	r, err := Parse("n.jsonl", []byte(l))
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(r); k[obs.KindSignature] != 1 || k[obs.KindHost] != 1 || k[obs.KindPort] != 1 {
		t.Fatalf("kinds %v", k)
	}
}

func TestUnknown(t *testing.T) {
	if _, err := Parse("x.bin", []byte("hello")); err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatal("must reject unknown format")
	}
}
