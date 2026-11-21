package findings

import (
	"encoding/json"
	"testing"
)

func TestCompare(t *testing.T) {
	a := []Service{{IP: "10.0.0.1", Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.6"},
		{IP: "10.0.0.1", Port: 80, Proto: "tcp", Name: "http"}}
	b := []Service{{IP: "10.0.0.1", Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.8"},
		{IP: "10.0.0.2", Port: 443, Proto: "tcp", Name: "https"}}
	d := Compare("a", "b", a, b, []string{"10.0.0.1"}, []string{"10.0.0.1", "10.0.0.2"})
	kinds := map[string]int{}
	for _, c := range d.Changes {
		kinds[c.Kind]++
	}
	if kinds["new"] != 1 || kinds["gone"] != 1 || kinds["changed"] != 1 || d.Unchanged != 0 {
		t.Fatalf("unexpected diff: %+v", kinds)
	}
	if len(d.HostsNew) != 1 || d.HostsNew[0] != "10.0.0.2" || len(d.HostsGone) != 0 {
		t.Fatalf("hosts: %+v %+v", d.HostsNew, d.HostsGone)
	}
}

func TestScore(t *testing.T) {
	cases := []struct {
		ip   string
		port int
		want string
	}{
		{"8.8.8.8", 3389, "high"}, {"10.0.0.1", 3389, "medium"}, {"10.0.0.2", 5432, "medium"},
		{"8.8.8.8", 8888, "medium"}, {"8.8.8.8", 443, "low"},
	}
	for _, c := range cases {
		if got, _ := score(Service{IP: c.ip, Port: c.port}); got != c.want {
			t.Errorf("%s:%d got %s want %s", c.ip, c.port, got, c.want)
		}
	}
}

func TestGenericJSONOneFindingPerHostPort(t *testing.T) {
	s := []Service{{IP: "1.2.3.4", Port: 443, Proto: "tcp", Name: "http", TLS: true, Domains: []string{"a.example"}, Interest: "low"},
		{IP: "1.2.3.5", Port: 443, Proto: "tcp", Name: "http", TLS: true, Interest: "low"}}
	var doc struct {
		Findings []struct {
			UID       string `json:"unique_id_from_tool"`
			Endpoints []struct {
				Host     string `json:"host"`
				Protocol string `json:"protocol"`
			} `json:"endpoints"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(GenericJSON(s), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 2 || doc.Findings[0].UID == doc.Findings[1].UID {
		t.Fatalf("want 2 distinct findings, got %+v", doc.Findings)
	}
	if e := doc.Findings[0].Endpoints; len(e) != 2 || e[1].Host != "a.example" || e[0].Protocol != "https" {
		t.Fatalf("endpoints: %+v", e)
	}
}

func TestURLScheme(t *testing.T) {
	for name, want := range map[string]string{"ms-wbt-server": "rdp", "sun-answerbook": "", "http": "http"} {
		if got := urlScheme(Service{Name: name}); got != want || len(got) > 10 {
			t.Errorf("%s -> %q want %q", name, got, want)
		}
	}
}
