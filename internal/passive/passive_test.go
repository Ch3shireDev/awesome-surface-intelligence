package passive

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFind(t *testing.T) {
	var asked []string
	down := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/issuances":
			if down {
				w.WriteHeader(429)
				return
			}
			w.Write([]byte(`[{"dns_names":["*.example.org","www.example.org","other.example.com","evilexample.org"]}]`))
		case "/":
			w.Write([]byte(`[{"name_value":"old.example.org\nexample.org"}]`))
		default:
			asked = append(asked, r.URL.Path)
			w.Write([]byte(`{"ports":[443,80]}`))
		}
	}))
	defer s.Close()
	c := New()
	c.CertSpotter, c.CRTSh, c.InternetDB = s.URL, s.URL, s.URL
	c.Lookup = func(_ context.Context, h string) ([]string, error) {
		if h == "www.example.org" {
			return []string{"8.8.8.8"}, nil
		}
		return []string{"10.0.0.1", "100.64.0.9"}, nil // never sent to the inventory
	}
	r, err := c.Find(context.Background(), "Example.ORG", true)
	if err != nil || len(r.Records) != 2 || r.Records[1].Name != "www.example.org" || len(r.Records[1].Ports) != 2 {
		t.Fatalf("%v %+v", err, r)
	}
	if len(asked) != 1 || asked[0] != "/8.8.8.8" {
		t.Fatalf("inventory asked about %v", asked)
	}
	down = true
	if r, err = c.Find(context.Background(), "example.org", false); err != nil || len(r.Records) != 2 || r.Records[1].Name != "old.example.org" {
		t.Fatalf("crt.sh fallback: %v %+v", err, r)
	}
	for _, bad := range []string{"192.0.2.1", "x/../y", ""} {
		if _, err := c.Find(context.Background(), bad, false); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
