package importer

import (
	"os"
	"testing"

	"asi/internal/obs"
)

// The sample file linked from docs/guide/jury.md ("import" step) must stay importable.
func TestDocsJurySample(t *testing.T) {
	b, err := os.ReadFile("../../docs/public/import/inny-skaner.csv")
	if err != nil {
		t.Fatal(err)
	}
	r, err := Parse("inny-skaner.csv", b)
	if err != nil {
		t.Fatal(err)
	}
	ports, svcs := 0, 0
	for _, o := range r.Observations {
		switch o.Kind {
		case obs.KindPort:
			ports++
		case obs.KindService:
			svcs++
		}
	}
	// 6 rows: 5 open (4 TCP + SNMP over UDP), the closed telnet is not an observation
	if len(r.Hosts) != 3 || ports != 5 || svcs != 5 {
		t.Fatalf("hosts %v, ports %d, services %d, skipped %v", r.Hosts, ports, svcs, r.Skipped)
	}
}
