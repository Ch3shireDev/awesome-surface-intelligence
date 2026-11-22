package findings

import "testing"

// LAB-T5: a two-run comparison must not call a first miss "gone" when the history says "missing".
func TestDiffAnnotateWithHistory(t *testing.T) {
	a := []Service{{IP: "192.0.2.1", Proto: "tcp", Port: 80, Name: "http"}, {IP: "192.0.2.1", Proto: "tcp", Port: 22, Name: "ssh"}}
	b := []Service{{IP: "192.0.2.1", Proto: "tcp", Port: 80, Name: "http"}, {IP: "192.0.2.1", Proto: "tcp", Port: 8787, Name: "http"}}
	d := Compare("A", "B", a, b, []string{"192.0.2.1", "192.0.2.9"}, []string{"192.0.2.1"})
	labels := map[string]string{}
	for _, c := range d.Changes {
		labels[c.Key] = c.Label()
	}
	if labels["192.0.2.1:22/tcp"] != "brak w tym przebiegu" || labels["192.0.2.1:8787/tcp"] != "pojawiła się" {
		t.Fatalf("labels without history: %v", labels)
	}
	d.Annotate(map[string]string{
		"192.0.2.1/tcp/22":   "missing",
		"192.0.2.1/tcp/8787": "reappeared",
		"192.0.2.9":          "gone",
	})
	for _, c := range d.Changes {
		labels[c.Key] = c.Label()
	}
	if labels["192.0.2.1:22/tcp"] != "missing" || labels["192.0.2.1:8787/tcp"] != "reappeared" {
		t.Fatalf("labels with history: %v", labels)
	}
	if d.HostHistory["192.0.2.9"] != "gone" {
		t.Fatalf("host history: %v", d.HostHistory)
	}
	// flapping alone does not replace the state word; a state event wins over flapping
	if PickEvent(PickEvent("", "flapping"), "missing") != "missing" || PickEvent("missing", "flapping") != "missing" {
		t.Fatal("PickEvent order")
	}
	if (Change{Kind: "gone", History: "flapping"}).Label() != "brak w tym przebiegu" {
		t.Fatal("flapping must not be the label")
	}
}
