package app

import (
	"testing"

	"asi/internal/passive"
	"asi/internal/store"
	"asi/internal/targets"
)

func TestSelection(t *testing.T) {
	all := []store.Asset{{Key: "192.0.2.1", Kind: "host"}, {Key: "192.0.2.1/tcp/6379", Kind: "port"}, {Key: "192.0.2.2/tcp/80", Kind: "port"}}
	got := pickAssets(all, []string{"192.0.2.1", "192.0.2.1/tcp/6379", "nope"})
	if len(got) != 2 {
		t.Fatalf("picked %+v", got)
	}
	if s := selectedServices(got, nil); len(s) != 1 || s[0].Port != 6379 || s[0].Interest == "" {
		t.Fatalf("services %+v", s)
	}
}

func TestPassiveCandidates(t *testing.T) {
	c := newCandidates([]passive.Record{{Name: "www.example.org"}, {Name: "new.example.org"}},
		[]targets.Target{{Target: "WWW.example.org", Enabled: true}})
	if len(c) != 1 || c[0].Target != "new.example.org" || c[0].Enabled {
		t.Fatalf("candidates %+v", c)
	}
}
