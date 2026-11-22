package app

import (
	"testing"
	"time"

	"asi/internal/store"
)

func TestEnsureHostsForAssetRowsAttachesExistingAndSyntheticHosts(t *testing.T) {
	now := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	rows := []assetRow{
		{Asset: store.Asset{Key: "127.0.0.1/tcp/80", Kind: "port", IP: "127.0.0.1", Port: 80, State: "new", LastSeen: now, SeenCount: 1}},
		{Asset: store.Asset{Key: "127.0.0.1/tcp/443", Kind: "port", IP: "127.0.0.1", Port: 443, State: "new", LastSeen: now, SeenCount: 2}},
		{Asset: store.Asset{Key: "192.0.2.10/tcp/22", Kind: "port", IP: "192.0.2.10", Port: 22, State: "active", LastSeen: now, SeenCount: 3}},
	}
	hostByIP := map[string]store.Asset{
		"127.0.0.1": {Key: "127.0.0.1", Kind: "host", IP: "127.0.0.1", State: "active", LastSeen: now, SeenCount: 7},
	}

	got := ensureHostsForAssetRows(rows, hostByIP)
	if len(got) != 5 {
		t.Fatalf("want 5 rows (2 hosts + 3 ports), got %d", len(got))
	}
	if got[0].Kind != "host" || got[0].Key != "127.0.0.1" || got[0].State != "active" || got[0].SeenCount != 7 {
		t.Fatalf("first row should be existing host 127.0.0.1, got %+v", got[0].Asset)
	}
	if got[1].Key != "127.0.0.1/tcp/80" || got[2].Key != "127.0.0.1/tcp/443" {
		t.Fatalf("ports of 127.0.0.1 must follow its host: %s, %s", got[1].Key, got[2].Key)
	}
	if got[3].Kind != "host" || got[3].Key != "192.0.2.10" || got[3].State != "active" {
		t.Fatalf("orphan port IP must get synthesized host, got %+v", got[3].Asset)
	}
	if got[4].Key != "192.0.2.10/tcp/22" {
		t.Fatalf("port 192.0.2.10/tcp/22 must follow its host, got %s", got[4].Key)
	}
}

func TestEnsureHostsFromOrphanPortsAndDashboardCount(t *testing.T) {
	hosts := []store.Asset{{Key: "192.0.2.10", Kind: "host", IP: "192.0.2.10", State: "active"}}
	ports := []store.Asset{
		{Key: "127.0.0.1/tcp/8080", Kind: "port", IP: "127.0.0.1", Port: 8080, State: "new"},
		{Key: "192.0.2.10/tcp/80", Kind: "port", IP: "192.0.2.10", Port: 80, State: "active"},
	}

	got := ensureHostsFromOrphanPorts(hosts, ports)
	if len(got) != 2 {
		t.Fatalf("want 2 hosts (127.0.0.1 synthesized + 192.0.2.10), got %d", len(got))
	}
	if got[0].Key != "127.0.0.1" || got[0].State != "new" || got[1].Key != "192.0.2.10" {
		t.Fatalf("unexpected hosts: %+v", got)
	}

	counts := map[string]map[string]int{"host": {"active": 1}, "port": {"new": 1, "active": 1}}
	countSyntheticHosts(append(hosts, ports...), counts)
	if counts["host"]["new"] != 1 || counts["host"]["active"] != 1 {
		t.Fatalf("dashboard synthetic host count mismatch: %+v", counts["host"])
	}
}
