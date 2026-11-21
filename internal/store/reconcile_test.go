package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"asi/internal/obs"
)

// fakeRun stores a run with done/failed chunks and observations, then reconciles it.
type scan struct {
	covered []string          // discovery+services chunk targets (done)
	failed  []string          // chunk targets that failed (must not create misses)
	up      map[string][]port // ip -> open ports
	ports   string            // scanned port set ("" = all)
}
type port struct {
	n       int
	product string
}

func runScan(t *testing.T, st *Store, prefix string, i int, sc scan) ReconcileResult {
	t.Helper()
	ctx := context.Background()
	id := fmt.Sprintf("%s-%02d", prefix, i)
	if err := st.CreateRun(ctx, id, "test", "manual", nil); err != nil {
		t.Fatal(err)
	}
	st.StartChunk(ctx, id, "discovery", 0, sc.covered)
	st.FinishChunk(ctx, id, "discovery", 0, "done", time.Second, "")
	st.StartChunk(ctx, id, "services", 0, sc.covered)
	st.FinishChunk(ctx, id, "services", 0, "done", time.Second, "")
	st.SetChunkPorts(ctx, id, "services", 0, sc.ports)
	if len(sc.failed) > 0 {
		st.StartChunk(ctx, id, "discovery", 1, sc.failed)
		st.FinishChunk(ctx, id, "discovery", 1, "killed", time.Second, "window")
	}
	var os []obs.Observation
	for ip, ports := range sc.up {
		os = append(os, obs.New(obs.KindHost, ip, "test", obs.HostData{Up: true}, 100, "up"))
		for _, p := range ports {
			k := obs.PortKey(ip, "tcp", p.n)
			os = append(os, obs.New(obs.KindPort, k, "test", obs.PortData{State: "open"}, 100, "open"))
			os = append(os, obs.New(obs.KindService, k, "test", obs.ServiceData{Name: "http", Product: p.product}, 100, "http", p.product))
		}
	}
	if err := st.InsertObservations(ctx, id, "services", 0, os); err != nil {
		t.Fatal(err)
	}
	st.FinishRun(ctx, id, "completed", nil)
	r, err := st.Reconcile(ctx, id, ReconcileConfig{HostMissThreshold: 3, PortMissThreshold: 2, FlapTransitions: 3})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func has(r ReconcileResult, typ, key string) bool {
	for _, e := range r.Events {
		if e.Type == typ && e.Key == key {
			return true
		}
	}
	return false
}

func TestReconcile(t *testing.T) {
	st := testStore(t, xorSealer{})
	ctx := context.Background()
	prefix := fmt.Sprintf("rt%d", time.Now().UnixNano())
	A, B, C := "198.51.100.1", "198.51.100.2", "198.51.100.3"
	cleanup := func() {
		st.DB.Exec(ctx, `DELETE FROM assets WHERE key LIKE '198.51.100.%'`)
		st.DB.Exec(ctx, `DELETE FROM runs WHERE id LIKE $1`, prefix+"%")
	}
	cleanup()
	t.Cleanup(cleanup)
	all := []string{A, B, C}
	A443 := obs.PortKey(A, "tcp", 443)
	B22 := obs.PortKey(B, "tcp", 22)
	C80 := obs.PortKey(C, "tcp", 80)

	r := runScan(t, st, prefix, 1, scan{covered: all, up: map[string][]port{
		A: {{443, "nginx 1.0"}}, B: {{22, "OpenSSH"}}, C: {{80, "x"}}}})
	if r.Counts["new"] != 6 {
		t.Fatalf("run1 new: %v", r.Counts)
	}
	// user edit must survive all later scans
	tags := []string{"crown-jewel"}
	note := "owner: team A"
	if err := st.EditAsset(ctx, nil, A443, AssetEdit{Tags: &tags, Note: &note}); err != nil {
		t.Fatal(err)
	}

	// run2: A changes version, B down (missing; its port inherits, no miss), C80 closed (port missing)
	r = runScan(t, st, prefix, 2, scan{covered: all, up: map[string][]port{A: {{443, "nginx 1.1"}}, C: {}}})
	if !has(r, "changed", A443) || !has(r, "missing", B) || has(r, "missing", B22) || !has(r, "missing", C80) {
		t.Fatalf("run2 events: %+v", r.Events)
	}

	// run3: partial - B's chunk failed: no new miss for B; C80 back -> reappeared
	r = runScan(t, st, prefix, 3, scan{covered: []string{A, C}, failed: []string{B},
		up: map[string][]port{A: {{443, "nginx 1.1"}}, C: {{80, "x"}}}})
	if has(r, "missing", B) || has(r, "gone", B) || !has(r, "reappeared", C80) {
		t.Fatalf("run3 events: %+v", r.Events)
	}
	// run4: B miss 2, C80 missing again; run5: B miss 3 -> gone (threshold 3)
	// C80 transitions: missing(2), reappeared(3), missing(4) = 3 -> flapping at run4
	r = runScan(t, st, prefix, 4, scan{covered: all, up: map[string][]port{A: {{443, "nginx 1.1"}}, C: {}}})
	if !has(r, "flapping", C80) || has(r, "gone", B) {
		t.Fatalf("run4 events: %+v", r.Events)
	}
	r = runScan(t, st, prefix, 5, scan{covered: all, up: map[string][]port{A: {{443, "nginx 1.1"}}, C: {{80, "x"}}}})
	if !has(r, "gone", B) {
		t.Fatalf("run5 events: %+v", r.Events)
	}
	// run6: B back
	r = runScan(t, st, prefix, 6, scan{covered: all, up: map[string][]port{A: {{443, "nginx 1.1"}}, B: {{22, "OpenSSH"}}, C: {{80, "x"}}}})
	if !has(r, "reappeared", B) {
		t.Fatalf("run6 events: %+v", r.Events)
	}

	as, err := st.Assets(ctx, AssetFilter{Search: "198.51.100."})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Asset{}
	for _, a := range as {
		got[a.Key] = a
	}
	if a := got[A443]; len(a.UserTags) != 1 || a.UserTags[0] != "crown-jewel" || a.UserNote != note || a.SeenCount != 6 {
		t.Fatalf("user edit lost or counts wrong: %+v", a)
	}
	if a := got[B]; a.State != "active" || a.ConsecutiveMisses != 0 {
		t.Fatalf("B: %+v", a)
	}
	if !got[C80].Flapping {
		t.Fatalf("C80 should be flapping: %+v", got[C80])
	}
	// run7 scans only port 443: A443 seen, C80 and B22 were not probed -> no miss
	r = runScan(t, st, prefix, 7, scan{covered: all, ports: "443", up: map[string][]port{A: {{443, "nginx 1.1"}}, B: {}, C: {}}})
	if has(r, "missing", C80) || has(r, "missing", B22) {
		t.Fatalf("run7: port outside the scanned set went missing: %+v", r.Events)
	}
	if _, err := st.Reconcile(ctx, prefix+"-06", ReconcileConfig{}); err == nil {
		t.Fatal("second reconcile of the same run must be refused")
	}
	if ev, _ := st.Events(ctx, "", A443, 10); len(ev) != 2 { // new + changed
		t.Fatalf("events of A443: %+v", ev)
	}
}

func TestPortSet(t *testing.T) {
	ps := ParsePorts("22,80,1000-1010")
	for p, want := range map[int]bool{22: true, 80: true, 1005: true, 443: false, 999: false} {
		if ps.Has(p) != want {
			t.Errorf("%d: want %v", p, want)
		}
	}
	if !ParsePorts("").Has(12345) {
		t.Error("empty set must cover all")
	}
}

func TestLessDetailed(t *testing.T) {
	full := []byte(`{"name":"http","product":"nginx","version":"1.27.5"}`)
	for in, want := range map[string]bool{
		`{"name":"http","product":"nginx"}`:                  true,
		`{"name":"http"}`:                                    true,
		`{"name":"http","product":"nginx","version":"1.28"}`: false,
		`{"name":"https","product":"nginx"}`:                 false,
		`{"name":"http","product":"Apache"}`:                 false,
	} {
		if got := lessDetailed(full, []byte(in)); got != want {
			t.Errorf("%s: got %v want %v", in, got, want)
		}
	}
}
