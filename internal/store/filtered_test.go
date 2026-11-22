package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"asi/internal/obs"
)

// Needs a throwaway database: assets are global, so it only runs with ASI_TEST_DATABASE_URL.
func TestReconcileFiltered(t *testing.T) {
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no ASI_TEST_DATABASE_URL")
	}
	ctx := context.Background()
	st, err := Open(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const ip = "198.51.100.99"
	key := obs.PortKey(ip, "tcp", 8787)
	base := time.Now().UnixNano()
	for i, state := range []string{"open", "filtered", "filtered", "filtered", "closed"} {
		id := fmt.Sprintf("t11-%d-%d", base, i)
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		must(st.CreateRun(ctx, id, "t11", "test", nil))
		must(st.StartChunk(ctx, id, "services", 0, []string{ip}))
		must(st.SetChunkPorts(ctx, id, "services", 0, "8787"))
		must(st.FinishChunk(ctx, id, "services", 0, "done", time.Second, ""))
		os := []obs.Observation{obs.New(obs.KindHost, ip, "test", obs.HostData{Up: true}, 100, "up")}
		if state != "closed" {
			os = append(os, obs.New(obs.KindPort, key, "test", obs.PortData{State: state}, 100, state))
		}
		must(st.InsertObservations(ctx, id, "services", 0, os))
		r, err := st.Reconcile(ctx, id, ReconcileConfig{})
		must(err)
		switch state {
		case "filtered":
			if r.Counts["filtered"] != 1 || r.Counts["missing"]+r.Counts["gone"]+r.Counts["changed"]+r.Counts["new"] != 0 {
				t.Fatalf("run %d: %v", i, r.Counts)
			}
		case "closed":
			if r.Counts["missing"] != 1 || r.Counts["gone"] != 0 {
				t.Fatalf("closed after filtered must be a first miss: %v", r.Counts)
			}
		}
	}
}
