package store

import (
	"context"
	"os"
	"testing"

	"asi/internal/targets"
)

func TestTargetPorts(t *testing.T) {
	url := os.Getenv("ASI_DATABASE_URL")
	if url == "" {
		t.Skip("no ASI_DATABASE_URL")
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
	const set = "test-target-ports"
	defer st.DeleteTargetSet(ctx, set, true)
	row := func(p string) []targets.Target {
		return []targets.Target{{Target: "192.0.2.77", Ports: p, Enabled: true}}
	}
	check := func(step, want string) {
		t.Helper()
		if ts, err := st.Targets(ctx, set); err != nil || len(ts) != 1 || ts[0].Ports != want {
			t.Fatalf("%s: %+v %v", step, ts, err)
		}
	}
	if _, err := st.MergeTargets(ctx, set, row("443;22")); err != nil {
		t.Fatal(err)
	}
	check("add", "22,443")
	st.MergeTargets(ctx, set, row(""))
	check("import without ports keeps them", "22,443")
	st.UpsertTargets(ctx, set, row(""))
	check("edit resets", "")
	if _, err := st.MergeTargets(ctx, set, row("70000")); err == nil {
		t.Fatal("invalid ports stored")
	}
}
