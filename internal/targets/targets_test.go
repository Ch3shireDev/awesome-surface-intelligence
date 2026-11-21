package targets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCSVAndPlan(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.csv")
	os.WriteFile(p, []byte("target,asset,owner,tags,enabled,note\n# comment,,,,,\n10.0.0.0/30,lab,me,a;b,true,\n10.0.0.1,lab,me,c,true,\n192.0.2.1,x,other,,false,not ours\n"), 0o644)
	ts, err := Load(p)
	if err != nil || len(ts) != 3 {
		t.Fatalf("load: %v %d", err, len(ts))
	}
	if len(ts[0].Tags) != 2 {
		t.Fatalf("tags: %+v", ts[0].Tags)
	}
	pl := BuildPlan(ts, PlanOptions{SkipCDN: true, OnlyInventory: true})
	if len(pl.Hosts) != 4 { // /30 = 4 addresses, 10.0.0.1 deduplicated
		t.Fatalf("hosts: %d", len(pl.Hosts))
	}
	if len(pl.Skipped) != 1 {
		t.Fatalf("skipped: %+v", pl.Skipped)
	}
}
