package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// AssetFilter.RunID/Events: kafelek "nowe w ostatnim skanie" musi pokazać dokładnie te
// assety, które w tym przebiegu dostały zdarzenie new/reappeared. Stan assetu to zwykle
// już "active", więc filtr po samym stanie dawał 0 przy niezerowej liczbie zdarzeń.
func TestAssetsByEvents(t *testing.T) {
	st := testStore(t, xorSealer{})
	ctx := context.Background()
	suf := time.Now().UnixNano()
	run := fmt.Sprintf("test-ev-%d", suf)
	keyNew := fmt.Sprintf("198.51.100.%d", suf%200+1)
	keyOld := fmt.Sprintf("198.51.100.%d", (suf/7)%200+1+30)
	cleanup := func() {
		st.DB.Exec(ctx, `DELETE FROM asset_events WHERE run_id=$1`, run)
		st.DB.Exec(ctx, `DELETE FROM assets WHERE key=$1 OR key=$2`, keyNew, keyOld)
	}
	cleanup()
	t.Cleanup(cleanup)

	ins := func(key string, state string) int64 {
		var id int64
		err := st.DB.QueryRow(ctx, `INSERT INTO assets (key, kind, ip, state, first_seen, last_seen, last_seen_run)
			VALUES ($1,'host',$2,$3,now(),now(),$4) RETURNING id`, key, key, state, run).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	newID := ins(keyNew, "active") // nowy asset, ale stan już "active" (po reconcile)
	oldID := ins(keyOld, "active")

	ev := func(id int64, typ string) {
		if _, err := st.DB.Exec(ctx, `INSERT INTO asset_events (asset_id, run_id, type) VALUES ($1,$2,$3)`, id, run, typ); err != nil {
			t.Fatal(err)
		}
	}
	ev(newID, "new")
	ev(oldID, "changed")

	got, err := st.Assets(ctx, AssetFilter{RunID: run, Events: []string{"new", "reappeared"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Key != keyNew {
		t.Fatalf("assetow=%d, oczekiwano 1 (%s)", len(got), keyNew)
	}
	// sam stan "new" nie da nic, bo asset jest "active" - to była przyczyna rozjazdu kafelka
	if as, _ := st.Assets(ctx, AssetFilter{State: "new", Search: keyNew}); len(as) != 0 {
		t.Fatalf("filtr state=new zwrocil %d assetow, a to wlasnie dawalo 0 przy niezerowym kafelku", len(as))
	}
	keys, err := st.EventAssetKeys(ctx, run, []string{"new", "reappeared"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != keyNew {
		t.Fatalf("EventAssetKeys=%v, oczekiwano [%s]", keys, keyNew)
	}
}
