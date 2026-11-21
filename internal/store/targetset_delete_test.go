package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"asi/internal/targets"
)

// DeleteTargetSet: pusty zbiór znika bez -force, z celami wymaga -force,
// a nieistniejący zbiór to czytelny błąd (sprzątanie zbiorów testowych w GUI/CLI).
func TestDeleteTargetSet(t *testing.T) {
	st := testStore(t, xorSealer{})
	ctx := context.Background()
	name := fmt.Sprintf("test-drop-%d", time.Now().UnixNano())
	if _, err := st.MergeTargets(ctx, name, []targets.Target{{Target: "192.0.2.77", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.DB.Exec(ctx, `DELETE FROM targets WHERE set_id=(SELECT id FROM target_sets WHERE name=$1)`, name)
	})
	t.Cleanup(func() { st.DB.Exec(ctx, `DELETE FROM target_sets WHERE name=$1`, name) })

	// z celami: bez -force odmowa, z liczbami w komunikacie
	if _, err := st.DeleteTargetSet(ctx, name, false); err == nil {
		t.Fatal("zbiór z celami usunięty bez -force")
	} else if !strings.Contains(err.Error(), "-force") || !strings.Contains(err.Error(), "cele: 1") {
		t.Fatalf("slaby komunikat: %v", err)
	}
	// cele nadal na miejscu
	ts, err := st.Targets(ctx, name)
	if err != nil || len(ts) != 1 {
		t.Fatalf("cele zniknely po odmowie: %d, %v", len(ts), err)
	}
	// -force usuwa zbiór i cele
	n, err := st.DeleteTargetSet(ctx, name, true)
	if err != nil || n != 1 {
		t.Fatalf("usunieto %d celow, err=%v", n, err)
	}
	if ts, err := st.Targets(ctx, name); err != nil || len(ts) != 0 {
		t.Fatalf("zbiór nadal ma cele: %d, %v", len(ts), err)
	}
	// drugi raz: nie ma takiego zbioru
	if _, err := st.DeleteTargetSet(ctx, name, true); err == nil {
		t.Fatal("usuniecie nieistniejacego zbioru bez bledu")
	} else if !strings.Contains(err.Error(), "nie ma zbioru") {
		t.Fatalf("nieoczekiwany blad: %v", err)
	}
}
