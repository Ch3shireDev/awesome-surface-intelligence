package store

import (
	"context"
	"strings"
	"testing"
)

// Reseal must refuse to run without a key: otherwise it would "succeed" while
// leaving plaintext in place (or write plaintext back through Plain).
func TestResealWithoutKeyFails(t *testing.T) {
	for _, s := range []Sealer{Plain{}, nil} {
		st := &Store{Sealer: s}
		if _, err := st.Reseal(context.Background(), true); err == nil {
			t.Fatalf("sealer %T: expected error, got nil", s)
		} else if !strings.Contains(err.Error(), "ASI_ENCRYPTION_KEYS") {
			t.Fatalf("sealer %T: error should name the variable, got %v", s, err)
		}
	}
}
