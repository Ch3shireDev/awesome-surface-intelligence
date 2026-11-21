package store

import (
	"context"
	"strings"
	"testing"
)

// SetPassword validates the length before touching the database, so this needs no
// connection (and proves the guard cannot be bypassed by a short password).
func TestSetPasswordRejectsShortPassword(t *testing.T) {
	st := &Store{}
	_, err := st.SetPassword(context.Background(), "admin", "short")
	if err == nil {
		t.Fatal("expected error for short password")
	}
	if !strings.Contains(err.Error(), "min. 10") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// HashPassword/CheckPassword round trip backs the recovery path used by `asi user passwd`.
func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("bardzo-tajne-haslo")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "bardzo-tajne-haslo") {
		t.Fatal("correct password rejected")
	}
	if CheckPassword(h, "inne-haslo") {
		t.Fatal("wrong password accepted")
	}
}
