package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestRoundTripAndNoPlaintext(t *testing.T) {
	k, err := ParseKeys("k1:" + newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"cookie":"session=SEKRET-123","ip":"192.0.2.10"}`)
	sealed, err := k.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("SEKRET-123")) || bytes.Contains(sealed, []byte("192.0.2.10")) {
		t.Fatal("sealed value contains plaintext")
	}
	if !bytes.HasPrefix(sealed, magic) {
		t.Fatal("missing magic prefix")
	}
	got, err := k.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip: got %q", got)
	}
	again, _ := k.Seal(plain)
	if bytes.Equal(again, sealed) {
		t.Fatal("two seals of the same value are identical (nonce reuse?)")
	}
}

func TestEmptyValue(t *testing.T) {
	k, _ := ParseKeys("k1:" + newKey(t))
	s, err := k.Seal(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Open(s)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty round trip: %q %v", got, err)
	}
}

func TestRotation(t *testing.T) {
	oldKey, newK := newKey(t), newKey(t)
	old, _ := ParseKeys("k1:" + oldKey)
	sealedOld, _ := old.Seal([]byte("stare"))

	rotated, err := ParseKeys("k2:" + newK + ",k1:" + oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ActiveID() != "k2" {
		t.Fatalf("active = %q, want k2", rotated.ActiveID())
	}
	if got, err := rotated.Open(sealedOld); err != nil || string(got) != "stare" {
		t.Fatalf("old value after rotation: %q %v", got, err)
	}
	sealedNew, _ := rotated.Seal([]byte("nowe"))
	if _, err := old.Open(sealedNew); err == nil || !strings.Contains(err.Error(), `"k2"`) {
		t.Fatalf("old ring must not open k2 values, err=%v", err)
	}
}

func TestTamperAndWrongKey(t *testing.T) {
	k, _ := ParseKeys("k1:" + newKey(t))
	s, _ := k.Seal([]byte("dane"))
	s[len(s)-1] ^= 0xff
	if _, err := k.Open(s); err == nil {
		t.Fatal("tampered value opened")
	}
	other, _ := ParseKeys("k1:" + newKey(t))
	s2, _ := k.Seal([]byte("dane"))
	if _, err := other.Open(s2); err == nil {
		t.Fatal("value opened with a different key of the same id")
	}
	if _, err := k.Open([]byte("ASI1\x05k1")); err == nil {
		t.Fatal("truncated value opened")
	}
}

func TestLegacyPlaintextPassthrough(t *testing.T) {
	k, _ := ParseKeys("k1:" + newKey(t))
	got, err := k.Open([]byte(`{"legacy":true}`))
	if err != nil || string(got) != `{"legacy":true}` {
		t.Fatalf("legacy: %q %v", got, err)
	}
}

func TestParseErrorsDoNotLeakKeys(t *testing.T) {
	key := newKey(t)
	cases := []string{"", " , ", "noColon", "k1:not-base64!!", "k1:" + base64.StdEncoding.EncodeToString([]byte("short")),
		"k1:" + key + ",k1:" + key}
	for _, c := range cases {
		_, err := ParseKeys(c)
		if err == nil {
			t.Errorf("ParseKeys(%q) = nil error", c)
			continue
		}
		if strings.Contains(err.Error(), key) {
			t.Errorf("error leaks key material: %v", err)
		}
	}
}
