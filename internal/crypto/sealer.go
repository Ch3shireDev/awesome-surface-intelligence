// Package crypto encrypts sensitive column values (store.Sealer) with
// AES-256-GCM. It is the application-level layer of encryption at rest; the
// database files themselves are encrypted by pg_tde (docs/guide/encryption.md).
//
// Keys come from ASI_ENCRYPTION_KEYS: a comma-separated list of id:key pairs,
// key = 32 bytes in standard base64 (openssl rand -base64 32), e.g.
//
//	ASI_ENCRYPTION_KEYS=k2:BASE64...,k1:BASE64...
//
// The FIRST key seals new values; every listed key can open. Rotation: put a
// new key first, keep the old ones until all rows are re-sealed.
//
// Sealed value layout:
//
//	"ASI1" | len(id) (1 byte) | id | nonce (12 bytes) | ciphertext+tag
//
// Values without the "ASI1" prefix are returned unchanged by Open: rows written
// before encryption was enabled (store.Plain) stay readable.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// EnvVar is the environment variable holding the keyring.
const EnvVar = "ASI_ENCRYPTION_KEYS"

var magic = []byte("ASI1")

// Keyring implements store.Sealer.
type Keyring struct {
	active string
	aeads  map[string]cipher.AEAD
}

// ParseKeys parses "id:base64key,id2:base64key". The first entry is active.
func ParseKeys(spec string) (*Keyring, error) {
	k := &Keyring{aeads: map[string]cipher.AEAD{}}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, b64, ok := strings.Cut(part, ":")
		if !ok || id == "" {
			return nil, fmt.Errorf("%s: entry %q is not id:base64key", EnvVar, redact(part))
		}
		if len(id) > 255 {
			return nil, fmt.Errorf("%s: key id longer than 255 bytes", EnvVar)
		}
		if _, dup := k.aeads[id]; dup {
			return nil, fmt.Errorf("%s: duplicate key id %q", EnvVar, id)
		}
		key, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("%s: key %q is not valid base64", EnvVar, id)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("%s: key %q has %d bytes, want 32 (AES-256)", EnvVar, id, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		k.aeads[id] = aead
		if k.active == "" {
			k.active = id
		}
	}
	if k.active == "" {
		return nil, fmt.Errorf("%s: no keys", EnvVar)
	}
	return k, nil
}

// ActiveID returns the id of the key used for new values.
func (k *Keyring) ActiveID() string { return k.active }

// Seal encrypts plain with the active key.
func (k *Keyring) Seal(plain []byte) ([]byte, error) {
	aead := k.aeads[k.active]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(magic)+1+len(k.active)+len(nonce)+len(plain)+aead.Overhead())
	out = append(out, magic...)
	out = append(out, byte(len(k.active)))
	out = append(out, k.active...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plain, nil), nil
}

// Open decrypts a value sealed by any key in the ring. Values without the
// magic prefix are legacy plaintext and are returned as is.
func (k *Keyring) Open(sealed []byte) ([]byte, error) {
	if !bytes.HasPrefix(sealed, magic) {
		return sealed, nil
	}
	b := sealed[len(magic):]
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return nil, errors.New("crypto: sealed value truncated")
	}
	id := string(b[1 : 1+int(b[0])])
	b = b[1+int(b[0]):]
	aead, ok := k.aeads[id]
	if !ok {
		return nil, fmt.Errorf("crypto: value sealed with unknown key %q (missing in %s)", id, EnvVar)
	}
	if len(b) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("crypto: sealed value truncated")
	}
	nonce, ct := b[:aead.NonceSize()], b[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt with key %q: %w", id, err)
	}
	return plain, nil
}

// redact hides the key material in error messages.
func redact(entry string) string {
	if id, _, ok := strings.Cut(entry, ":"); ok {
		return id + ":***"
	}
	if len(entry) > 4 {
		return entry[:4] + "***"
	}
	return "***"
}
