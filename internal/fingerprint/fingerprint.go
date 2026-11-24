// Package fingerprint turns a raw secret into a stable identifier that is useless outside this
// machine: HMAC-SHA256 under a random per-machine key, truncated to 16 hex characters. A plain hash
// of a short or structured secret could be brute-forced from the output; an HMAC cannot without the
// key. The local-secrets connector fingerprints what it finds; `segurata rotations replace`
// fingerprints the old and new values to tell them apart without ever storing either.
package fingerprint

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Key is the per-machine HMAC key.
type Key struct{ key []byte }

const keyBytes = 32

// FromBytes builds a key from raw bytes, for tests and callers that hold the key already.
func FromBytes(b []byte) Key { return Key{key: append([]byte(nil), b...)} }

// DefaultPath is ~/.config/segurata/fingerprint.key.
func DefaultPath(home string) string {
	return filepath.Join(home, ".config", "segurata", "fingerprint.key")
}

// Load reads the key, creating it with mode 0600 on first use. Losing the key changes every
// fingerprint, so the rotation ledger would see every secret as new.
func Load(path string) (Key, error) {
	k, err := Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return create(path)
	}
	return k, err
}

// Open reads an existing key. Commands that compare against fingerprints already in the ledger
// use it: a new key would match nothing.
func Open(path string) (Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Key{}, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) < keyBytes {
		return Key{}, fmt.Errorf("%s is not a %d-byte hex key", path, keyBytes)
	}
	return Key{key: key}, nil
}

func create(path string) (Key, error) {
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return Key{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Key{}, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) { // another run created it first
		return Load(path)
	}
	if err != nil {
		return Key{}, err
	}
	if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return Key{}, err
	}
	return Key{key: key}, f.Close()
}

// Of returns the fingerprint of secret, "" for an empty one.
func (k Key) Of(secret string) string {
	if secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, k.key)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))[:16]
}
