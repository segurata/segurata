// Package fingerprint turns a secret into an identifier useless outside this machine: HMAC-SHA256
// under a random per-machine key, truncated to 16 hex characters. A plain hash of a short or
// structured secret could be brute-forced from the output.
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

type Key struct{ key []byte }

const keyBytes = 32

func FromBytes(b []byte) Key { return Key{key: append([]byte(nil), b...)} }

func DefaultPath(home string) string {
	return filepath.Join(home, ".config", "segurata", "fingerprint.key")
}

// OpenDefault opens the key at DefaultPath, never creating it, for readers of fingerprints
// local-secrets recorded.
func OpenDefault() (k Key, ok bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Key{}, false
	}
	k, err = Open(DefaultPath(home))
	return k, err == nil
}

// Load reads the key, creating it with mode 0600 on first use. Losing the key changes every
// fingerprint: the rotation ledger would see every secret as new.
func Load(path string) (Key, error) {
	k, err := Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return create(path)
	}
	return k, err
}

// Open reads an existing key, for commands that compare against fingerprints in the ledger, which
// a new key would match none of.
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

// create writes the key under a temporary name and links it into place, so a run that starts
// meanwhile finds either no key or the whole of it.
func create(path string) (Key, error) {
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return Key{}, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Key{}, err
	}
	tmp, err := os.CreateTemp(dir, ".fingerprint-*")
	if err != nil {
		return Key{}, err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.WriteString(hex.EncodeToString(key) + "\n")
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Key{}, err
	}
	if err := os.Link(tmp.Name(), path); errors.Is(err, fs.ErrExist) {
		return Open(path)
	} else if err != nil {
		return Key{}, err
	}
	return Key{key: key}, nil
}

// Of is "" for an empty secret.
func (k Key) Of(secret string) string {
	if secret == "" {
		return ""
	}
	m := hmac.New(sha256.New, k.key)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// Find returns the substring of line, n bytes long, whose fingerprint is fp, or "": a value located
// again without ever having been stored. Only the windows fits accepts are fingerprinted.
func (k Key) Find(line string, n int, fp string, fits func(string) bool) string {
	if n <= 0 {
		return ""
	}
	for i := 0; i+n <= len(line); i++ {
		if w := line[i : i+n]; fits(w) && k.Of(w) == fp {
			return w
		}
	}
	return ""
}
