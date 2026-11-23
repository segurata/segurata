package localsecrets

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/segurata/segurata/internal/secretrisk"
)

// sshKeys inspects private keys in ~/.ssh: type, permissions and whether they have a passphrase.
// ssh-keygen opens each one with an empty passphrase; its output (the public key) is discarded.
func (s *scan) sshKeys() {
	dir := s.h(".ssh")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	keygen := guardSSHKeygen(s.c.SSHKeygen)
	for _, e := range entries {
		f := filepath.Join(dir, e.Name())
		if !e.Type().IsRegular() {
			continue
		}
		raw, err := readSmall(f)
		if err != nil || !strings.Contains(string(raw[:min(len(raw), 64)]), "PRIVATE KEY") {
			continue
		}
		text := string(raw)
		body := pemBody(text)
		_, err = keygen.Run(s.ctx, "-y", "-P", "", "-f", f)
		noPass := err == nil
		pub := ""
		if _, err := os.Stat(f + ".pub"); err == nil {
			pub = f + ".pub"
		} else if noPass {
			pub = f
		}
		keytype := "?"
		if pub != "" {
			if out, err := keygen.Run(s.ctx, "-l", "-f", pub); err == nil {
				// "256 SHA256:… comment (ED25519)": keep the type and the size, never the comment.
				if l := strings.Fields(strings.TrimSpace(string(out))); len(l) >= 2 {
					keytype = strings.Trim(l[len(l)-1], "()") + " " + l[0]
				}
			}
		}
		note := keytype + " no passphrase"
		if !noPass {
			note = keytype + " passphrase"
		}
		s.add(f, secretrisk.Evidence{Source: "ssh", Kind: "config", Type: "ssh-key", Note: note, Encrypted: !noPass}, body)
	}
}
