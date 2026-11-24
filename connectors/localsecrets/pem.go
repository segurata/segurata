package localsecrets

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// escapedBreak is a newline as it appears inside JSON strings and transcripts: "\n", "\\n", "\r\n".
var escapedBreak = regexp.MustCompile(`(?:\\+[nr])+`)

// pemBody extracts the base64 body of a PEM private key, in either real-newline or escaped form,
// dropping the BEGIN/END lines and RFC 1421 headers. The same key gives the same body wherever it
// is found (a .pem file, a service-account JSON, a transcript, git history), so it gets the same
// fingerprint.
func pemBody(text string) string {
	text = escapedBreak.ReplaceAllString(text, "\n")
	var b strings.Builder
	in := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "-----BEGIN"):
			in = true
			continue
		case strings.Contains(line, "-----END"):
			return b.String()
		case !in || strings.Contains(line, ":"):
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// pemEncrypted reports whether a PEM key needs a passphrase: PKCS#8 "ENCRYPTED PRIVATE KEY",
// PKCS#1 with a Proc-Type header, or an OpenSSH key whose cipher is not "none".
func pemEncrypted(header, text, body string) bool {
	if strings.Contains(header, "ENCRYPTED") || strings.Contains(text, "Proc-Type: 4,ENCRYPTED") {
		return true
	}
	if !strings.Contains(header, "OPENSSH") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return false
	}
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(raw, []byte(magic)) || len(raw) < len(magic)+4 {
		return false
	}
	rest := raw[len(magic):]
	n := int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	if len(rest) < 4+n {
		return false
	}
	return string(rest[4:4+n]) != "none"
}

var pemHeader = regexp.MustCompile(`-----BEGIN ([A-Z ]*)PRIVATE KEY-----`)

// pemLabel is the key kind from its header ("RSA", "OPENSSH", "EC"), "PKCS8" when unnamed.
func pemLabel(text string) string {
	m := pemHeader.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	if l := strings.TrimSpace(m[1]); l != "" {
		return l
	}
	return "PKCS8"
}

// pemBlockAt reads the PEM block whose header is on (1-based) line n of path, for keys stored with
// real newlines, where ripgrep only reports the header line.
func pemBlockAt(path string, n int) string {
	raw, err := readSmall(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(raw), "\n")
	if n < 1 || n > len(lines) {
		return ""
	}
	var b strings.Builder
	for _, l := range lines[n-1:] {
		b.WriteString(l)
		b.WriteByte('\n')
		if strings.Contains(l, "-----END") {
			break
		}
	}
	return b.String()
}

// readSmall reads a file of at most 50 MB, the limit ripgrep is given.
func readSmall(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > 50<<20 {
		return nil, fmt.Errorf("%s: too large", path)
	}
	return os.ReadFile(path)
}
