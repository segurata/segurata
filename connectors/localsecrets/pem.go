package localsecrets

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// escapedBreak is a newline escaped inside JSON strings and transcripts.
var escapedBreak = regexp.MustCompile(`(?:\\+[nr])+`)

// pemBody is the base64 body of a PEM private key, with real or escaped newlines and without RFC
// 1421 headers: the same key gets the same fingerprint wherever it is found.
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

// pemLabel is the key kind in the header, "PKCS8" when unnamed.
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

// pemBlockAt reads the PEM block whose header is on line n: ripgrep reports only that line.
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

// maxFileSize bounds every file read, ripgrep's included.
const maxFileSize = 50 << 20

func readSmall(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxFileSize {
		return nil, fmt.Errorf("%s: too large", path)
	}
	return os.ReadFile(path)
}
