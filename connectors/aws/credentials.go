package aws

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// credentialProfile is what the scan keeps from one [section]: never the secret.
type credentialProfile struct {
	Name      string
	KeyID     string
	Temporary bool // has a session token, so it expires on its own
}

// parseCredentials reads an INI shared credentials file. Secret values are skipped as they are read.
func parseCredentials(r io.Reader) []credentialProfile {
	var out []credentialProfile
	var cur *credentialProfile
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			out = append(out, credentialProfile{Name: strings.TrimSpace(line[1 : len(line)-1])})
			cur = &out[len(out)-1]
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || cur == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "aws_access_key_id":
			cur.KeyID = strings.TrimSpace(val)
		case "aws_session_token", "aws_security_token":
			cur.Temporary = true
		}
	}
	return out
}

// credentialFindings flags long-lived keys stored in plain text, worse when other users can read them.
func credentialFindings(path string, mode fs.FileMode, profiles []credentialProfile) []finding.Finding {
	loose := mode.Perm()&0o077 != 0
	var out []finding.Finding
	for _, p := range profiles {
		if p.KeyID == "" || p.Temporary {
			continue
		}
		f := finding.Finding{
			Account:  "local",
			Resource: finding.Resource{Type: "aws_local_credentials", ID: path + "#" + p.Name, Name: p.Name},
			Kind:     finding.KindExposure,
			Severity: finding.SevMedium,
			Title:    fmt.Sprintf("Long-lived AWS access key for profile %q stored in plain text", p.Name),
			Evidence: map[string]any{"file": path, "mode": fmt.Sprintf("%04o", mode.Perm()), "key_id": finding.Redact(p.KeyID)},
			Remediation: finding.Remediation{
				Summary: "Switch the profile to IAM Identity Center (`aws configure sso`) and delete the key; until then keep the file at mode 0600.",
				URL:     urlSSO,
			},
		}
		if loose {
			f.Severity = finding.SevHigh
			f.Title += " and readable by other users"
			f.Remediation.Summary = "Run `chmod 600` on the file now, then switch the profile to IAM Identity Center and delete the key."
			f.Remediation.URL = urlConfigFiles
		}
		out = append(out, f)
	}
	return out
}

func (c *Connector) scanCredentialsFile(emit connector.Emitter) {
	path := c.CredentialsFile()
	if path == "" {
		return
	}
	fh, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			emit.Log(fmt.Sprintf("credentials file %s: %v", path, err))
		}
		return
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		emit.Log(fmt.Sprintf("credentials file %s: %v", path, err))
		return
	}
	for _, f := range credentialFindings(path, st.Mode(), parseCredentials(fh)) {
		emit.Finding(f)
	}
}
