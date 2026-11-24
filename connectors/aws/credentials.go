package aws

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
)

// credentialProfile is what the scan keeps from one [section]: never the secret.
type credentialProfile struct {
	Name      string
	KeyID     string
	Temporary bool // has a session token, so it expires on its own
}

// profileConfig is what the scan keeps from a profile in the shared config file.
type profileConfig struct {
	Region   string
	Endpoint string // endpoint_url, set for S3-compatible services
}

// provider says who issued the key a profile holds: the shared files also carry keys for
// S3-compatible services, which STS and IAM know nothing about.
type provider int

const (
	providerAWS provider = iota
	providerR2
	providerS3Compatible
)

func (p provider) String() string {
	switch p {
	case providerR2:
		return "a Cloudflare R2 token"
	case providerS3Compatible:
		return "an S3-compatible key"
	}
	return "AWS"
}

// providerOf tells an AWS profile from one pointed at Cloudflare R2 or another S3-compatible
// service. AWS access key ids start with AKIA (long-lived) or ASIA (temporary); an R2 access key
// id is the 32-hex-character id of the R2 API token, used with region "auto" against
// <account>.r2.cloudflarestorage.com.
func providerOf(p credentialProfile, cfg profileConfig) provider {
	switch {
	case strings.Contains(cfg.Endpoint, ".r2.cloudflarestorage.com"):
		return providerR2
	case p.KeyID == "", strings.HasPrefix(p.KeyID, "AKIA"), strings.HasPrefix(p.KeyID, "ASIA"):
		return providerAWS
	case cfg.Region == "auto" || isHex(p.KeyID, 32):
		return providerR2
	}
	return providerS3Compatible
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// iniLines calls fn for every key = value line with its section header; comments and blank lines
// are skipped. Callers keep only the keys they need, so secret values are dropped as they are read.
func iniLines(r io.Reader, fn func(section, key, val string)) {
	section := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			fn(section, "", "")
			continue
		}
		if key, val, ok := strings.Cut(line, "="); ok && section != "" {
			fn(section, strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val))
		}
	}
}

// parseCredentials reads an INI shared credentials file. Secret values are skipped as they are read.
func parseCredentials(r io.Reader) []credentialProfile {
	var out []credentialProfile
	iniLines(r, func(section, key, val string) {
		switch key {
		case "":
			out = append(out, credentialProfile{Name: section})
		case "aws_access_key_id":
			out[len(out)-1].KeyID = val
		case "aws_session_token", "aws_security_token":
			out[len(out)-1].Temporary = true
		}
	})
	return out
}

// parseConfig reads the region and endpoint of every profile in an INI shared config file, whose
// sections are [default] and [profile name].
func parseConfig(r io.Reader) map[string]profileConfig {
	out := map[string]profileConfig{}
	iniLines(r, func(section, key, val string) {
		name, ok := strings.CutPrefix(section, "profile ")
		if !ok && section != "default" {
			return
		}
		name = strings.TrimSpace(name)
		c := out[name]
		switch key {
		case "region":
			c.Region = val
		case "endpoint_url":
			c.Endpoint = val
		default:
			return
		}
		out[name] = c
	})
	return out
}

// providers maps every profile with a key in the credentials file to the service that issued it.
func providers(profiles []credentialProfile, cfg map[string]profileConfig) map[string]provider {
	out := map[string]provider{}
	for _, p := range profiles {
		out[p.Name] = providerOf(p, cfg[p.Name])
	}
	return out
}

// credentialFindings flags long-lived keys stored in plain text, worse when other users can read them.
// Each names the key id by its redacted hint and, with key, by the fingerprint local-secrets gives
// its copies; an AWS key id also names the account it belongs to, read offline from the id.
func credentialFindings(path string, mode fs.FileMode, profiles []credentialProfile, cfg map[string]profileConfig, key *fingerprint.Key) []finding.Finding {
	var out []finding.Finding
	for _, p := range profiles {
		if p.KeyID == "" || p.Temporary {
			continue
		}
		f := localKeyFinding(path, mode, p, providerOf(p, cfg[p.Name]))
		if key != nil {
			f.Evidence["fingerprint"] = key.Of(p.KeyID)
		}
		if acct, ok := attribution.AWSAccountFromKeyID(p.KeyID); ok && f.Resource.Type == "aws_local_credentials" {
			f.Evidence["aws_account"] = acct
		}
		if mode.Perm()&0o077 != 0 {
			f.Severity = finding.SevHigh
			f.Title += " and readable by other users"
			f.Remediation.Summary = "Run `chmod 600` on the file now. " + f.Remediation.Summary
			f.Remediation.URL = urlConfigFiles
		}
		out = append(out, f)
	}
	return out
}

func localKeyFinding(path string, mode fs.FileMode, p credentialProfile, by provider) finding.Finding {
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
	switch by {
	case providerR2:
		f.Resource.Type = "r2_local_credentials"
		f.Title = fmt.Sprintf("Cloudflare R2 API token for profile %q stored in plain text", p.Name)
		f.Remediation = finding.Remediation{
			Summary: "This is an R2 token, not an AWS key. In Cloudflare R2 > Manage API Tokens, scope it to the buckets it needs with the least permission (Object Read only when that is enough) and a TTL, roll it if it was ever shared, and keep the file at mode 0600.",
			URL:     urlR2Tokens,
		}
	case providerS3Compatible:
		f.Resource.Type = "s3_local_credentials"
		f.Title = fmt.Sprintf("S3-compatible access key (not AWS) for profile %q stored in plain text", p.Name)
		f.Remediation = finding.Remediation{
			Summary: "The key id has no AKIA/ASIA prefix, so another S3-compatible service issued it. Scope it to the buckets it needs at that provider, rotate it if it was ever shared, and keep the file at mode 0600.",
			URL:     urlConfigFiles,
		}
	}
	return f
}

// scanLocalFiles returns the findings for plain-text keys in the shared credentials file, for
// Inventory to emit, and who issued each profile's key, so profiles that are not AWS skip the STS
// and IAM calls.
func (c *Connector) scanLocalFiles(emit connector.Emitter) ([]finding.Finding, map[string]provider) {
	cfg := map[string]profileConfig{}
	if path := c.ConfigFile(); path != "" {
		if fh, err := os.Open(path); err == nil {
			cfg = parseConfig(fh)
			fh.Close()
		} else if !os.IsNotExist(err) {
			emit.Log(fmt.Sprintf("config file %s: %v", path, err))
		}
	}
	path := c.CredentialsFile()
	if path == "" {
		return nil, nil
	}
	fh, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			emit.Log(fmt.Sprintf("credentials file %s: %v", path, err))
		}
		return nil, nil
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		emit.Log(fmt.Sprintf("credentials file %s: %v", path, err))
		return nil, nil
	}
	profiles := parseCredentials(fh)
	var key *fingerprint.Key
	if c.Fingerprint != nil {
		if k, ok := c.Fingerprint(); ok {
			key = &k
		}
	}
	return credentialFindings(path, st.Mode(), profiles, cfg, key), providers(profiles, cfg)
}
