package aws

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/segurata/segurata/connectors/internal/awsfiles"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
)

// awsKeyPrefixes are the prefixes a key id hint shows (secretrisk.RedactID).
const awsKeyPrefixes = "AKIA|ASIA"

// credentialFindings flags long-lived keys stored in plain text, worse when other users can read them.
// Each names the key id by its redacted hint and, with key, by the fingerprint local-secrets gives
// its copies; an AWS key id also names the account it belongs to, read offline from the id.
func credentialFindings(path string, mode fs.FileMode, profiles []awsfiles.Profile, cfg map[string]awsfiles.Config, key *fingerprint.Key) []finding.Finding {
	var out []finding.Finding
	for _, p := range profiles {
		if p.KeyID == "" || p.Temporary {
			continue
		}
		f := localKeyFinding(path, mode, p, awsfiles.ProviderOf(p, cfg[p.Name]))
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

func localKeyFinding(path string, mode fs.FileMode, p awsfiles.Profile, by awsfiles.Provider) finding.Finding {
	f := finding.Finding{
		Account:  "local",
		Resource: finding.Resource{Type: "aws_local_credentials", ID: path + "#" + p.Name, Name: p.Name},
		Kind:     finding.KindExposure,
		Severity: finding.SevMedium,
		Title:    fmt.Sprintf("Long-lived AWS access key for profile %q stored in plain text", p.Name),
		Evidence: map[string]any{"file": path, "mode": fmt.Sprintf("%04o", mode.Perm()), "key_id": secretrisk.RedactID(awsKeyPrefixes, p.KeyID)},
		Remediation: finding.Remediation{
			Summary: "Switch the profile to IAM Identity Center (`aws configure sso`) and delete the key; until then keep the file at mode 0600.",
			URL:     urlSSO,
		},
	}
	switch by {
	case awsfiles.R2:
		f.Resource.Type = "r2_local_credentials"
		f.Title = fmt.Sprintf("Cloudflare R2 API token for profile %q stored in plain text", p.Name)
		f.Remediation = finding.Remediation{
			Summary: "This is an R2 token, not an AWS key. In Cloudflare R2 > Manage API Tokens, scope it to the buckets it needs with the least permission (Object Read only when that is enough) and a TTL, roll it if it was ever shared, and keep the file at mode 0600.",
			URL:     urlR2Tokens,
		}
	case awsfiles.S3Compatible:
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
func (c *Connector) scanLocalFiles(emit connector.Emitter) ([]finding.Finding, map[string]awsfiles.Provider) {
	cfg, err := awsfiles.ReadConfig(c.ConfigFile())
	if err != nil {
		emit.Log(fmt.Sprintf("config file %s: %v", c.ConfigFile(), err))
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
	profiles := awsfiles.ParseCredentials(fh)
	var key *fingerprint.Key
	if c.Fingerprint != nil {
		if k, ok := c.Fingerprint(); ok {
			key = &k
		}
	}
	return credentialFindings(path, st.Mode(), profiles, cfg, key), awsfiles.Providers(profiles, cfg)
}
