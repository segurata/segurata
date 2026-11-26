package aws

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"

	"github.com/segurata/segurata/connectors/internal/awsfiles"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/fileacl"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
)

const awsKeyPrefixes = "AKIA|ASIA"

func credentialFindings(path string, mode *fs.FileMode, profiles []awsfiles.Profile, cfg map[string]awsfiles.Config, key *fingerprint.Key) []finding.Finding {
	var out []finding.Finding
	for _, p := range profiles {
		if p.KeyID == "" || p.Temporary {
			continue
		}
		f := localKeyFinding(path, p, awsfiles.ProviderOf(p, cfg[p.Name]))
		if mode != nil {
			f.Evidence["mode"] = fmt.Sprintf("%04o", mode.Perm())
		}
		if key != nil {
			f.Evidence["fingerprint"] = key.Of(p.KeyID)
		}
		if acct, ok := attribution.AWSAccountFromKeyID(p.KeyID); ok && f.Resource.Type == "aws_local_credentials" {
			f.Evidence["aws_account"] = acct
		}
		if mode != nil && fileacl.Exposed(*mode) {
			f.Severity = finding.SevHigh
			f.Title += " and readable by other users"
			f.Remediation.Summary = "Restrict the file to your account now: `" + connector.MakePrivateCommand(runtime.GOOS, path, false) + "`. " + f.Remediation.Summary
			f.Remediation.URL = urlConfigFiles
		}
		out = append(out, f)
	}
	return out
}

func localKeyFinding(path string, p awsfiles.Profile, by awsfiles.Provider) finding.Finding {
	f := finding.Finding{
		Account:  "local",
		Resource: finding.Resource{Type: "aws_local_credentials", ID: path + "#" + p.Name, Name: p.Name},
		Kind:     finding.KindExposure,
		Severity: finding.SevMedium,
		Title:    fmt.Sprintf("Long-lived AWS access key for profile %q stored in plain text", p.Name),
		Evidence: map[string]any{"file": path, "key_id": secretrisk.RedactID(awsKeyPrefixes, p.KeyID)},
		Remediation: finding.Remediation{
			Summary: "Switch the profile to IAM Identity Center (`aws configure sso`) and delete the key. Until then, keep the file accessible only to your account.",
			URL:     urlSSO,
		},
	}
	switch by {
	case awsfiles.R2:
		f.Resource.Type = "r2_local_credentials"
		f.Title = fmt.Sprintf("Cloudflare R2 API token for profile %q stored in plain text", p.Name)
		f.Remediation = finding.Remediation{
			Summary: "In Cloudflare R2 > Manage API Tokens, scope the token to the buckets it needs with the least permission and a TTL. Rotate it if it was ever shared and keep the file accessible only to your account.",
			URL:     urlR2Tokens,
		}
	case awsfiles.S3Compatible:
		f.Resource.Type = "s3_local_credentials"
		f.Title = fmt.Sprintf("S3-compatible access key (not AWS) for profile %q stored in plain text", p.Name)
		f.Remediation = finding.Remediation{
			Summary: "The key id has no AKIA/ASIA prefix. Scope it to the buckets it needs at its provider, rotate it if it was ever shared, and keep the file accessible only to your account.",
			URL:     urlConfigFiles,
		}
	}
	return f
}

// scanLocalFiles also says who issued each profile's key, so non-AWS profiles skip STS and IAM.
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
	mode, err := fileacl.Exposure(path)
	var access *fs.FileMode
	if err != nil {
		emit.Log(fmt.Sprintf("credentials file %s permissions: %v", path, err))
	} else {
		access = &mode
	}
	profiles := awsfiles.ParseCredentials(fh)
	var key *fingerprint.Key
	if c.Fingerprint != nil {
		if k, ok := c.Fingerprint(); ok {
			key = &k
		}
	}
	return credentialFindings(path, access, profiles, cfg, key), awsfiles.Providers(profiles, cfg)
}
