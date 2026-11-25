// Package awsfiles reads the AWS CLI's shared credentials and config files and tells, for each
// profile, which service issued its key: the same files also carry Cloudflare R2 tokens and keys
// for other S3-compatible services, which STS and IAM know nothing about. Secret values are
// dropped as they are read.
package awsfiles

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Profile is what is kept from one [section] of the credentials file: never the secret.
type Profile struct {
	Name      string
	KeyID     string
	Temporary bool // has a session token, so it expires on its own
}

// Config is what is kept from a profile in the shared config file.
type Config struct {
	Region   string
	Endpoint string // endpoint_url, set for S3-compatible services
}

// Provider says who issued the key a profile holds.
type Provider int

const (
	AWS Provider = iota
	R2
	S3Compatible
)

func (p Provider) String() string {
	switch p {
	case R2:
		return "a Cloudflare R2 token"
	case S3Compatible:
		return "an S3-compatible key"
	}
	return "AWS"
}

// ProviderOf tells an AWS profile from one pointed at Cloudflare R2 or another S3-compatible
// service. AWS access key ids start with AKIA (long-lived) or ASIA (temporary); an R2 access key
// id is the 32-hex-character id of the R2 API token, used with region "auto" against
// <account>.r2.cloudflarestorage.com. A profile with no key (SSO, a role) is AWS.
func ProviderOf(p Profile, cfg Config) Provider {
	switch {
	case strings.Contains(cfg.Endpoint, ".r2.cloudflarestorage.com"):
		return R2
	case p.KeyID == "", strings.HasPrefix(p.KeyID, "AKIA"), strings.HasPrefix(p.KeyID, "ASIA"):
		return AWS
	case cfg.Region == "auto" || isHex(p.KeyID, 32):
		return R2
	}
	return S3Compatible
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

// ParseCredentials reads an INI shared credentials file.
func ParseCredentials(r io.Reader) []Profile {
	var out []Profile
	iniLines(r, func(section, key, val string) {
		switch key {
		case "":
			out = append(out, Profile{Name: section})
		case "aws_access_key_id":
			out[len(out)-1].KeyID = val
		case "aws_session_token", "aws_security_token":
			out[len(out)-1].Temporary = true
		}
	})
	return out
}

// ParseConfig reads the region and endpoint of every profile in an INI shared config file, whose
// sections are [default] and [profile name].
func ParseConfig(r io.Reader) map[string]Config {
	out := map[string]Config{}
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

// Providers maps every profile with a section in the credentials file to the service that issued
// its key.
func Providers(profiles []Profile, cfg map[string]Config) map[string]Provider {
	out := map[string]Provider{}
	for _, p := range profiles {
		out[p.Name] = ProviderOf(p, cfg[p.Name])
	}
	return out
}

// CredentialsPath and ConfigPath are the paths the AWS CLI reads: the environment override, else
// ~/.aws/<name>; "" when there is no home directory.
func CredentialsPath() string { return sharedFile("AWS_SHARED_CREDENTIALS_FILE", "credentials") }

func ConfigPath() string { return sharedFile("AWS_CONFIG_FILE", "config") }

func sharedFile(env, name string) string {
	if p := os.Getenv(env); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aws", name)
}

// ReadConfig parses the config file at path; a missing file is an empty config.
func ReadConfig(path string) (map[string]Config, error) {
	if path == "" {
		return map[string]Config{}, nil
	}
	fh, err := os.Open(path)
	if os.IsNotExist(err) {
		return map[string]Config{}, nil
	}
	if err != nil {
		return map[string]Config{}, err
	}
	defer fh.Close()
	return ParseConfig(fh), nil
}

// Issuers says who issued each profile's key, from the shared files at the paths the AWS CLI
// reads.
func Issuers() map[string]Provider { return IssuersAt(CredentialsPath(), ConfigPath()) }

// IssuersAt reads the credentials and config files at the given paths. Profiles absent from the
// map (SSO, roles, an unreadable file) are AWS.
func IssuersAt(credentials, config string) map[string]Provider {
	if credentials == "" {
		return nil
	}
	fh, err := os.Open(credentials)
	if err != nil {
		return nil
	}
	defer fh.Close()
	cfg, _ := ReadConfig(config)
	return Providers(ParseCredentials(fh), cfg)
}
