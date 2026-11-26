// Package awsfiles tells which service issued each key of the AWS CLI's shared files, which also
// carry Cloudflare R2 tokens and other S3-compatible keys STS and IAM know nothing about. Secret
// values are dropped as they are read.
package awsfiles

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Profile struct {
	Name      string
	KeyID     string
	Temporary bool // has a session token, so it expires on its own
}

type Config struct {
	Region   string
	Endpoint string // endpoint_url, set for S3-compatible services
}

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

// ProviderOf: an R2 key id is the 32-hex id of the R2 API token, used with region "auto" against
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

// iniLines calls fn for every section header (key "") and key = value line under it.
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

// parseConfig reads the [default] and [profile name] sections.
func parseConfig(r io.Reader) map[string]Config {
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

func Providers(profiles []Profile, cfg map[string]Config) map[string]Provider {
	out := map[string]Provider{}
	for _, p := range profiles {
		out[p.Name] = ProviderOf(p, cfg[p.Name])
	}
	return out
}

// CredentialsPath and ConfigPath are what the AWS CLI reads: the environment override, else
// ~/.aws/<name>.
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

// ReadConfig reads a missing file as an empty config.
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
	return parseConfig(fh), nil
}

func Issuers() map[string]Provider { return IssuersAt(CredentialsPath(), ConfigPath()) }

// IssuersAt leaves out profiles without a credentials section (SSO, roles), which are AWS.
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
