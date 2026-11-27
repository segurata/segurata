package attribution

import (
	"cmp"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

var awsKeyID = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z2-7]{16}\b`)

// AWSAccountFromKeyID decodes the account an access key id carries: the first 6 base32-decoded
// bytes after the prefix, big-endian, masked with 0x7fffffffff80 and shifted right by 7 (Tal
// Be'ery, 2023; https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/). Ids of the
// older format, fifth character I or J, carry none.
func AWSAccountFromKeyID(id string) (string, bool) {
	if len(id) != 20 || !awsKeyID.MatchString(id) || id[4] == 'I' || id[4] == 'J' {
		return "", false
	}
	raw, err := base32.StdEncoding.DecodeString(id[4:])
	if err != nil || len(raw) < 6 {
		return "", false
	}
	var b [8]byte
	copy(b[2:], raw[:6])
	n := (binary.BigEndian.Uint64(b[:]) & 0x7fffffffff80) >> 7
	return fmt.Sprintf("%012d", n), true
}

var (
	slackHook      = regexp.MustCompile(`hooks\.slack\.com/(?:services|workflows|triggers)/(T[A-Z0-9]{6,})/`)
	googleClientID = regexp.MustCompile(`\b(\d{6,})-[a-z0-9]+\.apps\.googleusercontent\.com\b`)
)

// slackTeam is the workspace a webhook URL names; Slack tokens (xox…) carry none documented.
func slackTeam(s string) (string, bool) {
	if m := slackHook.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	return "", false
}

// gcpProjectOfClientID is the project number an OAuth client id starts with; API keys (AIza…)
// carry none.
func gcpProjectOfClientID(s string) (string, bool) {
	if m := googleClientID.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	return "", false
}

// FromValue reads the claims a secret's own value carries.
func FromValue(value string) Claims {
	var c Claims
	if id := awsKeyID.FindString(value); id != "" {
		c.AWSAccount, _ = AWSAccountFromKeyID(id)
	}
	c.SlackTeam, _ = slackTeam(value)
	c.GCPProject, _ = gcpProjectOfClientID(value)
	return c
}

var (
	gcpProjectID = []*regexp.Regexp{
		regexp.MustCompile(`"project_id"\s*:\s*"([a-z][a-z0-9-]{4,28}[a-z0-9])"`),                     // service-account key, client_secret.json, google-services.json
		regexp.MustCompile(`<key>PROJECT_ID</key>\s*<string>([a-z][a-z0-9-]{4,28}[a-z0-9])</string>`), // GoogleService-Info.plist
	}
	gcpProjectNumber = []*regexp.Regexp{
		regexp.MustCompile(`"project_number"\s*:\s*"(\d{6,})"`),                    // google-services.json
		regexp.MustCompile(`<key>GCM_SENDER_ID</key>\s*<string>(\d{6,})</string>`), // GoogleService-Info.plist: the sender id is the project number
	}
)

// FromContext reads the claims the text around a secret makes. A kind with two different values
// claims nothing: the file mixes accounts and cannot say which is the secret's.
func FromContext(text string) Claims {
	var c Claims
	c.AWSAccount = only(func(add func(string)) {
		for _, id := range awsKeyID.FindAllString(text, -1) {
			if a, ok := AWSAccountFromKeyID(id); ok {
				add(a)
			}
		}
	})
	c.GCPProject = only(func(add func(string)) {
		for _, re := range gcpProjectID {
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				add(m[1])
			}
		}
	})
	if c.GCPProject == "" {
		c.GCPProject = only(func(add func(string)) {
			for _, re := range append(gcpProjectNumber, googleClientID) {
				for _, m := range re.FindAllStringSubmatch(text, -1) {
					add(m[1])
				}
			}
		})
	}
	return c
}

// only is the one distinct value collect adds, "" for none or several.
func only(collect func(add func(string))) string {
	seen := ""
	several := false
	collect(func(v string) {
		switch {
		case seen == "":
			seen = v
		case v != seen:
			several = true
		}
	})
	if several {
		return ""
	}
	return seen
}

// Or fills the claims c lacks from o.
func (c Claims) Or(o Claims) Claims {
	return Claims{AWSAccount: cmp.Or(c.AWSAccount, o.AWSAccount), SlackTeam: cmp.Or(c.SlackTeam, o.SlackTeam),
		GCPProject: cmp.Or(c.GCPProject, o.GCPProject), GitHubLogin: cmp.Or(c.GitHubLogin, o.GitHubLogin), AuthorEmail: cmp.Or(c.AuthorEmail, o.AuthorEmail),
		SSHKey: cmp.Or(c.SSHKey, o.SSHKey)}
}

// NamesAccount reports whether a claim can make a verdict, unlike the commit author.
func (c Claims) NamesAccount() bool {
	return c.AWSAccount != "" || c.SlackTeam != "" || c.GCPProject != "" || c.GitHubLogin != "" || (c.SSHKey != "" && c.SSHKey != SSHKeyUnreadable)
}

// FromAccount reads the claims of a liveness Account, "<provider>:<id>"; providers attribution
// knows nothing of claim nothing.
func FromAccount(account string) Claims {
	kind, id, _ := strings.Cut(account, ":")
	switch {
	case id == "":
	case kind == "aws" && awsAccountID.MatchString(id):
		return Claims{AWSAccount: id}
	case kind == "slack":
		return Claims{SlackTeam: id}
	case kind == "github":
		return Claims{GitHubLogin: id}
	}
	return Claims{}
}

func (c Claims) Empty() bool { return c == Claims{} }

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
