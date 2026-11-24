package attribution

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// awsKeyID is an AWS access key id: a four-letter prefix (AKIA long-term, ASIA temporary) and 16
// base32 characters.
var awsKeyID = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z2-7]{16}\b`)

// AWSAccountFromKeyID decodes the AWS account id an access key id carries, offline: base32-decode
// the 16 characters after the four-letter prefix, read the first 6 bytes as a big-endian 48-bit
// integer, mask it with 0x7fffffffff80 and shift it right by 7 bits. Technique published by Tal
// Be'ery ("A short note on AWS KEY ID", 2023), reproduced at
// https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/; AKIASP2TPHJSQH3FJXYZ decodes
// to 171436882533, the example of the aws_account_id_from_key_id crate. Key ids of the older
// format, whose fifth character is I or J, do not carry the account: ok is false for them, and for
// anything that is not a key id.
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
	// slackHook is an incoming webhook or workflow trigger URL, whose first path element is the
	// workspace (team) id.
	slackHook = regexp.MustCompile(`hooks\.slack\.com/(?:services|workflows|triggers)/(T[A-Z0-9]{6,})/`)
	// googleClientID is an OAuth client id: the GCP project number, a dash, a random label.
	googleClientID = regexp.MustCompile(`\b(\d{6,})-[a-z0-9]+\.apps\.googleusercontent\.com\b`)
)

// SlackTeam is the workspace id (T…) a Slack webhook URL names. Slack tokens (xox…) carry none
// that is documented.
func SlackTeam(s string) (string, bool) {
	if m := slackHook.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	return "", false
}

// GCPProjectNumber is the project number a Google OAuth client id
// (<number>-<label>.apps.googleusercontent.com) starts with. API keys (AIza…) carry no project:
// only the file around them can tell (FromContext).
func GCPProjectNumber(s string) (string, bool) {
	if m := googleClientID.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	return "", false
}

// FromValue reads the claims a secret's own value carries: the AWS account of an access key id
// (alone, or inside a pre-signed URL), the Slack workspace of a webhook, the GCP project of an
// OAuth client id.
func FromValue(value string) Claims {
	var c Claims
	if id := awsKeyID.FindString(value); id != "" {
		c.AWSAccount, _ = AWSAccountFromKeyID(id)
	}
	c.SlackTeam, _ = SlackTeam(value)
	c.GCPProject, _ = GCPProjectNumber(value)
	return c
}

// Context patterns: what a credentials file says about whose the secret next to it is.
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

// FromContext reads the claims the text around a secret makes: the AWS account of the access key
// id next to a secret access key, the GCP project of a credentials file (project_id,
// project_number, an OAuth client id). A kind with two different values in the text claims
// nothing: the file mixes accounts, so it cannot say which one the secret belongs to.
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

// only is the one distinct value collect adds, or "" for none or several.
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

// Or fills the claims c lacks from o: a value's own claims win over its context's.
func (c Claims) Or(o Claims) Claims {
	pick := func(a, b string) string {
		if a != "" {
			return a
		}
		return b
	}
	return Claims{AWSAccount: pick(c.AWSAccount, o.AWSAccount), SlackTeam: pick(c.SlackTeam, o.SlackTeam),
		GCPProject: pick(c.GCPProject, o.GCPProject), AuthorEmail: pick(c.AuthorEmail, o.AuthorEmail)}
}

// Empty reports whether no claim is set.
func (c Claims) Empty() bool { return c == Claims{} }

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
