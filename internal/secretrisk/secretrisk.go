// Package secretrisk is the shared risk model for leaked secrets: what each secret type is, how
// much damage it can do (impact), how far it travelled (exposure), the resulting rotation
// priority, and where the provider lets you rotate it. The local-secrets connector uses it to set
// finding severity and the rotation ledger to set item priority, so both always agree.
package secretrisk

import (
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
)

// Evidence is the evidence a local-secrets finding carries. It never holds a secret value: at
// most a redacted hint (known prefix, last four characters of long keys, length) and an HMAC
// fingerprint that only this machine's key can reproduce.
type Evidence struct {
	// Claims are the account identifiers the value or its file names (aws_account, slack_team,
	// gcp_project) and a commit's author_email, derived at scan time: see internal/attribution.
	attribution.Claims

	Source      string `json:"source"`              // scan | gitleaks | name | ssh
	Kind        string `json:"kind"`                // config | repo | transcript | history | log
	Type        string `json:"type"`                // a key of the catalog, or a gitleaks rule id
	Redacted    string `json:"redacted"`            // e.g. "sk_live_…a1b2(107)"
	Path        string `json:"path"`                // ~-relative
	Line        int    `json:"line,omitempty"`      // 0 when the whole file is the secret
	Mode        string `json:"mode,omitempty"`      // effective octal permissions for other accounts, "" for git history
	FileMode    string `json:"file_mode,omitempty"` // the file's own mode, when parent folders close it
	Tracked     bool   `json:"tracked"`             // in a git-tracked file or in git history
	Remote      bool   `json:"remote,omitempty"`
	Bucket      string `json:"bucket"` // 0-git | 1-readable | 2-trail | 3-local | ok
	Fingerprint string `json:"fingerprint,omitempty"`
	Fix         string `json:"fix"` // docs/secrets.md#anchor
	Note        string `json:"note,omitempty"`
	Count       int    `json:"count"`
	Repo        string `json:"repo,omitempty"`   // gitleaks: repository
	Commit      string `json:"commit,omitempty"` // gitleaks: first commit seen
	Date        string `json:"date,omitempty"`   // gitleaks: date of that commit
	Public      bool   `json:"public,omitempty"` // not a secret on its own: anon or expired JWT, expired STS key, public OAuth client
	Encrypted   bool   `json:"encrypted,omitempty"`
	InDataDump  bool   `json:"in_data_dump,omitempty"` // gitleaks: inside a committed database dump
	// Origin is whose repository a committed copy sits in (OriginOwned, OriginThirdParty,
	// OriginForkUpstream); "" when unknown or not committed. See origin.go.
	Origin string `json:"origin,omitempty"`
	// Reused marks a copy in a third-party repository (or inherited from a fork's upstream) whose
	// value is also in one of the owner's own files: it is the owner's secret, so it counts.
	Reused bool `json:"reused,omitempty"`
	// Sample marks a value that reads like test data ("test", "fake", "1234", a run of one
	// character). It lowers the impact to noise only in a test, example or documentation path.
	Sample bool `json:"sample,omitempty"`
	// Liveness is what the provider said when the secret was tried against it, when the liveness
	// check is on and allowed to try it.
	Liveness *Liveness `json:"liveness,omitempty"`
}

// Impact is how much damage the secret can do in the wrong hands.
type Impact int

const (
	Noise Impact = iota // generic matches, mostly false positives: excluded from rotation
	Low
	Medium
	High
)

func (i Impact) String() string {
	return [...]string{"noise", "low", "medium", "high"}[i]
}

// Exposure is how far a copy of the secret travelled.
type Exposure int

const (
	Local  Exposure = iota // a file only this user can read, shell history, a log
	Shared                 // readable by other users, or in a local repository's history
	Remote                 // pushed to a remote, or sent to a model provider in a transcript
)

// Priority is the rotation urgency, P0 (now) to P3 (when convenient). Empty for noise.
type Priority string

const (
	P0 Priority = "P0"
	P1 Priority = "P1"
	P2 Priority = "P2"
	P3 Priority = "P3"
)

// priorities is impact × exposure. P0 means high impact that left this machine.
var priorities = map[Impact][3]Priority{
	//      Local Shared Remote
	Low:    {P3, P3, P2},
	Medium: {P3, P2, P1},
	High:   {P2, P1, P0},
}

// PriorityOf returns "" for noise.
func PriorityOf(i Impact, e Exposure) Priority {
	row, ok := priorities[i]
	if !ok {
		return ""
	}
	return row[e]
}

// Rank orders priorities, P0 first; noise last.
func (p Priority) Rank() int {
	if len(p) == 2 && p[0] == 'P' {
		return int(p[1] - '0')
	}
	return 9
}

// Lower is the next priority down, P3 staying P3; noise stays noise.
func (p Priority) Lower() Priority {
	if r := p.Rank(); r < 3 {
		return Priority("P" + string(rune('0'+r+1)))
	}
	return p
}

// SeverityOf maps a priority to a finding severity.
func SeverityOf(p Priority) finding.Severity {
	switch p {
	case P0:
		return finding.SevCritical
	case P1:
		return finding.SevHigh
	case P2:
		return finding.SevMedium
	case P3:
		return finding.SevLow
	}
	return finding.SevInfo
}

// Type describes one kind of secret.
type Type struct {
	Service   string // provider, used to group and filter
	Label     string // plain words, used in reasons and titles
	Impact    Impact
	RotateURL string // provider page where this kind of secret is revoked or rotated
}

// Provider console pages where each kind of secret is revoked or reissued, checked against each
// provider's documentation on 2026-11-23. A type without a stable, account-independent page (npm
// tokens live under /settings/<user>/tokens, Shopify per store) has none rather than a guess.
const (
	urlStripeKeys     = "https://dashboard.stripe.com/apikeys"
	urlStripeWebhooks = "https://dashboard.stripe.com/webhooks"
	urlAWS            = "https://console.aws.amazon.com/iam/home#/security_credentials"
	urlGCPServiceAcct = "https://console.cloud.google.com/iam-admin/serviceaccounts"
	urlGCPCredentials = "https://console.cloud.google.com/apis/credentials"
	urlGoogleClients  = "https://console.cloud.google.com/auth/clients"
	urlGoogleAccess   = "https://myaccount.google.com/linkedapps"
	urlGitHubTokens   = "https://github.com/settings/tokens"
	urlGitHubFineGr   = "https://github.com/settings/personal-access-tokens"
	urlGitHubKeys     = "https://github.com/settings/keys"
	urlGitLab         = "https://gitlab.com/-/user_settings/personal_access_tokens"
	urlCloudflare     = "https://dash.cloudflare.com/profile/api-tokens"
	urlAnthropic      = "https://platform.claude.com/settings/keys"
	urlOpenAI         = "https://platform.openai.com/api-keys"
	urlXAI            = "https://console.x.ai/team/default/api-keys"
	urlOpenRouter     = "https://openrouter.ai/settings/keys"
	urlNotion         = "https://app.notion.com/developers/connections"
	urlSlack          = "https://api.slack.com/apps"
	urlSendGrid       = "https://app.sendgrid.com/settings/api_keys"
	urlTelegram       = "https://t.me/BotFather"
	urlSentryTokens   = "https://sentry.io/settings/account/api/auth-tokens/"
	urlHuggingFace    = "https://huggingface.co/settings/tokens"
	urlGroq           = "https://console.groq.com/keys"
	urlSupabase       = "https://supabase.com/dashboard/account/tokens"
	urlDigitalOcean   = "https://cloud.digitalocean.com/account/api/tokens"
	urlPyPI           = "https://pypi.org/manage/account/"
	urlRubyGems       = "https://rubygems.org/profile/api_keys"
	urlReplicate      = "https://replicate.com/account/api-tokens"
	urlPerplexity     = "https://console.perplexity.ai/project/keys"
	urlElevenLabs     = "https://elevenlabs.io/app/settings/api-keys"
	urlLinear         = "https://linear.app/settings/account/security"
	urlOnePassword    = "https://start.1password.com/developer-tools"
	urlTavily         = "https://app.tavily.com/home"
)

// catalog maps every secret type the connector emits (its own pattern names and the gitleaks
// rules it maps onto them) to its risk. Unknown types are medium impact, see Lookup.
var catalog = map[string]Type{
	// High: money, infrastructure, source code, identity.
	"stripe-live":                {"stripe", "Stripe live secret key", High, urlStripeKeys},
	"aws-access-key-id":          {"aws", "AWS access key", High, urlAWS},
	"aws-secret-key":             {"aws", "AWS secret access key", High, urlAWS},
	"gcp-service-account":        {"gcp", "GCP service account key", High, urlGCPServiceAcct},
	"private-key":                {"private-key", "Private key", High, ""},
	"ssh-key":                    {"ssh", "SSH private key without a passphrase", High, urlGitHubKeys},
	"github":                     {"github", "GitHub token", High, urlGitHubTokens},
	"github-pat":                 {"github", "GitHub fine-grained token", High, urlGitHubFineGr},
	"gitlab":                     {"gitlab", "GitLab token", High, urlGitLab},
	"google-refresh-token":       {"google", "Google OAuth refresh token", High, urlGoogleAccess},
	"google-oauth-client-secret": {"google", "Google OAuth client secret", High, urlGoogleClients},
	"cloudflare-token":           {"cloudflare", "Cloudflare API token", High, urlCloudflare},
	"digitalocean":               {"digitalocean", "DigitalOcean token", High, urlDigitalOcean},
	"supabase":                   {"supabase", "Supabase access or secret key", High, urlSupabase},
	"onepassword-service":        {"1password", "1Password service account token", High, urlOnePassword},
	"kube-client-key":            {"kubernetes", "Kubernetes client key", High, ""},
	"age-secret-key":             {"age", "age secret key", High, ""},
	"rails-master-key":           {"rails", "Rails master key", High, ""},
	"keystore":                   {"keystore", "Keystore or certificate bundle", High, ""},

	// Medium: paid APIs and messaging, abusable but bounded.
	"anthropic":            {"anthropic", "Anthropic API key", Medium, urlAnthropic},
	"openai-project":       {"openai", "OpenAI project key", Medium, urlOpenAI},
	"openai-service":       {"openai", "OpenAI service account or admin key", Medium, urlOpenAI},
	"openai-legacy":        {"openai", "OpenAI API key", Medium, urlOpenAI},
	"sk-generic":           {"unknown", "API key with an sk- prefix (provider unknown)", Medium, ""},
	"xai":                  {"xai", "xAI API key", Medium, urlXAI},
	"openrouter":           {"openrouter", "OpenRouter API key", Medium, urlOpenRouter},
	"groq":                 {"groq", "Groq API key", Medium, urlGroq},
	"huggingface":          {"huggingface", "Hugging Face token", Medium, urlHuggingFace},
	"replicate":            {"replicate", "Replicate token", Medium, urlReplicate},
	"perplexity":           {"perplexity", "Perplexity API key", Medium, urlPerplexity},
	"tavily":               {"tavily", "Tavily API key", Medium, urlTavily},
	"elevenlabs":           {"elevenlabs", "ElevenLabs API key", Medium, urlElevenLabs},
	"notion":               {"notion", "Notion integration secret", Medium, urlNotion},
	"slack-token":          {"slack", "Slack token", Medium, urlSlack},
	"slack-webhook":        {"slack", "Slack incoming webhook", Medium, urlSlack},
	"sendgrid":             {"sendgrid", "SendGrid API key", Medium, urlSendGrid},
	"npm-token":            {"npm", "npm token", Medium, ""},
	"npm-authtoken":        {"npm", "npm auth token", Medium, ""},
	"pypi-token":           {"pypi", "PyPI token", Medium, urlPyPI},
	"rubygems":             {"rubygems", "RubyGems API key", Medium, urlRubyGems},
	"telegram-bot":         {"telegram", "Telegram bot token", Medium, urlTelegram},
	"stripe-webhook":       {"stripe", "Stripe webhook signing secret", Medium, urlStripeWebhooks},
	"linear":               {"linear", "Linear API key", Medium, urlLinear},
	"sentry-token":         {"sentry", "Sentry auth token", Medium, urlSentryTokens},
	"shopify":              {"shopify", "Shopify access token", Medium, ""},
	"docker-auth":          {"docker", "Docker registry credentials", Medium, ""},
	"netrc-password":       {"netrc", "Password in ~/.netrc", Medium, ""},
	"url-credentials":      {"url", "Password inside a URL", Medium, ""},
	"url-token-param":      {"url", "Token in a URL query string", Medium, ""},
	"oauth-refresh-token":  {"oauth", "OAuth refresh token (provider unknown)", Medium, ""},
	"oauth-client-secret":  {"oauth", "OAuth client secret (provider unknown)", Medium, ""},
	"gcloud-credential-db": {"google", "gcloud credential store", Medium, urlGoogleAccess},
	"curl-auth-header":     {"unknown", "Credential in a curl Authorization header", Medium, ""},
	"curl-auth-user":       {"unknown", "Credential in a curl --user argument", Medium, ""},

	// Low: public by design or limited blast radius.
	"sentry-dsn":     {"sentry", "Sentry DSN", Low, ""},
	"google-api-key": {"google", "Google API key", Low, urlGCPCredentials},
	// A pre-signed URL carries a key id and a signature, never the secret key, and expires within
	// seven days (STS-signed ones within 36 hours).
	"aws-presigned-url": {"aws", "Pre-signed AWS URLs", Low, urlAWS},
	"stripe-test":       {"stripe", "Stripe test key", Low, urlStripeKeys},
	"jwt":               {"unknown", "JWT of unknown origin", Low, ""},

	// Noise: generic name=value matches, mostly configuration that is not secret.
	"assignment":      {"generic", "Generic secret-looking assignment", Noise, ""},
	"generic-api-key": {"generic", "Generic API key (gitleaks)", Noise, ""},
}

// Lookup returns the catalog entry, or a medium-impact entry named after the type: an unknown
// gitleaks rule still matched something specific.
func Lookup(typ string) Type {
	if t, ok := Known(typ); ok {
		return t
	}
	service := typ
	if i := strings.IndexByte(typ, '-'); i > 0 {
		service = typ[:i]
	}
	return Type{Service: service, Label: typ + " (gitleaks rule)", Impact: Medium}
}

// temporaryAWS is the entry for AWS key ids starting with ASIA: temporary STS credentials (from
// an assumed role or a pre-signed URL) that expire within 36 hours at most. A copy found later
// is almost always dead, so it is low impact instead of a long-lived AKIA key.
var temporaryAWS = Type{Service: "aws", Label: "Temporary AWS credential (STS, expires within 36 hours)", Impact: Low, RotateURL: urlAWS}

// hexLookalike is for gitleaks rules that also accept any 40-character hex string (Sourcegraph's
// legacy token format). Without the service's own prefix the match is most often a SHA-1, a git
// object id or a hash column in a database dump: 2,013 such matches in one SQL backup on
// 2026-11-24. Real current tokens carry the prefix and keep the catalog impact. Among gitleaks
// 8.30's rules only this one takes a bare hex value with no keyword: facebook-secret and
// codecov-access-token also capture 32 hex characters, but only next to their provider's name.
var hexLookalike = Type{Service: "generic", Label: "40-character hex string (a hash more often than a token)", Impact: Noise}

// TypeFor is Lookup refined by the redacted hint, for types whose prefix changes what they are.
func TypeFor(typ, redacted string) Type {
	if strings.HasPrefix(typ, "aws-access") && strings.HasPrefix(redacted, "ASIA") {
		return temporaryAWS
	}
	if typ == "sourcegraph-access-token" && !strings.HasPrefix(redacted, "sgp_") {
		return hexLookalike
	}
	return Lookup(typ)
}

// Known returns the catalog entry and whether the type is in the catalog.
func Known(typ string) (Type, bool) {
	t, ok := catalog[typ]
	return t, ok
}

// ImpactOf is the type's impact, adjusted by where the copy is: noise for values that are not
// usable secrets and for other people's repositories, by host for URL credentials (url.go), and
// one level lower in test, example, documentation and vendored paths (paths.go).
func ImpactOf(e Evidence) Impact {
	if e.Public || e.Encrypted || dumpNoise(e) || NotOwners(e.Origin, e.Reused) {
		return Noise
	}
	i := TypeFor(e.Type, e.Redacted).Impact
	if urlTypes[e.Type] {
		i = hostImpact(URLHost(e.Note), i)
	}
	if e.Kind != "repo" {
		return i
	}
	switch RoleOf(e.Path) {
	case RoleNone:
		return i
	case RoleGenerated:
		return Noise
	}
	if e.Sample || i == Noise {
		return Noise
	}
	return i - 1
}

// Spot is how far one location exposed the secret, with a short label for tables and the plain
// words used in reasons.
type Spot struct {
	Level  Exposure
	Label  string
	Phrase string
}

// Where locates one copy of a secret: in git (pushed or not), in a transcript, in a readable
// file, in a trail on disk, or in a closed local file.
func Where(source, kind, mode string, tracked, remote bool) Spot {
	switch {
	case tracked && remote:
		return Spot{Remote, "git+remote", "committed to a git repository with a remote, so every clone has it"}
	case kind == "transcript":
		return Spot{Remote, "transcript", "pasted into an agent transcript, so it reached the model provider"}
	case tracked:
		return Spot{Shared, "git", "committed to a local git repository (no remote yet)"}
	case groupReadable(mode):
		return Spot{Shared, "readable", "in a file other users of this machine can read"}
	case kind == "history":
		return Spot{Local, "history", "in shell history"}
	case kind == "log":
		return Spot{Local, "log", "in a log file"}
	}
	return Spot{Local, "local", "in a local file only you can read"}
}

// WhereEvidence is Where for one finding, or the upstream's spot for a copy in a repository that
// is not the owner's.
func WhereEvidence(e Evidence) Spot {
	if s, ok := UpstreamSpot(e.Origin, e.Reused); ok {
		return s
	}
	return Where(e.Source, e.Kind, e.Mode, e.Tracked, e.Remote)
}

func groupReadable(mode string) bool {
	m, err := strconv.ParseUint(mode, 8, 32)
	return err == nil && m&0o044 != 0
}

// Reason is the plain-words line behind a priority: what it is and how far it went.
func Reason(t Type, s Spot) string { return t.Label + "; " + s.Phrase }

// ShellRC are the shell start-up files: an `export NAME=value` there reaches every process, and
// docs/secrets.md moves such values to the Keychain.
var ShellRC = []string{".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"}

// IsShellRC reports whether path (~/ or absolute) names one of ShellRC.
func IsShellRC(path string) bool {
	i := strings.LastIndexByte(path, '/')
	for _, f := range ShellRC {
		if path[i+1:] == f {
			return true
		}
	}
	return false
}

// passwordLike types hold human-chosen secrets: their hint shows only the length.
var passwordLike = map[string]bool{
	"assignment": true, "url-credentials": true, "netrc-password": true, "docker-auth": true,
	"url-token-param": true, "curl-auth-user": true,
}

// Redact returns the hint a finding may show: the known prefix (from the "|"-separated list
// prefixes), the last four characters of a long random key (what provider consoles show to tell
// keys apart) and the length. Never more.
func Redact(typ, prefixes, secret string) string {
	if secret == "" {
		return ""
	}
	h := Hint{Prefix: KnownPrefix(prefixes, secret), Len: len(secret)}
	if !passwordLike[typ] && len(secret) >= 24 && len(secret)-len(h.Prefix) >= 20 {
		h.Tail = secret[len(secret)-tailLen:]
	}
	return h.String()
}

// RedactID is the hint of an identifier that is not itself secret but names one (an AWS access
// key id): the known prefix, the last four characters and the length, "AKIA…WXYZ(20)".
func RedactID(prefixes, id string) string {
	if id == "" {
		return ""
	}
	h := Hint{Prefix: KnownPrefix(prefixes, id), Len: len(id)}
	if len(id)-len(h.Prefix) > tailLen {
		h.Tail = id[len(id)-tailLen:]
	}
	return h.String()
}

// KnownPrefix is the prefix from the "|"-separated list that secret starts with, or "".
func KnownPrefix(prefixes, secret string) string {
	for _, p := range strings.Split(prefixes, "|") {
		if p != "" && strings.HasPrefix(secret, p) {
			return p
		}
	}
	return ""
}

// tailLen is how many of a value's last characters a hint shows.
const tailLen = 4

// unknownLen stands for the length in a hint made from what a provider shows of a key when the
// provider does not give the length: "sk-or-v1-27e…d4d(?)".
const unknownLen = "?"

// Hint is a redacted hint read back: what Redact showed of a value. Len is 0 when the hint's
// source did not give the length.
type Hint struct {
	Prefix, Tail string
	Len          int
}

// String writes the hint in Redact's format: prefix, "…", tail, and the length in parentheses, or
// "(?)" when it is not known.
func (h Hint) String() string {
	n := unknownLen
	if h.Len > 0 {
		n = strconv.Itoa(h.Len)
	}
	return h.Prefix + "…" + h.Tail + "(" + n + ")"
}

// ParseHint reads a hint made by Redact, RedactID or Masked. ok is false for hints that do not
// describe one value on one line ("PEM", a whole file, an empty hint).
func ParseHint(redacted string) (h Hint, ok bool) {
	i, j := strings.Index(redacted, "…"), strings.LastIndexByte(redacted, '(')
	if i < 0 || j < i || !strings.HasSuffix(redacted, ")") {
		return Hint{}, false
	}
	h = Hint{Prefix: redacted[:i], Tail: redacted[i+len("…") : j]}
	if num := redacted[j+1 : len(redacted)-1]; num == unknownLen {
		return h, h.Prefix != "" || h.Tail != ""
	} else if n, err := strconv.Atoi(num); err == nil && n > 0 {
		h.Len = n
		return h, len(h.Prefix)+len(h.Tail) <= n
	}
	return Hint{}, false
}

// Masked turns what a provider shows of a key into a hint in Redact's format, keeping every
// character the provider shows in front, at most the last four at the end, and the length n, or
// unknown when n is 0. It reads the masked forms providers use: OpenRouter's label
// "sk-or-v1-27e...d4d", Anthropic's partial_key_hint "sk-ant-api03-R2D...igAA", OpenAI's
// redacted_value "sk-proj-****…abcd" (stars) and an ellipsis. "" when the text masks nothing.
func Masked(masked string, n int) string {
	h, ok := parseMasked(masked)
	if !ok {
		return ""
	}
	if len(h.Tail) > tailLen {
		h.Tail = h.Tail[len(h.Tail)-tailLen:]
	}
	if n >= len(h.Prefix)+len(h.Tail) {
		h.Len = n
	}
	return h.String()
}

// ReadHint reads a hint in Redact's format or, failing that, a provider's masked form (see
// Masked), for code that meets both: findings written before every connector used Redact's format,
// a provider's raw value.
func ReadHint(s string) (Hint, bool) {
	if h, ok := ParseHint(s); ok {
		return h, true
	}
	return ParseHint(Masked(s, 0))
}

// parseMasked splits a provider's masked key at its mask: "...", "…" or a run of "*".
func parseMasked(s string) (Hint, bool) {
	for _, sep := range []string{"...", "…"} {
		if i := strings.Index(s, sep); i >= 0 {
			pre, tail := s[:i], s[i+len(sep):]
			h := Hint{Prefix: strings.TrimRight(pre, "*"), Tail: strings.TrimLeft(tail, "*")}
			return h, h.Prefix != "" || h.Tail != ""
		}
	}
	if i, j := strings.IndexByte(s, '*'), strings.LastIndexByte(s, '*'); i >= 0 {
		h := Hint{Prefix: s[:i], Tail: s[j+1:]}
		return h, h.Prefix != "" || h.Tail != ""
	}
	return Hint{}, false
}

// Agrees reports whether two hints can describe the same value: one prefix starts the other, one
// tail ends the other, and the lengths agree when both are known.
func (h Hint) Agrees(o Hint) bool {
	if h.Len > 0 && o.Len > 0 && h.Len != o.Len {
		return false
	}
	return (strings.HasPrefix(h.Prefix, o.Prefix) || strings.HasPrefix(o.Prefix, h.Prefix)) &&
		(strings.HasSuffix(h.Tail, o.Tail) || strings.HasSuffix(o.Tail, h.Tail))
}

// Fits reports whether value could be the one the hint describes. A hint without a length fits
// nothing: it cannot tell where a value ends.
func (h Hint) Fits(value string) bool {
	return h.Len > 0 && len(value) == h.Len && strings.HasPrefix(value, h.Prefix) && strings.HasSuffix(value, h.Tail)
}
