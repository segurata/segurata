package localsecrets

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/secretrisk"
)

// pattern is one secret shape. src runs in both ripgrep and RE2; group is the submatch holding
// the secret; prefix lists ("|") the prefixes a hint may show; files restricts it to paths.
type pattern struct {
	typ    string
	src    string
	prefix string
	group  int
	files  *regexp.Regexp
	re     *regexp.Regexp // src anchored to the whole match
}

// privateKeyType matches the key body in escaped "\n" form (JSON, transcripts) or the header line
// alone, whose body is then read from the file.
const privateKeyType = "private-key"

// Nothing in an AWS secret access key says AWS: the name it is assigned to does, or the key id
// beside it.
const (
	awsSecretType = "aws-secret-key"
	awsSecretBody = `[A-Za-z0-9/+=]{40}`
	awsSecretName = `[A-Za-z0-9_.-]*secret[_-]?access[_-]?key`
)

var (
	awsSecretValue = regexp.MustCompile(`^` + awsSecretBody + `$`)
	hexOnly        = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	secretishName  = regexp.MustCompile(`(?i)secret`)
	awsSecretNamed = regexp.MustCompile(`(?i)^` + awsSecretName + `$`)
)

// awsSecretShaped: a 40-hex commit hash fits the alphabet; a real key is all hex with odds of
// about 10^-19.
func awsSecretShaped(v string) bool { return awsSecretValue.MatchString(v) && !hexOnly.MatchString(v) }

// awsSecretNearKeyID judges a value written near a long-term key id: a secret-ish name and the
// shape. Names holding secret_access_key need no key id (the aws-secret-key pattern).
func awsSecretNearKeyID(name, value string) bool {
	return secretishName.MatchString(name) && awsSecretShaped(value)
}

var awsSecretKey = specificByType(awsSecretType)

func specificByType(typ string) *pattern {
	for i := range specific {
		if specific[i].typ == typ {
			return &specific[i]
		}
	}
	return nil
}

// specific patterns apply everywhere, trails included.
var specific = compile([]pattern{
	{typ: "anthropic", src: `sk-ant-[A-Za-z0-9_-]{32,}`, prefix: "sk-ant-"},
	{typ: "openrouter", src: `sk-or-[A-Za-z0-9_-]{32,}`, prefix: "sk-or-"},
	{typ: "openai-project", src: `sk-proj-[A-Za-z0-9_-]{40,}`, prefix: "sk-proj-"},
	{typ: "openai-service", src: `sk-(?:svcacct|admin)-[A-Za-z0-9_-]{40,}`, prefix: "sk-svcacct-|sk-admin-"},
	{typ: "openai-legacy", src: `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`, prefix: "sk-"},
	{typ: "sk-generic", src: `\bsk-[A-Za-z0-9]{32,64}\b`, prefix: "sk-"},
	{typ: "xai", src: `\bxai-[A-Za-z0-9]{40,}`, prefix: "xai-"},
	{typ: "groq", src: `\bgsk_[A-Za-z0-9]{48,}`, prefix: "gsk_"},
	{typ: "huggingface", src: `\bhf_[A-Za-z0-9]{34,}`, prefix: "hf_"},
	{typ: "replicate", src: `\br8_[A-Za-z0-9]{37}\b`, prefix: "r8_"},
	{typ: "perplexity", src: `\bpplx-[A-Za-z0-9]{40,}`, prefix: "pplx-"},
	{typ: "tavily", src: `\btvly-[A-Za-z0-9-]{30,}`, prefix: "tvly-"},
	{typ: "elevenlabs", src: `\bsk_[a-f0-9]{48}\b`, prefix: "sk_"},
	{typ: "github", src: `\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}`, prefix: "ghp_|gho_|ghu_|ghs_|ghr_"},
	{typ: "github-pat", src: `\bgithub_pat_[A-Za-z0-9_]{60,}`, prefix: "github_pat_"},
	{typ: "gitlab", src: `\bglpat-[A-Za-z0-9_-]{20,}`, prefix: "glpat-"},
	// The value may end in "/" or "+": it ends outside its alphabet, not at a word boundary.
	{typ: awsSecretType, src: `(?i)` + awsSecretName + `["']?\s*[:=]\s*["']?(` + awsSecretBody + `)(?:[^A-Za-z0-9/+=]|$)`, group: 1},
	// SigV4 and SigV2 pre-signed URLs start before the bare key id, so they win the leftmost match.
	{typ: "aws-presigned-url", src: `(?:X-Amz-Credential|AWSAccessKeyId)=((?:AKIA|ASIA)[A-Z0-9]{16})\b`, prefix: "AKIA|ASIA", group: 1},
	{typ: "aws-access-key-id", src: `\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`, prefix: "AKIA|ASIA"},
	{typ: "google-api-key", src: `\bAIza[0-9A-Za-z_-]{35}`, prefix: "AIza"},
	{typ: "google-oauth-client-secret", src: `\bGOCSPX-[A-Za-z0-9_-]{28}`, prefix: "GOCSPX-"},
	{typ: "google-refresh-token", src: `\b1//0[A-Za-z0-9_-]{40,}`, prefix: "1//0"},
	{typ: "oauth-refresh-token", src: `"refresh_token"\s*:\s*"([^"\\]{20,})"`, group: 1},
	{typ: "oauth-client-secret", src: `"client_secret"\s*:\s*"([^"\\]{10,})"`, group: 1},
	{typ: "gcp-service-account", src: `"type"\s*:\s*"service_account"`},
	{typ: privateKeyType, src: `-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?:\\+[nr])+[A-Za-z0-9+/=]{4,})*`},
	{typ: "age-secret-key", src: `\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b`, prefix: "AGE-SECRET-KEY-1"},
	{typ: "stripe-live", src: `\b(?:sk|rk)_live_[A-Za-z0-9]{20,}`, prefix: "sk_live_|rk_live_"},
	{typ: "stripe-test", src: `\b(?:sk|rk)_test_[A-Za-z0-9]{20,}`, prefix: "sk_test_|rk_test_"},
	{typ: "stripe-webhook", src: `\bwhsec_[A-Za-z0-9+/=]{24,}`, prefix: "whsec_"},
	{typ: "slack-token", src: `\bxox[abposr]-[A-Za-z0-9-]{10,}`, prefix: "xoxa-|xoxb-|xoxp-|xoxo-|xoxs-|xoxr-"},
	{typ: "slack-webhook", src: `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}`, prefix: "https://hooks.slack.com/"},
	{typ: "cloudflare-token", src: `(?i)\b(?:cloudflare|cf)_?(?:api_?)?(?:token|key)\w*["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{37,40})\b`, group: 1},
	{typ: "notion", src: `\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b`, prefix: "secret_|ntn_"},
	{typ: "sentry-token", src: `\bsntry[su]_[A-Za-z0-9+/=_-]{50,}`, prefix: "sntrys_|sntryu_"},
	{typ: "sentry-dsn", src: `https://[a-f0-9]{32}@[a-z0-9.-]+\.sentry\.io/\d+`, prefix: "https://"},
	{typ: "linear", src: `\blin_api_[A-Za-z0-9]{40}\b`, prefix: "lin_api_"},
	{typ: "sendgrid", src: `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`, prefix: "SG."},
	{typ: "shopify", src: `\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b`, prefix: "shpat_|shpss_|shpca_|shppa_"},
	{typ: "digitalocean", src: `\bdo[por]_v1_[a-f0-9]{64}\b`, prefix: "dop_v1_|doo_v1_|dor_v1_"},
	{typ: "supabase", src: `\b(?:sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,})`, prefix: "sbp_|sb_secret_"},
	{typ: "onepassword-service", src: `\bops_[A-Za-z0-9_-]{50,}`, prefix: "ops_"},
	{typ: "npm-token", src: `\bnpm_[A-Za-z0-9]{36}\b`, prefix: "npm_"},
	{typ: "npm-authtoken", src: `_authToken\s*=\s*([^\s"']{16,})`, group: 1},
	{typ: "pypi-token", src: `\bpypi-[A-Za-z0-9_-]{50,}`, prefix: "pypi-"},
	{typ: "rubygems", src: `\brubygems_[a-f0-9]{48}\b`, prefix: "rubygems_"},
	{typ: "telegram-bot", src: `\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`},
	{typ: "docker-auth", src: `"auth"\s*:\s*"([A-Za-z0-9+/=]{16,})"`, group: 1},
	{typ: "kube-client-key", src: `client-key-data:\s*([A-Za-z0-9+/=]{40,})`, group: 1},
	{typ: "netrc-password", src: `\bpassword\s+(\S{6,})`, group: 1, files: regexp.MustCompile(`[._]netrc$`)},
	{typ: "url-credentials", src: `\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@"'<>]+:([^\s@/"'<>]{3,})@[A-Za-z0-9.-]+`, group: 1},
	{typ: "url-token-param", src: `(?i)[?&](?:access_token|token|api_key|apikey|key|secret|password)=([A-Za-z0-9._~%-]{16,})`, group: 1},
	{typ: "jwt", src: `\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, prefix: "eyJ"},
})

// assignment is the generic `NAME_TOKEN=value` shape, kept out of transcripts and logs. A value
// starting with "-" is left to the private-key pattern.
var assignment = compile([]pattern{{
	typ:   "assignment",
	group: 2,
	src:   "(?i)\\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|credentials?)[A-Za-z0-9_.-]*)[\"']?\\s*(?::|=>|=)\\s*[\"']?([^\\s\"'`,;#-][^\\s\"'`,;#]{7,})",
}})[0]

var withAssignment = append(append([]pattern{}, specific...), assignment)

func compile(ps []pattern) []pattern {
	for i := range ps {
		src := ps[i].src
		flags := ""
		if strings.HasPrefix(src, "(?i)") {
			src, flags = src[4:], "(?i)"
		}
		ps[i].re = regexp.MustCompile(flags + `^(?:` + src + `)$`)
	}
	return ps
}

// rgPattern puts ripgrep in ASCII mode: Unicode `\b` is several times slower.
func rgPattern(src string) string {
	if strings.HasPrefix(src, "(?i)") {
		return "(?i-u)" + src[4:]
	}
	return "(?-u)" + src
}

// classifyValue is the specific pattern a bare value matches whole.
func classifyValue(v string) *pattern {
	for i := range specific {
		p := &specific[i]
		if p.files == nil && p.group == 0 && p.typ != "gcp-service-account" && p.re.MatchString(v) {
			return p
		}
	}
	return nil
}

var placeholder = regexp.MustCompile(`(?i)abcdefgh|123456789|x{5,}|0{8,}|\.{3}|…|\*{3,}|example|your[_-]|placeholder|dummy|redacted|changeme|replace|<[^>]*>|\$\{|\$\(|%s|\{\{`)

var (
	notSecretValue  = regexp.MustCompile(`(?i)^(true|false|null|none|nil)$|^[a-z_]+$|^\d+$|^(https?:|/|\./|~)`)
	notSecretName   = regexp.MustCompile(`(?i)tokens$|_(url|uri|path|file|dir|ttl|type|count|length|expires(_at|_in)?)$`)
	defaultPassword = regexp.MustCompile(`(?i)^(pass(word)?|postgres|secret|root|admin|test|user|changeme|mysql|redis|guest)$`)
)

// minEntropyOf: short random bodies score low, so a flat 3.2 dropped 3 in 100 AWS key ids. Under
// 28 characters the floor is log2(n) - 1.5, which still rejects four letters repeated (entropy 2).
func minEntropyOf(n int) float64 {
	return math.Min(3.2, math.Log2(float64(n))-1.5)
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	n := 0
	for _, c := range s {
		freq[c]++
		n++
	}
	e := 0.0
	for _, k := range freq {
		p := float64(k) / float64(n)
		e -= p * math.Log2(p)
	}
	return e
}

// verdict is a plausible secret: the raw value, kept in memory, and a printable note.
type verdict struct {
	secret  string
	note    string
	public  bool
	expires int64 // JWT exp, Unix seconds
}

func judge(p *pattern, secret, name string, now time.Time) (verdict, bool) {
	body := strings.TrimPrefix(secret, secretrisk.KnownPrefix(p.prefix, secret))
	minEntropy := minEntropyOf(len(body))
	if p.typ == "assignment" {
		minEntropy = 3.0
	}
	if secret == "" || placeholder.MatchString(secret) || entropy(body) < minEntropy {
		return verdict{}, false
	}
	if note, ok := publicValue(secret); ok {
		return verdict{secret: secret, note: note, public: true}, true
	}
	switch p.typ {
	case "assignment":
		if strings.ContainsAny(secret, "(${<%") || notSecretValue.MatchString(secret) || notSecretName.MatchString(name) {
			return verdict{}, false
		}
		return verdict{secret: secret, note: name}, true
	case awsSecretType:
		if !awsSecretShaped(secret) {
			return verdict{}, false
		}
	case "url-credentials":
		if defaultPassword.MatchString(secret) {
			return verdict{}, false
		}
	case "jwt":
		claims, ok := jwtClaims(secret)
		if !ok {
			return verdict{}, false
		}
		role, _ := claims["role"].(string)
		if role == "" {
			role, _ = claims["typ"].(string)
		}
		exp, _ := claims["exp"].(float64)
		expired := exp > 0 && time.Unix(int64(exp), 0).Before(now)
		var notes []string
		if role != "" {
			notes = append(notes, "role="+role)
		}
		if expired {
			notes = append(notes, "expired")
		}
		return verdict{secret: secret, note: strings.Join(notes, " "), public: role == "anon" || expired, expires: int64(exp)}, true
	}
	return verdict{secret: secret}, true
}

// publicClients are OAuth client secrets published in gcloud's source (core/config.py,
// api_lib/auth/util.py), found in its ADC and legacy credentials. Each is recognised by its head,
// tail and length, so the value is not repeated here.
var publicClients = []struct{ head, tail, name string }{
	{"ZmssLNj", "ejr2", "Google Cloud SDK"},
	{"d-FL95Q", "D0Ty", "gcloud application-default login"},
}

const publicClientLen = 24

func publicValue(v string) (string, bool) {
	if len(v) != publicClientLen {
		return "", false
	}
	for _, c := range publicClients {
		if strings.HasPrefix(v, c.head) && strings.HasSuffix(v, c.tail) {
			return "public OAuth client of " + c.name, true
		}
	}
	return "", false
}

var sampleMarks = regexp.MustCompile(`(?i)test|fake|sample|demo|mock|fixture|dummy|foo|bar|baz|qwerty|1234|abcd`)

// sampleValue reports test-looking data, a run of four equal characters included. Real keys hit it
// now and then, so it only lowers secrets in test, example or documentation paths.
func sampleValue(v string) bool {
	if sampleMarks.MatchString(v) {
		return true
	}
	run := 1
	for i := 1; i < len(v); i++ {
		if v[i] == v[i-1] {
			if run++; run >= 4 {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

func jwtClaims(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return nil, false
	}
	return claims, true
}
