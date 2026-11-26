package secretrisk

import "strings"

// Type describes one kind of secret.
type Type struct {
	Service   string // provider, used to group and filter
	Label     string // plain words, used in reasons and titles
	Impact    Impact
	RotateURL string // provider page where this kind of secret is revoked or rotated
}

// Checked against each provider's documentation on 2026-11-23. A type without a stable,
// account-independent page (npm tokens live under /settings/<user>/tokens) has none.
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

// catalog holds the connector's own pattern names and the gitleaks rules mapped onto them.
var catalog = map[string]Type{
	// High: money, infrastructure, source code, identity.
	"stripe-live":                {"stripe", "Stripe live secret key", High, urlStripeKeys},
	"aws-access-key-id":          {"aws", "AWS access key id (signs nothing without its secret key)", Low, urlAWS},
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
	// A key id and a signature, never the secret key, expiring within seven days (STS: 36 hours).
	"aws-presigned-url": {"aws", "Pre-signed AWS URLs", Low, urlAWS},
	"stripe-test":       {"stripe", "Stripe test key", Low, urlStripeKeys},
	"jwt":               {"unknown", "JWT of unknown origin", Low, ""},

	// Noise: generic name=value matches, mostly configuration that is not secret.
	"assignment":      {"generic", "Generic secret-looking assignment", Noise, ""},
	"generic-api-key": {"generic", "Generic API key (gitleaks)", Noise, ""},
}

// Known returns the catalog entry and whether the type is in the catalog.
func Known(typ string) (Type, bool) {
	t, ok := catalog[typ]
	return t, ok
}

// lookup is the catalog entry, or a medium-impact one for an unknown gitleaks rule, which still
// matched something specific.
func lookup(typ string) Type {
	if t, ok := Known(typ); ok {
		return t
	}
	service := typ
	if i := strings.IndexByte(typ, '-'); i > 0 {
		service = typ[:i]
	}
	return Type{Service: service, Label: typ + " (gitleaks rule)", Impact: Medium}
}

// An ASIA key id is a temporary STS credential that expires within 36 hours: a copy found later is
// almost always dead.
var temporaryAWS = Type{Service: "aws", Label: "Temporary AWS credential (STS, expires within 36 hours)", Impact: Low, RotateURL: urlAWS}

// Gitleaks' sourcegraph-access-token also accepts any bare 40-hex string (the legacy format), so
// without the sgp_ prefix the match is most often a SHA-1: 2,013 of them in one SQL backup. It is
// the only gitleaks 8.30 rule that takes bare hex without a keyword next to it.
var hexLookalike = Type{Service: "generic", Label: "40-character hex string (a hash more often than a token)", Impact: Noise}

// TypeFor is the catalog entry refined by the redacted hint, for types whose prefix changes what
// they are.
func TypeFor(typ, redacted string) Type {
	if strings.HasPrefix(typ, "aws-access") && strings.HasPrefix(redacted, "ASIA") {
		return temporaryAWS
	}
	if typ == "sourcegraph-access-token" && !strings.HasPrefix(redacted, "sgp_") {
		return hexLookalike
	}
	return lookup(typ)
}
