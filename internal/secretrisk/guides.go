package secretrisk

// Guide is how to rotate one kind of secret at its provider, and the documentation it follows.
type Guide struct {
	Steps []string
	Doc   string
}

// Checked against the linked documentation on 2026-11-24; what it leaves open, a step says so.
var (
	guideStripeKey = Guide{[]string{
		"Dashboard > API keys > the key's ⋯ menu > Roll key.",
		"Pick the expiration: Now kills the old key at once; otherwise both work for up to 7 days.",
		"Copy the new key right away: a live key is shown only once.",
		"Update every consumer and check the old key's request logs before it expires.",
	}, "https://docs.stripe.com/keys"}
	guideStripeWebhook = Guide{[]string{
		"Workbench > Webhooks > the endpoint > ⋯ > Roll secret.",
		"Choose immediate expiry or up to 7 days; meanwhile Stripe signs with both secrets.",
		"Deploy the new secret to the code that verifies signatures.",
	}, "https://docs.stripe.com/webhooks#roll-endpoint-secrets"}
	guideAWS = Guide{[]string{
		"IAM > Users > the user > Security credentials > Create access key (the secret is shown once).",
		"Update every consumer, then check the old key's Last used.",
		"Old key: Actions > Deactivate (reversible); once nothing breaks, Actions > Delete.",
	}, "https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html"}
	guideGCPServiceAccount = Guide{[]string{
		"IAM > Service accounts > the account > Keys > Add key > Create new key > JSON (downloads once).",
		"Deploy the new key, then disable the old one and watch for failures.",
		"Delete the old key (permanent; tokens it already issued are not revoked).",
		"Better: no key at all, with Workload Identity Federation or impersonation.",
	}, "https://docs.cloud.google.com/iam/docs/keys-create-delete"}
	guideGitHub = Guide{[]string{
		"Settings > Developer settings > Fine-grained tokens (or Tokens (classic)).",
		"Generate the replacement, fine-grained with an expiry, and copy it now.",
		"Delete the old token (also deletes deploy keys created with it).",
	}, "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"}
	guideGoogleClientSecret = Guide{[]string{
		"Google Auth Platform > Clients > the client > Add Secret (two at most; shown once).",
		"Switch the app to the new secret, then Disable the old one (reversible).",
		"Delete the disabled secret once nothing breaks.",
	}, "https://support.google.com/cloud/answer/15549257"}
	guideGoogleRefreshToken = Guide{[]string{
		"myaccount.google.com/linkedapps > the app > See details > Remove access > Confirm.",
		"Re-authorise the app (sign in again) so it gets a fresh refresh token.",
	}, "https://support.google.com/accounts/answer/13533235"}
	guideCloudflare = Guide{[]string{
		"My Profile > API Tokens > the token's ⋯ menu > Roll > Confirm.",
		"The previous value is invalidated: update consumers right away.",
	}, "https://developers.cloudflare.com/fundamentals/api/how-to/roll-token/"}
	guideAnthropic = Guide{[]string{
		"Console > Settings > API keys > Create key (the expiration cannot change later).",
		"Deploy the new key.",
		"Old key: Disable (reversible), then Delete (permanent).",
	}, "https://platform.claude.com/docs/en/manage-claude/authentication"}
	guideOpenAI = Guide{[]string{
		"platform.openai.com/api-keys > create a new key (shown once).",
		"Update consumers, then delete the old key (trash icon): it fails at once.",
	}, "https://help.openai.com/en/articles/9047852-how-can-i-delete-or-revoke-my-api-key"}
	guideXAI = Guide{[]string{
		"console.x.ai, on the team that owns the key > API Keys > Create API Key.",
		"Update consumers; old key: ⋯ > Disable key (temporary) or Delete key (permanent).",
	}, "https://docs.x.ai/console/faq/security"}
	guideOpenRouter = Guide{[]string{
		"openrouter.ai/settings/keys: delete the leaked key; there is no roll.",
		"Create a new key, ideally with a credit limit, and update consumers.",
	}, "https://openrouter.ai/docs/api-reference/authentication"}
	guideNotion = Guide{[]string{
		"Settings > Connections > Develop or manage connections > the connection.",
		"Refresh the secret (Notion does not say whether the old one dies at once).",
		"Update every consumer, then review recent page and database changes.",
	}, "https://developers.notion.com/guides/authorization/credential-security"}
	guideSlackToken = Guide{[]string{
		"api.slack.com/apps > the app: revoke one token with auth.revoke, or Revoke all tokens.",
		"Reinstall the app through OAuth to get new tokens.",
	}, "https://docs.slack.dev/faq/"}
	guideSlackWebhook = Guide{[]string{
		"api.slack.com/apps > the app > Incoming Webhooks > Add New Webhook to Workspace.",
		"Update consumers with the new URL.",
		"Slack does not document revoking one URL: if the old one has no remove option, reinstall the app.",
	}, "https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks"}
	guideSendGrid = Guide{[]string{
		"Settings > API Keys > Create API Key > Create & View (shown once).",
		"Update consumers, then the old key's menu > Delete API Key (rejected at once).",
	}, "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys"}
	guideNPM = Guide{[]string{
		"npmjs.com > Access Tokens: create a granular token with an expiry.",
		"Delete the old one there, or `npm token list` and `npm token revoke <id>`.",
		"Revocation can take up to an hour to apply.",
	}, "https://docs.npmjs.com/revoking-access-tokens"}
	guideTelegram = Guide{[]string{
		"In @BotFather send /token and pick the bot: it issues a new token.",
		"Telegram does not document whether the old token dies at once: check it no longer works.",
	}, "https://core.telegram.org/bots/features#botfather"}
	guideSentry = Guide{[]string{
		"Organization tokens: Settings > Developer Settings > Organization Tokens (owners, managers).",
		"Personal tokens: account menu > Personal Tokens.",
		"Create the new token (shown once), update consumers, revoke the old one.",
	}, "https://docs.sentry.io/account/auth-tokens/"}
)

var guides = map[string]Guide{
	"stripe-live":                guideStripeKey,
	"stripe-test":                guideStripeKey,
	"stripe-webhook":             guideStripeWebhook,
	"aws-access-key-id":          guideAWS,
	"aws-secret-key":             guideAWS,
	"gcp-service-account":        guideGCPServiceAccount,
	"github":                     guideGitHub,
	"github-pat":                 guideGitHub,
	"google-oauth-client-secret": guideGoogleClientSecret,
	"google-refresh-token":       guideGoogleRefreshToken,
	"cloudflare-token":           guideCloudflare,
	"anthropic":                  guideAnthropic,
	"openai-project":             guideOpenAI,
	"openai-service":             guideOpenAI,
	"openai-legacy":              guideOpenAI,
	"xai":                        guideXAI,
	"openrouter":                 guideOpenRouter,
	"notion":                     guideNotion,
	"slack-token":                guideSlackToken,
	"slack-webhook":              guideSlackWebhook,
	"sendgrid":                   guideSendGrid,
	"npm-token":                  guideNPM,
	"npm-authtoken":              guideNPM,
	"telegram-bot":               guideTelegram,
	"sentry-token":               guideSentry,
}

func GuideFor(typ string) (Guide, bool) {
	g, ok := guides[typ]
	return g, ok
}
