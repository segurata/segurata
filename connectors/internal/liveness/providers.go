package liveness

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/secretrisk"
)

// provider is one provider's check; docs/architecture.md, "Liveness", cites each endpoint's
// documentation.
type provider struct {
	name   string
	types  []string
	bases  []string // tried in order: SendGrid's global host rejects an EU key
	ask    func(ctx context.Context, base string, p Probe) secretrisk.Liveness
	lookup func(ctx context.Context, l *lookups, p Probe) secretrisk.Liveness // in place of ask
}

var providers = []*provider{
	{name: "openai", types: []string{"openai-project", "openai-service", "openai-legacy"}, bases: []string{"https://api.openai.com"}, ask: askOpenAI},
	{name: "anthropic", types: []string{"anthropic"}, bases: []string{"https://api.anthropic.com"}, ask: askAnthropic},
	{name: "openrouter", types: []string{"openrouter"}, bases: []string{"https://openrouter.ai"}, ask: bearer("/api/v1/key", deadWhen(http.StatusUnauthorized, "error.code", "401", accepted(byStatus(false), http.StatusPaymentRequired)), nil)},
	{name: "github", types: []string{"github", "github-pat"}, bases: []string{"https://api.github.com"}, ask: askGitHub},
	{name: "gitlab", types: []string{"gitlab"}, bases: []string{"https://gitlab.com"}, ask: askGitLab},
	{name: "aws", types: []string{"aws-secret-key"}, bases: []string{"https://sts.amazonaws.com"}, ask: askAWS},
	{name: "google", types: []string{"google-api-key"}, bases: []string{"https://generativelanguage.googleapis.com"}, ask: askGoogle},
	{name: "slack", types: []string{"slack-token"}, bases: []string{"https://slack.com"}, ask: askSlack},
	{name: "stripe", types: []string{"stripe-live", "stripe-test"}, bases: []string{"https://api.stripe.com"}, ask: bearer("/v1/balance", deadWhen(http.StatusUnauthorized, "error.code", "api_key_expired", byStatus(true)), nil)},
	{name: "sendgrid", types: []string{"sendgrid"}, bases: []string{"https://api.sendgrid.com", "https://api.eu.sendgrid.com"}, ask: bearer("/v3/scopes", byStatus(true), nil)},
	{name: "telegram", types: []string{"telegram-bot"}, bases: []string{"https://api.telegram.org"}, ask: askTelegram},
	{name: "huggingface", types: []string{"huggingface"}, bases: []string{"https://huggingface.co"}, ask: bearer("/api/whoami-v2", byStatus(false), account("huggingface", "name"))},
	{name: "npm", types: []string{"npm-token"}, bases: []string{"https://registry.npmjs.org"}, ask: bearer("/-/whoami", byStatus(false), account("npm", "username"))},
	{name: "xai", types: []string{"xai"}, bases: []string{"https://api.x.ai"}, ask: askXAI},
	{name: "groq", types: []string{"groq"}, bases: []string{"https://api.groq.com"}, ask: bearer("/openai/v1/models", byStatus(false), nil)},
	{name: "notion", types: []string{"notion"}, bases: []string{"https://api.notion.com"}, ask: askNotion},
	{name: "cloudflare", types: []string{"cloudflare-token"}, bases: []string{"https://api.cloudflare.com"}, ask: askCloudflare},
	{name: "digitalocean", types: []string{"digitalocean"}, bases: []string{"https://api.digitalocean.com"}, ask: bearer("/v2/account", deadWhen(http.StatusUnauthorized, "id", "unauthorized", byStatus(false)), account("digitalocean", "account.uuid"))},
	// sentry.io refuses tokens of self-hosted Sentry and of other regions: only a 2xx tells.
	{name: "sentry", types: []string{"sentry-token"}, bases: []string{"https://sentry.io"}, ask: bearer("/api/0/organizations/", byStatus(false), nil)},
	{name: "linear", types: []string{"linear"}, bases: []string{"https://api.linear.app"}, ask: askLinear},
	{name: "aws-keys", types: []string{"aws-access-key-id"}, lookup: lookupAWSKey},
	{name: "ssh-keys", types: []string{"private-key", "ssh-key"}, lookup: lookupSSHKey},
}

func byName(name string) *provider {
	for _, p := range providers {
		if p.name == name {
			return p
		}
	}
	return nil
}

func forType(typ string) *provider {
	for _, pv := range providers {
		if slices.Contains(pv.types, typ) {
			return pv
		}
	}
	return nil
}

// forProbe is nil for an AWS secret key without its key id.
func forProbe(p Probe) *provider {
	if pv := forType(p.Type); pv != nil && (pv.name != "aws" || p.KeyID != "") {
		return pv
	}
	return nil
}

// Supported reports whether some provider takes secrets of this type.
func Supported(typ string) bool { return forType(typ) != nil }

type judge func(code int, body []byte) (secretrisk.LiveState, string)

// byStatus: 2xx live, 403 live when the provider answers it only to a valid key lacking a
// permission, anything else unknown. A status alone never says dead: a 401 can be a key of another
// instance, region or partition, an IP allowlist, a missing scope.
func byStatus(forbiddenIsLive bool) judge {
	return func(code int, _ []byte) (secretrisk.LiveState, string) {
		reason := "HTTP " + strconv.Itoa(code)
		switch {
		case code >= 200 && code <= 299:
			return secretrisk.Live, reason
		case code == http.StatusForbidden && forbiddenIsLive:
			return secretrisk.Live, reason + " (valid, lacks a permission)"
		}
		return secretrisk.Unknown, reason
	}
}

// deadWhen is j, except that status with value at the dotted field is dead: the provider's
// documented signal of an invalid, revoked or expired key.
func deadWhen(status int, field, value string, j judge) judge {
	return func(code int, body []byte) (secretrisk.LiveState, string) {
		if code == status && bodyField(body, field) == value {
			return secretrisk.Dead, value
		}
		return j(code, body)
	}
}

// bodyField is the string or number at a dotted path into a JSON body, through providerText.
func bodyField(body []byte, field string) string {
	var v any
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	for _, k := range strings.Split(field, ".") {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	switch x := v.(type) {
	case string:
		return providerText(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

const maxProviderText = 64

// providerText is the one sanitizer of text read from an answer: kept only when short and made of
// letters, digits and _ . @ -, since anything else could be a message echoing part of the key.
func providerText(s string) string {
	if len(s) > maxProviderText {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.@-", r)) {
			return ""
		}
	}
	return s
}

// accepted is j, except that codes mean an accepted key: OpenAI's 429 over quota, OpenRouter's 402
// out of credits.
func accepted(j judge, codes ...int) judge {
	return func(code int, body []byte) (secretrisk.LiveState, string) {
		if slices.Contains(codes, code) {
			return secretrisk.Live, "HTTP " + strconv.Itoa(code) + " (the key was accepted)"
		}
		return j(code, body)
	}
}

// account reads "<provider>:<field>" from a 2xx body.
func account(provider, field string) func([]byte) string {
	return func(body []byte) string {
		if s := bodyField(body, field); s != "" {
			return provider + ":" + s
		}
		return ""
	}
}

func call(ctx context.Context, base, path string, header http.Header, j judge, acct func([]byte) string) secretrisk.Liveness {
	return send(ctx, http.MethodGet, base, path, nil, header, j, acct)
}

// send judges the answer; a failed call is unknown, its error never kept: it may carry the URL.
func send(ctx context.Context, method, base, path string, body []byte, header http.Header, j judge, acct func([]byte) string) secretrisk.Liveness {
	u, _ := url.Parse(base)
	host := base
	if u != nil {
		host = u.Host
	}
	r := secretrisk.Liveness{Endpoint: method + " " + host + httpx.ShownPath(path)}
	client := httpx.New(base, header)
	client.HTTP.CheckRedirect = httpx.NoRedirect
	code, answer, err := client.Fetch(ctx, method, path, nil, body)
	if err != nil {
		r.State, r.Reason = secretrisk.Unknown, "no answer"
		return r
	}
	r.State, r.Reason = j(code, answer)
	if r.State == secretrisk.Live && code >= 200 && code <= 299 && acct != nil {
		r.Account = acct(answer)
	}
	return r
}

func bearerAuth(value string) http.Header {
	return http.Header{"Authorization": {"Bearer " + value}}
}

func bearer(path string, j judge, acct func([]byte) string) func(context.Context, string, Probe) secretrisk.Liveness {
	return func(ctx context.Context, base string, p Probe) secretrisk.Liveness {
		return call(ctx, base, path, bearerAuth(p.Value), j, acct)
	}
}

// askOpenAI: an admin key works only on the organization endpoints. Never dead: OpenAI answers the
// same 401 to a wrong key, an IP outside the allowlist and a key lacking the permission.
func askOpenAI(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	path := "/v1/models"
	if strings.HasPrefix(p.Value, "sk-admin-") {
		path = "/v1/organization/projects?limit=1"
	}
	return bearer(path, accepted(byStatus(false), http.StatusTooManyRequests), nil)(ctx, base, p)
}

// askAnthropic: an Admin API key is refused by the Messages API endpoints.
func askAnthropic(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	path := "/v1/models"
	if strings.HasPrefix(p.Value, "sk-ant-admin") {
		path = "/v1/organizations/me"
	}
	h := http.Header{"X-Api-Key": {p.Value}, "Anthropic-Version": {"2023-06-01"}}
	return call(ctx, base, path, h, deadWhen(http.StatusUnauthorized, "error.type", "authentication_error", byStatus(true)), nil)
}

// askGitHub: never dead, since api.github.com answers a GHES or GHE.com token with the 401 of a
// revoked one; a 403 neither, since ghs_ tokens cannot call /user and many failures earn one.
func askGitHub(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	h := bearerAuth(p.Value)
	h.Set("X-Github-Api-Version", "2022-11-28")
	return call(ctx, base, "/user", h, byStatus(false), account("github", "login"))
}

// askGitLab: never dead, the token may be a self-managed instance's.
func askGitLab(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	return call(ctx, base, "/api/v4/user", http.Header{"Private-Token": {p.Value}}, byStatus(true), account("gitlab", "username"))
}

// askGoogle lists Gemini models, free of charge. Google checks the key first: invalid is 400
// API_KEY_INVALID; a 403 (API not enabled, restrictions) is still a key that exists.
func askGoogle(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		reason := googleReason(body)
		switch {
		case code == http.StatusBadRequest && reason == "API_KEY_INVALID":
			return secretrisk.Dead, reason
		case code == http.StatusForbidden && reason != "":
			return secretrisk.Live, reason + " (the key exists)"
		}
		return byStatus(false)(code, body)
	}
	return call(ctx, base, "/v1beta/models?pageSize=1", http.Header{"X-Goog-Api-Key": {p.Value}}, j, nil)
}

func googleReason(body []byte) string {
	var e struct {
		Error struct {
			Details []struct {
				Type   string `json:"@type"`
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	for _, d := range e.Error.Details {
		if strings.HasSuffix(d.Type, "google.rpc.ErrorInfo") && d.Reason != "" {
			return providerText(d.Reason)
		}
	}
	return ""
}

// slackDead leaves out not_authed (no token sent): segurata sent one.
var slackDead = map[string]bool{"invalid_auth": true, "token_revoked": true, "token_expired": true, "account_inactive": true}

// askSlack: auth.test answers 200 either way, with ok and an error code.
func askSlack(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		var r struct {
			OK bool `json:"ok"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &r) != nil {
			return byStatus(false)(code, body)
		}
		e := bodyField(body, "error")
		switch {
		case r.OK:
			return secretrisk.Live, "ok"
		case slackDead[e]:
			return secretrisk.Dead, e
		}
		return secretrisk.Unknown, cmp.Or(e, "error")
	}
	return send(ctx, http.MethodPost, base, "/api/auth.test", nil, bearerAuth(p.Value), j, account("slack", "team_id"))
}

// askTelegram: getMe's URL holds the token, which ShownPath hides. Never dead: the Bot API says
// its error_code "is subject to change".
func askTelegram(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	acct := func(body []byte) string {
		if u := bodyField(body, "result.username"); u != "" {
			return "telegram:@" + u
		}
		return ""
	}
	return call(ctx, base, "/bot"+p.Value+"/getMe", http.Header{}, byStatus(false), acct)
}

// askXAI: a blocked or disabled key, or a blocked team, answers 200 with a flag set. xAI documents
// no body code for a 401.
func askXAI(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		var k map[string]any
		if code == http.StatusOK && json.Unmarshal(body, &k) == nil {
			for _, flag := range []string{"api_key_blocked", "api_key_disabled", "team_blocked"} {
				if k[flag] == true {
					return secretrisk.Dead, flag
				}
			}
		}
		return byStatus(true)(code, body)
	}
	return call(ctx, base, "/v1/api-key", bearerAuth(p.Value), j, nil)
}

const notionVersion = "2026-03-11"

// askNotion: 403 restricted_resource is a valid token lacking the capability.
func askNotion(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	h := bearerAuth(p.Value)
	h.Set("Notion-Version", notionVersion)
	return call(ctx, base, "/v1/users/me", h, deadWhen(http.StatusUnauthorized, "code", "unauthorized", byStatus(true)), account("notion", "bot.workspace_id"))
}

// askCloudflare: only the token's status decides. A failure tells nothing: an account-owned token
// is verified with its account id, a legacy Global API Key with the account's email.
func askCloudflare(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		status := bodyField(body, "result.status")
		if code != http.StatusOK || status == "" {
			return secretrisk.Unknown, "HTTP " + strconv.Itoa(code)
		}
		switch status {
		case "active":
			return secretrisk.Live, "active"
		case "disabled", "expired":
			return secretrisk.Dead, "token " + status
		}
		return secretrisk.Unknown, "status " + status
	}
	return call(ctx, base, "/client/v4/user/tokens/verify", bearerAuth(p.Value), j, nil)
}

var linearQuery = []byte(`{"query":"{ viewer { id } }"}`)

// askLinear: a personal API key goes in Authorization without Bearer. Never dead: Linear
// documents no error code for an invalid key.
func askLinear(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		if code == http.StatusOK && bodyField(body, "data.viewer.id") != "" {
			return secretrisk.Live, "HTTP 200"
		}
		return secretrisk.Unknown, "HTTP " + strconv.Itoa(code)
	}
	return send(ctx, http.MethodPost, base, "/graphql", linearQuery, http.Header{"Authorization": {p.Value}}, j, account("linear", "data.viewer.id"))
}
