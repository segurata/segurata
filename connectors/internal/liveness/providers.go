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

// provider is one provider's check: the secret types it takes and the call that tries one. Every
// call is a GET to a read-only endpoint that says who the caller is or lists something; see the
// table in docs/architecture.md, "Liveness", for each endpoint's documentation.
type provider struct {
	name  string
	types []string
	// bases are the API hosts, tried in order until one accepts the key (Checker.ask): a key of
	// SendGrid's EU region is rejected by the global host.
	bases []string
	ask   func(ctx context.Context, base string, p Probe) secretrisk.Liveness
	// lookup, in place of ask, classifies the secret with the owner's credentials (lookup.go).
	lookup func(ctx context.Context, l *lookups, p Probe) secretrisk.Liveness
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
	// A token of a self-hosted Sentry, or of an organization stored in another region, may be
	// refused by sentry.io: only a 2xx tells.
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

// forType is the provider that takes secrets of the type, or nil.
func forType(typ string) *provider {
	for _, pv := range providers {
		if slices.Contains(pv.types, typ) {
			return pv
		}
	}
	return nil
}

// forProbe is the provider that can try the probe, or nil: an AWS secret key needs the key id
// found with it.
func forProbe(p Probe) *provider {
	if pv := forType(p.Type); pv != nil && (pv.name != "aws" || p.KeyID != "") {
		return pv
	}
	return nil
}

// Supported reports whether some provider takes secrets of this type. An AWS secret key is
// supported, though tried only with its key id (forProbe).
func Supported(typ string) bool { return forType(typ) != nil }

// judge turns an HTTP answer into a state and segurata's own reason.
type judge func(code int, body []byte) (secretrisk.LiveState, string)

// byStatus is the common judgement: 2xx live, 403 live when the provider answers 403 only to a
// valid key that lacks a permission (forbiddenIsLive), anything else unknown. A status alone never
// says dead: a 401 can be a key of another instance, region or partition, an IP allowlist, a
// missing scope. Dead is deadWhen's, on the provider's documented signal.
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

// deadWhen is j, except that an answer with the status whose body holds value at field (a dotted
// path) is dead: the signal the provider documents for an invalid, revoked or expired key. The
// reason is value, segurata's copy of it.
func deadWhen(status int, field, value string, j judge) judge {
	return func(code int, body []byte) (secretrisk.LiveState, string) {
		if code == status && bodyField(body, field) == value {
			return secretrisk.Dead, value
		}
		return j(code, body)
	}
}

// bodyField is the string or number at a dotted path into a JSON body, through providerText; ""
// when there is none.
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

// maxProviderText bounds what segurata keeps of a provider's words: a code, an account id.
const maxProviderText = 64

// providerText is the one sanitizer of text read from a provider's answer (codes, reasons,
// statuses, account ids): kept only when it is short and made of letters, digits and _ . @ -,
// else "". Anything else could be a message that echoes part of the key. Checker.Check also drops
// any result field that holds a part of the probe's value (withoutValue).
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

// accepted is j, except that the codes given mean the provider accepted the key: OpenAI answers 429
// to a valid key out of quota or over its rate limit, OpenRouter 402 to one out of credits.
func accepted(j judge, codes ...int) judge {
	return func(code int, body []byte) (secretrisk.LiveState, string) {
		if slices.Contains(codes, code) {
			return secretrisk.Live, "HTTP " + strconv.Itoa(code) + " (the key was accepted)"
		}
		return j(code, body)
	}
}

// account reads the account a 2xx body names, "<provider>:<value of field>"; field may be a
// dotted path into nested objects ("bot.workspace_id").
func account(provider, field string) func([]byte) string {
	return func(body []byte) string {
		if s := bodyField(body, field); s != "" {
			return provider + ":" + s
		}
		return ""
	}
}

// call GETs base+path with header and judges the answer.
func call(ctx context.Context, base, path string, header http.Header, j judge, acct func([]byte) string) secretrisk.Liveness {
	return send(ctx, http.MethodGet, base, path, nil, header, j, acct)
}

// send makes the request and judges the answer. A failed call (network, timeout) is unknown, its
// error never kept: it may carry the URL.
func send(ctx context.Context, method, base, path string, body []byte, header http.Header, j judge, acct func([]byte) string) secretrisk.Liveness {
	u, _ := url.Parse(base)
	host := base
	if u != nil {
		host = u.Host
	}
	r := secretrisk.Liveness{Endpoint: method + " " + host + httpx.ShownPath(path)}
	code, answer, err := httpx.New(base, header).Fetch(ctx, method, path, nil, body)
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

// bearerAuth is the header that sends the secret as a bearer token.
func bearerAuth(value string) http.Header {
	return http.Header{"Authorization": {"Bearer " + value}}
}

// bearer is a check that sends the secret as a bearer token to one path.
func bearer(path string, j judge, acct func([]byte) string) func(context.Context, string, Probe) secretrisk.Liveness {
	return func(ctx context.Context, base string, p Probe) secretrisk.Liveness {
		return call(ctx, base, path, bearerAuth(p.Value), j, acct)
	}
}

// askOpenAI lists models; an admin key works only on the organization endpoints, so it lists one
// project instead. Never dead: OpenAI documents a 401 for an IP outside the allowlist, an account
// out of its organization and a key without the endpoint's permission as well as for a wrong key,
// and no body code that tells them apart.
func askOpenAI(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	path := "/v1/models"
	if strings.HasPrefix(p.Value, "sk-admin-") {
		path = "/v1/organization/projects?limit=1"
	}
	return bearer(path, accepted(byStatus(false), http.StatusTooManyRequests), nil)(ctx, base, p)
}

// askAnthropic lists models with an API key, or reads the organization with an Admin API key
// (sk-ant-admin…), which the Messages API endpoints do not take.
func askAnthropic(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	path := "/v1/models"
	if strings.HasPrefix(p.Value, "sk-ant-admin") {
		path = "/v1/organizations/me"
	}
	h := http.Header{"X-Api-Key": {p.Value}, "Anthropic-Version": {"2023-06-01"}}
	return call(ctx, base, path, h, deadWhen(http.StatusUnauthorized, "error.type", "authentication_error", byStatus(true)), nil)
}

// askGitHub reads the user a token signs in as. Never dead: GitHub Enterprise Server and GHE.com
// issue tokens of the same formats, which api.github.com rejects with the 401 it gives a revoked
// one. A 403 tells nothing either: an installation token (ghs_) cannot call /user, and GitHub may
// answer 403 to any credential after many invalid ones.
func askGitHub(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	h := bearerAuth(p.Value)
	h.Set("X-Github-Api-Version", "2022-11-28")
	return call(ctx, base, "/user", h, byStatus(false), account("github", "login"))
}

// askGitLab reads the user on gitlab.com. Never dead: the token may belong to a self-managed
// instance, which segurata cannot know.
func askGitLab(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	return call(ctx, base, "/api/v4/user", http.Header{"Private-Token": {p.Value}}, byStatus(true), account("gitlab", "username"))
}

// askGoogle lists Gemini models, free of charge, with the key in a header. Google checks the key
// before anything else: an invalid one is 400 API_KEY_INVALID; a valid key whose project has not
// enabled the API, or whose restrictions block it, is 403 and still a key that exists.
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

// googleReason is the ErrorInfo reason of a Google API error.
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

// slackDead are the auth.test errors of a token that no longer works. not_authed (no token sent)
// is not one of them: segurata sent one, so it says nothing about it.
var slackDead = map[string]bool{"invalid_auth": true, "token_revoked": true, "token_expired": true, "account_inactive": true}

// askSlack calls auth.test, which answers 200 either way: ok true with the workspace, or ok false
// with an error code. Slack documents it as POST; it reads, and the request has no body.
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

// askTelegram calls getMe, whose URL holds the token: the endpoint recorded hides it, and a failed
// call keeps no error. Never dead: the Bot API says its error_code "is subject to change".
func askTelegram(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	acct := func(body []byte) string {
		if u := bodyField(body, "result.username"); u != "" {
			return "telegram:@" + u
		}
		return ""
	}
	return call(ctx, base, "/bot"+p.Value+"/getMe", http.Header{}, byStatus(false), acct)
}

// askXAI reads the key's own record. A key that still authenticates but is blocked or disabled,
// or whose team is blocked, answers 200 with a flag set: dead, by the first flag set. A 401 is
// unknown: xAI documents no body code for it.
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

// notionVersion is the API version Notion's reference for GET /v1/users/me lists.
const notionVersion = "2026-03-11"

// askNotion reads the integration's bot user; 403 restricted_resource is a token without the
// capability, still valid.
func askNotion(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	h := bearerAuth(p.Value)
	h.Set("Notion-Version", notionVersion)
	return call(ctx, base, "/v1/users/me", h, deadWhen(http.StatusUnauthorized, "code", "unauthorized", byStatus(true)), account("notion", "bot.workspace_id"))
}

// askCloudflare verifies a user API token. Only the token's status decides: active is live,
// disabled or expired dead. A failure tells nothing: an account-owned token is verified on an
// endpoint that needs the account id, and a legacy Global API Key needs the account's email.
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

// linearQuery is the only body sent to Linear: a GraphQL query, which cannot change anything.
var linearQuery = []byte(`{"query":"{ viewer { id } }"}`)

// askLinear asks Linear's GraphQL API who the viewer is. A personal API key goes in Authorization
// as it is, without Bearer. Never dead: Linear documents no error code for an invalid key.
func askLinear(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		if code == http.StatusOK && bodyField(body, "data.viewer.id") != "" {
			return secretrisk.Live, "HTTP 200"
		}
		return secretrisk.Unknown, "HTTP " + strconv.Itoa(code)
	}
	return send(ctx, http.MethodPost, base, "/graphql", linearQuery, http.Header{"Authorization": {p.Value}}, j, account("linear", "data.viewer.id"))
}
