package liveness

import (
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
	// bases are the API hosts, tried in order while each says dead: a key of SendGrid's EU region
	// is rejected by the global host.
	bases []string
	ask   func(ctx context.Context, base string, p Probe) secretrisk.Liveness
}

var providers = []*provider{
	{name: "openai", types: []string{"openai-project", "openai-service", "openai-legacy"}, bases: []string{"https://api.openai.com"}, ask: askOpenAI},
	{name: "anthropic", types: []string{"anthropic"}, bases: []string{"https://api.anthropic.com"}, ask: askAnthropic},
	{name: "openrouter", types: []string{"openrouter"}, bases: []string{"https://openrouter.ai"}, ask: bearer("/api/v1/key", accepted(byStatus(false), http.StatusPaymentRequired), nil)},
	{name: "github", types: []string{"github", "github-pat"}, bases: []string{"https://api.github.com"}, ask: askGitHub},
	{name: "gitlab", types: []string{"gitlab"}, bases: []string{"https://gitlab.com"}, ask: askGitLab},
	{name: "aws", types: []string{"aws-secret-key"}, bases: []string{"https://sts.amazonaws.com"}, ask: askAWS},
	{name: "google", types: []string{"google-api-key"}, bases: []string{"https://generativelanguage.googleapis.com"}, ask: askGoogle},
	{name: "slack", types: []string{"slack-token"}, bases: []string{"https://slack.com"}, ask: askSlack},
	{name: "stripe", types: []string{"stripe-live", "stripe-test"}, bases: []string{"https://api.stripe.com"}, ask: bearer("/v1/balance", byStatus(true), nil)},
	{name: "sendgrid", types: []string{"sendgrid"}, bases: []string{"https://api.sendgrid.com", "https://api.eu.sendgrid.com"}, ask: bearer("/v3/scopes", byStatus(true), nil)},
	{name: "telegram", types: []string{"telegram-bot"}, bases: []string{"https://api.telegram.org"}, ask: askTelegram},
	{name: "huggingface", types: []string{"huggingface"}, bases: []string{"https://huggingface.co"}, ask: bearer("/api/whoami-v2", byStatus(false), account("huggingface", "name"))},
	{name: "npm", types: []string{"npm-token"}, bases: []string{"https://registry.npmjs.org"}, ask: bearer("/-/whoami", byStatus(false), account("npm", "username"))},
	{name: "xai", types: []string{"xai"}, bases: []string{"https://api.x.ai"}, ask: askXAI},
	{name: "groq", types: []string{"groq"}, bases: []string{"https://api.groq.com"}, ask: bearer("/openai/v1/models", byStatus(false), nil)},
	{name: "notion", types: []string{"notion"}, bases: []string{"https://api.notion.com"}, ask: askNotion},
	{name: "cloudflare", types: []string{"cloudflare-token"}, bases: []string{"https://api.cloudflare.com"}, ask: askCloudflare},
	{name: "digitalocean", types: []string{"digitalocean"}, bases: []string{"https://api.digitalocean.com"}, ask: bearer("/v2/account", byStatus(false), account("digitalocean", "account.uuid"))},
	{name: "sentry", types: []string{"sentry-token"}, bases: []string{"https://sentry.io"}, ask: askSentry},
	{name: "linear", types: []string{"linear"}, bases: []string{"https://api.linear.app"}, ask: askLinear},
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

// byStatus is the common judgement: 2xx live, 401 dead, 403 live when the provider answers 403
// only to a valid key that lacks a permission (forbiddenIsLive), anything else unknown.
func byStatus(forbiddenIsLive bool) judge {
	return func(code int, _ []byte) (secretrisk.LiveState, string) {
		reason := "HTTP " + strconv.Itoa(code)
		switch {
		case code >= 200 && code <= 299:
			return secretrisk.Live, reason
		case code == http.StatusUnauthorized:
			return secretrisk.Dead, reason
		case code == http.StatusForbidden && forbiddenIsLive:
			return secretrisk.Live, reason + " (valid, lacks a permission)"
		}
		return secretrisk.Unknown, reason
	}
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
		var v any
		if json.Unmarshal(body, &v) != nil {
			return ""
		}
		for _, k := range strings.Split(field, ".") {
			m, _ := v.(map[string]any)
			v = m[k]
		}
		if s, ok := v.(string); ok && s != "" {
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
	r := secretrisk.Liveness{Endpoint: method + " " + host + endpointPath(path)}
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

// endpointPath is the path as results show it: a token in the path (Telegram's /bot<token>/) is
// replaced by a placeholder.
func endpointPath(path string) string {
	if rest, ok := strings.CutPrefix(path, "/bot"); ok {
		if _, after, ok := strings.Cut(rest, "/"); ok {
			return "/bot<token>/" + after
		}
	}
	return path
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
// project instead.
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
	return call(ctx, base, path, h, byStatus(true), nil)
}

// askGitHub reads the user a token signs in as. A 403 tells nothing: an installation token (ghs_)
// cannot call /user, and GitHub may answer 403 to any credential after many invalid ones.
func askGitHub(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	h := bearerAuth(p.Value)
	h.Set("X-Github-Api-Version", "2022-11-28")
	return call(ctx, base, "/user", h, byStatus(false), account("github", "login"))
}

// askGitLab reads the user on gitlab.com. A 401 there is not dead: the token may belong to a
// self-managed instance, which segurata cannot know.
func askGitLab(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		if code == http.StatusUnauthorized {
			return secretrisk.Unknown, "HTTP 401 on gitlab.com (it may belong to a self-managed instance)"
		}
		return byStatus(true)(code, body)
	}
	return call(ctx, base, "/api/v4/user", http.Header{"Private-Token": {p.Value}}, j, account("gitlab", "username"))
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
			return d.Reason
		}
	}
	return ""
}

// slackDead are the auth.test errors of a token that no longer works.
var slackDead = map[string]bool{"invalid_auth": true, "not_authed": true, "token_revoked": true, "token_expired": true, "account_inactive": true}

// askSlack calls auth.test, which answers 200 either way: ok true with the workspace, or ok false
// with an error code. Slack documents it as POST; it reads, and the request has no body.
func askSlack(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	var team string
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		var r struct {
			OK     bool   `json:"ok"`
			Error  string `json:"error"`
			TeamID string `json:"team_id"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &r) != nil {
			return byStatus(false)(code, body)
		}
		switch {
		case r.OK:
			team = r.TeamID
			return secretrisk.Live, "ok"
		case slackDead[r.Error]:
			return secretrisk.Dead, r.Error
		}
		return secretrisk.Unknown, safeCode(r.Error)
	}
	res := send(ctx, http.MethodPost, base, "/api/auth.test", nil, bearerAuth(p.Value), j, nil)
	if res.State == secretrisk.Live && team != "" {
		res.Account = "slack:" + team
	}
	return res
}

// askTelegram calls getMe, whose URL holds the token: the endpoint recorded hides it, and a failed
// call keeps no error.
func askTelegram(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	acct := func(body []byte) string {
		var r struct {
			Result struct {
				Username string `json:"username"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &r) != nil || r.Result.Username == "" {
			return ""
		}
		return "telegram:@" + r.Result.Username
	}
	return call(ctx, base, "/bot"+p.Value+"/getMe", http.Header{}, byStatus(false), acct)
}

// safeCode keeps an API error code only when it is a short snake_case word: anything else could
// be text the provider echoed.
func safeCode(s string) string {
	if len(s) == 0 || len(s) > 40 {
		return "error"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r == '_') {
			return "error"
		}
	}
	return s
}

// askXAI reads the key's own record. A key that still authenticates but is blocked or disabled,
// or whose team is blocked, answers 200 with a flag set: dead, by the first flag set.
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
	return call(ctx, base, "/v1/users/me", h, byStatus(true), account("notion", "bot.workspace_id"))
}

// askCloudflare verifies a user API token. Only the token's status decides: active is live,
// disabled or expired dead. A failure tells nothing: an account-owned token is verified on an
// endpoint that needs the account id, and a legacy Global API Key needs the account's email.
func askCloudflare(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		var r struct {
			Result struct {
				Status string `json:"status"`
			} `json:"result"`
		}
		if code != http.StatusOK || json.Unmarshal(body, &r) != nil {
			return secretrisk.Unknown, "HTTP " + strconv.Itoa(code)
		}
		switch r.Result.Status {
		case "active":
			return secretrisk.Live, "active"
		case "disabled", "expired":
			return secretrisk.Dead, "token " + r.Result.Status
		}
		return secretrisk.Unknown, "status " + safeCode(r.Result.Status)
	}
	return call(ctx, base, "/client/v4/user/tokens/verify", bearerAuth(p.Value), j, nil)
}

// askSentry lists the organizations a token reaches. Only a 2xx tells: a token of a self-hosted
// Sentry, or of an organization stored in another region, may be refused by sentry.io.
func askSentry(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		if code >= 200 && code <= 299 {
			return secretrisk.Live, "HTTP " + strconv.Itoa(code)
		}
		return secretrisk.Unknown, "HTTP " + strconv.Itoa(code) + " on sentry.io (it may belong to a self-hosted Sentry or another region)"
	}
	return call(ctx, base, "/api/0/organizations/", bearerAuth(p.Value), j, nil)
}

// linearQuery is the only body sent to Linear: a GraphQL query, which cannot change anything.
var linearQuery = []byte(`{"query":"{ viewer { id } }"}`)

// graphQLError is one entry of a GraphQL answer's errors.
type graphQLError struct {
	Extensions struct {
		Code string `json:"code"`
	} `json:"extensions"`
}

// askLinear asks Linear's GraphQL API who the viewer is. A personal API key goes in Authorization
// as it is, without Bearer. An authentication error is dead.
func askLinear(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	j := func(code int, body []byte) (secretrisk.LiveState, string) {
		var r struct {
			Data struct {
				Viewer struct {
					ID string `json:"id"`
				} `json:"viewer"`
			} `json:"data"`
			Errors []graphQLError `json:"errors"`
		}
		_ = json.Unmarshal(body, &r)
		switch {
		case code == http.StatusOK && r.Data.Viewer.ID != "":
			return secretrisk.Live, "HTTP 200"
		case slices.ContainsFunc(r.Errors, func(e graphQLError) bool { return e.Extensions.Code == "AUTHENTICATION_ERROR" }):
			return secretrisk.Dead, "AUTHENTICATION_ERROR"
		}
		return byStatus(false)(code, body)
	}
	return send(ctx, http.MethodPost, base, "/graphql", linearQuery, http.Header{"Authorization": {p.Value}}, j, account("linear", "data.viewer.id"))
}
