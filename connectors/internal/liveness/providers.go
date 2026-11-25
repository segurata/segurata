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
}

func byName(name string) *provider {
	for _, p := range providers {
		if p.name == name {
			return p
		}
	}
	return nil
}

// forType is the provider that can try the probe, or nil: an AWS secret key needs the key id
// found with it.
func forType(p Probe) *provider {
	for _, pv := range providers {
		for _, t := range pv.types {
			if t == p.Type && (pv.name != "aws" || p.KeyID != "") {
				return pv
			}
		}
	}
	return nil
}

// Supported reports whether some provider can try a secret of this type (an AWS secret key only
// with its key id).
func Supported(typ string) bool { return forType(Probe{Type: typ, KeyID: "-"}) != nil }

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

// account reads the account a 2xx body names, "<provider>:<value of field>".
func account(provider, field string) func([]byte) string {
	return func(body []byte) string {
		var m map[string]any
		if json.Unmarshal(body, &m) != nil {
			return ""
		}
		if v, ok := m[field].(string); ok && v != "" {
			return provider + ":" + v
		}
		return ""
	}
}

// call GETs base+path with header and judges the answer. A failed call (network, timeout) is
// unknown, its error never kept: it may carry the URL.
func call(ctx context.Context, base, path string, header http.Header, j judge, acct func([]byte) string) secretrisk.Liveness {
	return send(ctx, http.MethodGet, base, path, header, j, acct)
}

func send(ctx context.Context, method, base, path string, header http.Header, j judge, acct func([]byte) string) secretrisk.Liveness {
	u, _ := url.Parse(base)
	host := base
	if u != nil {
		host = u.Host
	}
	r := secretrisk.Liveness{Endpoint: method + " " + host + endpointPath(path)}
	code, body, err := httpx.New(base, header).Fetch(ctx, method, path, nil)
	if err != nil {
		r.State, r.Reason = secretrisk.Unknown, "no answer"
		return r
	}
	r.State, r.Reason = j(code, body)
	if r.State == secretrisk.Live && code >= 200 && code <= 299 && acct != nil {
		r.Account = acct(body)
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

// bearer is a check that sends the secret as a bearer token to one path.
func bearer(path string, j judge, acct func([]byte) string) func(context.Context, string, Probe) secretrisk.Liveness {
	return func(ctx context.Context, base string, p Probe) secretrisk.Liveness {
		return call(ctx, base, path, http.Header{"Authorization": {"Bearer " + p.Value}}, j, acct)
	}
}

// askOpenAI lists models; an admin key works only on the organization endpoints, so it lists one
// project instead.
func askOpenAI(ctx context.Context, base string, p Probe) secretrisk.Liveness {
	path := "/v1/models"
	if strings.HasPrefix(p.Value, "sk-admin-") {
		path = "/v1/organization/projects?limit=1"
	}
	return call(ctx, base, path, http.Header{"Authorization": {"Bearer " + p.Value}}, accepted(byStatus(false), http.StatusTooManyRequests), nil)
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
	h := http.Header{"Authorization": {"Bearer " + p.Value}, "X-Github-Api-Version": {"2022-11-28"}}
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
	res := send(ctx, http.MethodPost, base, "/api/auth.test", http.Header{"Authorization": {"Bearer " + p.Value}}, j, nil)
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
