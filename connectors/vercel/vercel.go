// Package vercel inventories a Vercel account through the REST API: the user's tokens (leaked,
// idle, never expiring) and teams with the plan that decides whether spend can run away.
// Read-only. See docs/cloud-connectors.md.
package vercel

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	secretName     = "VERCEL_TOKEN"
	DefaultBaseURL = "https://api.vercel.com"
	setupHint      = "create a token at https://vercel.com/account/settings/tokens (set an expiry), store it with " +
		"`security add-generic-password -s segurata-vercel -a \"$USER\" -w` and reference it in " +
		"~/.config/segurata/config.json as connectors.vercel.secrets.VERCEL_TOKEN = \"keychain:segurata-vercel\""
)

// Connector is the built-in Vercel connector. Zero values use the real API and clock.
type Connector struct {
	BaseURL string
	Now     func() time.Time
}

func init() { connector.Register(&Connector{}) }

// SetupHint says how to create and store the secret the connector needs (connector.SetupHinter).
func (c *Connector) SetupHint(secret string) string {
	return connector.HintFor(secret, secretName, setupHint)
}

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     "vercel",
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Tokens (leaked, idle, never expiring), teams and plans; Spend Management is not exposed by the API",
		Needs:    []string{"secret:" + secretName},
	}
}

type token struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Type      string `json:"type"`
	Origin    string `json:"origin"`
	ActiveAt  *int64 `json:"activeAt"`
	CreatedAt *int64 `json:"createdAt"`
	ExpiresAt *int64 `json:"expiresAt"`
	LeakedAt  *int64 `json:"leakedAt"`
	LeakedURL string `json:"leakedUrl"`
	Scopes    []struct {
		Type   string `json:"type"`
		TeamID string `json:"teamId"`
	} `json:"scopes"`
}

type team struct {
	ID      string `json:"id"`
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	Billing *struct {
		Plan string `json:"plan"`
	} `json:"billing"`
	Membership *struct {
		Role string `json:"role"`
	} `json:"membership"`
}

func (t team) plan() string {
	if t.Billing == nil {
		return ""
	}
	return t.Billing.Plan
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	tok := req.Secrets[secretName]
	if tok == "" {
		emit.Status(finding.Status{Account: "vercel", State: finding.StateMissingCredentials, Detail: secretName + " is not configured: " + setupHint})
		return nil
	}
	api := httpx.New(httpx.Base(c.BaseURL, DefaultBaseURL), http.Header{"Authorization": {"Bearer " + tok}})
	var me struct {
		User struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"user"`
	}
	if err := api.Get(ctx, "/v2/user", nil, &me); err != nil {
		emit.Status(finding.Status{Account: "vercel", State: httpx.State(err), Detail: err.Error()})
		return nil
	}
	account := me.User.Username
	if account == "" {
		account = me.User.Email
	}
	scanned := connector.Now(c.Now)
	var failed []string

	var tokens struct {
		Tokens []token `json:"tokens"`
	}
	if err := api.Get(ctx, "/v6/user/tokens", url.Values{"status": {"active"}}, &tokens); err != nil {
		failed = append(failed, "tokens: "+err.Error())
	}
	for _, t := range tokens.Tokens {
		f := tokenFinding(t, scanned)
		f.Account = account
		emit.Finding(f)
	}

	var teams struct {
		Teams []team `json:"teams"`
	}
	if err := api.Get(ctx, "/v2/teams", url.Values{"limit": {"100"}}, &teams); err != nil {
		failed = append(failed, "teams: "+err.Error())
	}
	for _, t := range teams.Teams {
		for _, f := range teamFindings(t) {
			f.Account = account
			emit.Finding(f)
		}
	}

	st := finding.Status{Account: account, State: finding.StateOK}
	if len(failed) > 0 {
		st.State, st.Detail = finding.StateError, strings.Join(failed, "; ")
	}
	emit.Status(st)
	return nil
}
