// Package workspace audits a Google Workspace tenant through the Admin SDK with read-only scopes
// and GET requests only: 2-Step Verification, admins, stale accounts and third-party OAuth apps.
// One instance per tenant ("workspace:example.com").
package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	connectorName       = "workspace"
	secretName          = "WORKSPACE_ACCESS_TOKEN"
	defaultAPIURL       = "https://admin.googleapis.com/admin"
	defaultTokenInfoURL = "https://oauth2.googleapis.com/tokeninfo"
	defaultInactiveDays = 90
)

// Scopes are requested for the access token; without the last, optional one, token activity is
// skipped.
var Scopes = []string{
	"https://www.googleapis.com/auth/admin.directory.user.readonly",
	"https://www.googleapis.com/auth/admin.directory.user.security",
	"https://www.googleapis.com/auth/admin.reports.audit.readonly",
}

var (
	requiredScopes = Scopes[:2]
	reportsScope   = Scopes[2]
)

// readOnly is the only gcloud command the connector runs; signing in is left to the owner.
var readOnly = cli.Allowlist{"auth application-default print-access-token"}

func init() { connector.Register(New()) }

type Connector struct {
	apiURL       string
	tokenInfoURL string
	home         string
	now          func() time.Time
	http         *http.Client
	gcloud       func(configured string, env []string) (cli.Runner, error)
}

func New() *Connector {
	home, _ := os.UserHomeDir()
	c := &Connector{apiURL: defaultAPIURL, tokenInfoURL: defaultTokenInfoURL, home: home, now: time.Now,
		http: &http.Client{Timeout: 60 * time.Second, CheckRedirect: httpx.NoRedirect}}
	c.gcloud = func(configured string, env []string) (cli.Runner, error) {
		path, err := cli.FindGcloud(configured, c.home, connectorName)
		if err != nil {
			return nil, err
		}
		return cli.Exec{Path: path, Timeout: 60 * time.Second, Env: env}, nil
	}
	return c
}

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     connectorName,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Google Workspace tenant: 2SV, admins, suspended or inactive accounts, third-party OAuth apps, token activity",
		Needs:    []string{"cli:gcloud", "secret:" + secretName},
		Theme:    finding.ThemeGoogle,
		Covers:   []finding.Area{{ID: "workspace"}}, // audited when a tenant reports ok
	}
}

type settings struct {
	domain         string
	cloudsdkConfig string // gcloud config folder of this tenant's credentials
	quotaProject   string // sent as X-Goog-User-Project
	gcloudPath     string
	inactiveDays   int
}

var domainRE = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)

func parseSettings(m map[string]any, home string) (settings, error) {
	s := settings{inactiveDays: defaultInactiveDays}
	for key, dst := range map[string]*string{"domain": &s.domain, "cloudsdk_config": &s.cloudsdkConfig,
		"quota_project": &s.quotaProject, "gcloud_path": &s.gcloudPath} {
		if v, ok := m[key]; ok && v != nil {
			str, ok := v.(string)
			if !ok {
				return s, fmt.Errorf("workspace config: %q must be a string", key)
			}
			*dst = str
		}
	}
	s.domain = strings.ToLower(strings.TrimSpace(s.domain))
	if s.domain != "" && !domainRE.MatchString(s.domain) {
		return s, fmt.Errorf("workspace config: %q does not look like a domain", s.domain)
	}
	var err error
	if s.inactiveDays, err = connector.PositiveInt(m, "workspace", "inactive_days", defaultInactiveDays); err != nil {
		return s, err
	}
	switch {
	case strings.HasPrefix(s.cloudsdkConfig, "~/"):
		s.cloudsdkConfig = filepath.Join(home, s.cloudsdkConfig[2:])
	case s.cloudsdkConfig == "" && s.domain != "":
		s.cloudsdkConfig = DefaultConfigDir(home, s.domain)
	}
	return s, nil
}

// DefaultConfigDir keeps a tenant's credentials apart from the usual ADC.
func DefaultConfigDir(home, domain string) string {
	return filepath.Join(home, ".config", "segurata", "gcloud-"+domain)
}

const noTenantHint = `no tenant configured: add one instance per tenant to ~/.config/segurata/config.json, ` +
	`such as "workspace:example.com": {"config": {"domain": "example.com"}}, and run again for the one-time sign-in steps`

// loginHelp: gcloud requires cloud-platform on the ADC login (the token requested carries only
// Scopes), and its default OAuth client refuses scopes outside Google Cloud, hence an own client.
func loginHelp(s settings) string {
	return strings.Join([]string{
		"No admin credentials for " + s.domain + " with the read-only Admin SDK scopes.",
		"One-time steps per tenant:",
		`  1. In a Google Cloud project of the tenant: enable "Admin SDK API" and create an OAuth client ID`,
		`     of type "Desktop app". Download its JSON (for example ~/Downloads/client_secret.json).`,
		"  2. Sign in with an admin account of the tenant, in a separate gcloud config:",
		`     CLOUDSDK_CONFIG="` + s.cloudsdkConfig + `" gcloud auth application-default login \`,
		`       --client-id-file=$HOME/Downloads/client_secret.json \`,
		"       --scopes=openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform," + strings.Join(Scopes, ","),
		"Then run segurata inventory workspace again. To authenticate some other way, set the " + secretName + " secret.",
	}, "\n")
}

func (c *Connector) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	cfg, err := parseSettings(req.Config, c.home)
	if err != nil {
		return err
	}
	if cfg.domain == "" {
		emit.Status(finding.Status{State: finding.StateMissingCredentials, Detail: noTenantHint})
		return nil
	}
	status := func(state finding.State, detail string) {
		emit.Status(finding.Status{Account: cfg.domain, State: state, Detail: detail})
	}
	token, state, why := c.token(ctx, cfg, req.Secrets[secretName])
	if state != "" {
		status(state, why)
		return nil
	}
	info, state, why := c.checkToken(ctx, cfg, token)
	if state != "" {
		status(state, why)
		return nil
	}
	if !info.reports {
		emit.Log(cfg.domain + ": the token lacks " + reportsScope + "; skipping token activity")
	}
	a := &audit{api: newAPI(c.apiURL, token, cfg.quotaProject), cfg: cfg, now: c.now().UTC(), emit: emit}
	a.run(ctx, info)
	return nil
}

func (c *Connector) token(ctx context.Context, cfg settings, secret string) (string, finding.State, string) {
	if secret != "" {
		return secret, "", ""
	}
	if _, err := os.Stat(filepath.Join(cfg.cloudsdkConfig, "application_default_credentials.json")); err != nil {
		return "", finding.StateMissingCredentials, loginHelp(cfg)
	}
	env := []string{"CLOUDSDK_CONFIG=" + cfg.cloudsdkConfig, "CLOUDSDK_CORE_DISABLE_PROMPTS=1"}
	r, err := c.gcloud(cfg.gcloudPath, env)
	if err != nil {
		return "", finding.StateUnsupported, err.Error() + ", or set the " + secretName + " secret"
	}
	out, err := readOnly.Guard(r).Run(ctx, "auth", "application-default", "print-access-token", "--scopes="+strings.Join(Scopes, ","))
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", finding.StateUnsupported, "gcloud not found: install the Google Cloud SDK, set gcloud_path, or set the " + secretName + " secret"
		}
		state := finding.StateError
		if strings.Contains(cli.Stderr(err), "invalid_grant") || strings.Contains(cli.Stderr(err), "Reauthentication") {
			state = finding.StateReauth
		}
		return "", state, fmt.Sprintf("gcloud could not issue a token for %s (%s).\n\n%s", cfg.domain, lastLine(cli.Stderr(err)), loginHelp(cfg))
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", finding.StateError, "gcloud printed an empty token for " + cfg.domain + ".\n\n" + loginHelp(cfg)
	}
	return token, "", ""
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

type tokenInfo struct {
	email   string
	reports bool
}

// checkToken posts the token in a form body, never a URL, so no error message can carry it.
func (c *Connector) checkToken(ctx context.Context, cfg settings, token string) (tokenInfo, finding.State, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenInfoURL,
		strings.NewReader(url.Values{"access_token": {token}}.Encode()))
	if err != nil {
		return tokenInfo{}, finding.StateError, err.Error()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return tokenInfo{}, finding.StateError, "tokeninfo: " + err.Error()
	}
	defer resp.Body.Close()
	var body struct {
		Scope            string `json:"scope"`
		Email            string `json:"email"`
		ErrorDescription string `json:"error_description"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(raw, &body)
	if resp.StatusCode != http.StatusOK {
		why := body.ErrorDescription
		if why == "" {
			why = resp.Status
		}
		return tokenInfo{}, finding.StateReauth, fmt.Sprintf("The token is not valid (%s).\n\n%s", why, loginHelp(cfg))
	}
	granted := strings.Fields(body.Scope)
	var missing []string
	for _, s := range requiredScopes {
		if !slices.Contains(granted, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		return tokenInfo{}, finding.StateMissingCredentials, fmt.Sprintf("The token lacks scopes: %s.\n\n%s", strings.Join(missing, ", "), loginHelp(cfg))
	}
	email := strings.ToLower(body.Email)
	if email != "" && !inDomain(email, cfg.domain) {
		return tokenInfo{}, finding.StateMissingCredentials, otherTenant(cfg.domain, "belong to "+email+", outside that domain")
	}
	return tokenInfo{email: email, reports: slices.Contains(granted, reportsScope)}, "", ""
}

func inDomain(email, domain string) bool {
	return strings.HasSuffix(strings.ToLower(email), "@"+domain)
}

func otherTenant(domain, why string) string {
	return fmt.Sprintf("The credentials for %s %s. Sign in again with an admin account of %s.", domain, why, domain)
}
