package cloudflare

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/finding"
)

const (
	urlTokens    = "https://dash.cloudflare.com/profile/api-tokens"
	urlGlobalKey = "https://developers.cloudflare.com/fundamentals/api/get-started/keys/"
	url2FA       = "https://developers.cloudflare.com/fundamentals/user-profiles/2fa/"
	urlRoles     = "https://developers.cloudflare.com/fundamentals/manage-members/roles/"
	urlSSLModes  = "https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/"
	urlHTTPS     = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/"
	urlMinTLS    = "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/"
	urlDNSSEC    = "https://developers.cloudflare.com/dns/dnssec/"

	superAdminRole = "Super Administrator - All Privileges"

	resAllAccounts = "com.cloudflare.api.account.*"
	resAllZones    = "com.cloudflare.api.account.zone.*"
	resZone        = "com.cloudflare.api.account.zone."
	resAccount     = "com.cloudflare.api.account."
	resUser        = "com.cloudflare.api.user."
)

type apiToken struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	IssuedOn   *string   `json:"issued_on"`
	ModifiedOn *string   `json:"modified_on"`
	LastUsedOn *string   `json:"last_used_on"`
	ExpiresOn  *string   `json:"expires_on"`
	Condition  condition `json:"condition"`
	Policies   []policy  `json:"policies"`
}

// condition holds the client IP filter. The API guide writes the key "request.ip"; the API
// reference writes "request_ip". Both are read.
type condition struct {
	RequestIP    *ipFilter `json:"request.ip"`
	RequestIPAlt *ipFilter `json:"request_ip"`
}

type ipFilter struct {
	In    []string `json:"in"`
	NotIn []string `json:"not_in"`
}

func (c condition) ip() ipFilter {
	switch {
	case c.RequestIP != nil:
		return *c.RequestIP
	case c.RequestIPAlt != nil:
		return *c.RequestIPAlt
	}
	return ipFilter{}
}

type permissionGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type policy struct {
	Effect           string                     `json:"effect"`
	PermissionGroups []permissionGroup          `json:"permission_groups"`
	Resources        map[string]json.RawMessage `json:"resources"`
}

// canEdit reports whether a permission group grants more than reading. Cloudflare names read-only
// groups "… Read" or "… Read-Only"; anything else (Write, Edit, Admin, an unnamed group) counts as
// edit, so an unknown group is never taken for read-only.
func canEdit(g permissionGroup) bool {
	n := strings.ToLower(strings.TrimSpace(g.Name))
	return n == "" || !(strings.HasSuffix(n, " read") || strings.HasSuffix(n, " read-only"))
}

// scopes describes a policy's resources and lists the ones that cover every zone or every
// account the user can reach.
func scopes(res map[string]json.RawMessage) (desc, broad []string) {
	keys := make([]string, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch {
		case k == resAllAccounts:
			desc, broad = append(desc, "all accounts"), append(broad, "all accounts")
		case k == resAllZones:
			desc, broad = append(desc, "all zones"), append(broad, "all zones")
		case strings.HasPrefix(k, resZone):
			desc = append(desc, "zone "+strings.TrimPrefix(k, resZone))
		case strings.HasPrefix(k, resAccount):
			id := strings.TrimPrefix(k, resAccount)
			var nested map[string]json.RawMessage
			if json.Unmarshal(res[k], &nested) == nil && len(nested) > 0 {
				inner, _ := scopes(nested)
				for _, d := range inner {
					desc = append(desc, d+" of account "+id)
				}
				continue
			}
			desc = append(desc, "account "+id)
		case strings.HasPrefix(k, resUser):
			desc = append(desc, "your user")
		default:
			desc = append(desc, k)
		}
	}
	return desc, broad
}

// policySummary condenses a token's policies for the evidence and the severity rules.
type policySummary struct {
	lines []string
	edit  bool
	broad []string // edit permissions on all zones or all accounts
}

func summarize(ps []policy) policySummary {
	var s policySummary
	for _, p := range ps {
		var names []string
		edit := false
		for _, g := range p.PermissionGroups {
			n := g.Name
			if n == "" {
				n = g.ID
			}
			names = append(names, n)
			edit = edit || canEdit(g)
		}
		desc, broad := scopes(p.Resources)
		s.lines = append(s.lines, fmt.Sprintf("%s %s on %s", p.Effect, strings.Join(names, ", "), strings.Join(desc, ", ")))
		if p.Effect != "allow" || !edit {
			continue
		}
		s.edit = true
		for _, b := range broad {
			s.broad = append(s.broad, fmt.Sprintf("%s (%s)", b, strings.Join(names, ", ")))
		}
	}
	return s
}

// tokenFinding grades one user API token: no expiry, idle, edit rights without an IP filter,
// edit rights on every zone or account.
func tokenFinding(t apiToken, self bool, now time.Time) finding.Finding {
	issued, modified := httpx.ParseTime(t.IssuedOn), httpx.ParseTime(t.ModifiedOn)
	lastUsed, expires := httpx.ParseTime(t.LastUsedOn), httpx.ParseTime(t.ExpiresOn)
	pol := summarize(t.Policies)
	ip := t.Condition.ip()

	var a httpx.Assessment
	if t.Status != "active" {
		a = a.Done(t.Status + "; delete it if nobody will re-enable it")
	} else {
		if len(pol.broad) > 0 {
			a.Raise(finding.SevHigh, "can edit "+strings.Join(pol.broad, ", "))
		}
		if pol.edit && len(ip.In) == 0 {
			a.Raise(finding.SevMedium, "has edit permissions and no client IP restriction")
		}
		if expires == nil {
			a.Raise(finding.SevMedium, "never expires")
		}
		switch {
		case lastUsed != nil && now.Sub(*lastUsed) > httpx.IdleAfter:
			a.Raise(finding.SevMedium, fmt.Sprintf("unused for %d days", httpx.Days(now, *lastUsed)))
		case lastUsed == nil && issued != nil && now.Sub(*issued) > httpx.IdleAfter:
			a.Raise(finding.SevMedium, fmt.Sprintf("never used in the %d days since it was issued", httpx.Days(now, *issued)))
		}
		a = a.Done("expires, in use, and read-only or IP-restricted")
	}

	ev := map[string]any{"status": t.Status, "policies": pol.lines, "issues": a.Reasons}
	if expires != nil {
		ev["expires_on"] = expires.Format(time.RFC3339)
	}
	if modified != nil {
		ev["modified_on"] = modified.Format(time.RFC3339)
	}
	if len(ip.In) > 0 {
		ev["ip_in"] = ip.In
	}
	if len(ip.NotIn) > 0 {
		ev["ip_not_in"] = ip.NotIn
	}
	if self {
		ev["used_by_securizame"] = true
	}
	return finding.Finding{
		Account:    userAccount,
		Resource:   finding.Resource{Type: "cloudflare_api_token", ID: t.ID, Name: t.Name},
		Kind:       finding.KindCredential,
		Severity:   a.Severity,
		Title:      fmt.Sprintf("Cloudflare API token %q: %s", t.Name, strings.Join(a.Reasons, "; ")),
		Evidence:   ev,
		CreatedAt:  issued,
		LastUsedAt: lastUsed,
		Remediation: finding.Remediation{
			Summary: "Delete tokens nobody uses; give the rest an expiry (TTL), the narrowest zones and permissions, and Client IP Address Filtering when they can edit.",
			URL:     urlTokens,
		},
	}
}

// globalKeyFinding asks for a manual look: the API cannot list or describe the Global API Key.
func globalKeyFinding() finding.Finding {
	return finding.Finding{
		Account:  userAccount,
		Resource: finding.Resource{Type: "cloudflare_global_api_key", ID: "global_api_key", Name: "Global API Key"},
		Kind:     finding.KindCredential,
		Severity: finding.SevInfo,
		Title:    "Check the Cloudflare Global API Key by hand: the API cannot list it",
		Evidence: map[string]any{"why": "the Global API Key has every permission of the user, no expiry and no IP filter, and no endpoint reports whether it was ever viewed or used"},
		Remediation: finding.Remediation{
			Summary: "My Profile > API Tokens > API Keys > Global API Key: if anything still uses it, move that to a scoped token, then Change the key so old copies stop working.",
			URL:     urlGlobalKey,
		},
	}
}

type account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Settings *struct {
		EnforceTwofactor bool `json:"enforce_twofactor"`
	} `json:"settings"`
}

func (a account) label() string {
	if a.Name != "" {
		return a.Name
	}
	return a.ID
}

func accountFinding(a account, label string) finding.Finding {
	enforced := a.Settings != nil && a.Settings.EnforceTwofactor
	f := finding.Finding{
		Account:  label,
		Resource: finding.Resource{Type: "cloudflare_account", ID: a.ID, Name: a.Name},
		Kind:     finding.KindSetting,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("Cloudflare account %q requires two-factor authentication for members", label),
		Evidence: map[string]any{"enforce_twofactor": enforced, "type": a.Type},
		Remediation: finding.Remediation{
			Summary: "Manage Account > Members > Members 2FA enforcement: turn it on so every member needs a second factor.",
			URL:     url2FA,
		},
	}
	if !enforced {
		f.Severity = finding.SevHigh
		f.Title = fmt.Sprintf("Cloudflare account %q does not require two-factor authentication for members", label)
	}
	return f
}

type member struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Status string `json:"status"`
	Roles  []struct {
		Name string `json:"name"`
	} `json:"roles"`
	Policies []struct {
		Access           string            `json:"access"`
		PermissionGroups []permissionGroup `json:"permission_groups"`
	} `json:"policies"`
	User *struct {
		Email     string `json:"email"`
		TwoFactor bool   `json:"two_factor_authentication_enabled"`
	} `json:"user"`
}

func (m member) email() string {
	if m.User != nil && m.User.Email != "" {
		return m.User.Email
	}
	return m.Email
}

// roles lists role names and the permission groups of allow policies (newer memberships carry
// policies instead of roles), deduplicated.
func (m member) roles() []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, r := range m.Roles {
		add(r.Name)
	}
	for _, p := range m.Policies {
		if p.Access == "allow" {
			for _, g := range p.PermissionGroups {
				add(g.Name)
			}
		}
	}
	return out
}

func (m member) superAdmin() bool {
	for _, r := range m.roles() {
		if r == superAdminRole {
			return true
		}
	}
	return false
}

// memberFindings grades each member's second factor and counts the account's super administrators.
func memberFindings(accountID, label string, members []member, enforced bool) []finding.Finding {
	var admins []string
	var fs []finding.Finding
	for _, m := range members {
		roles := m.roles()
		ev := map[string]any{"status": m.Status, "roles": roles}
		f := finding.Finding{
			Account:  label,
			Resource: finding.Resource{Type: "cloudflare_member", ID: m.ID, Name: m.email()},
			Kind:     finding.KindGrant,
			Severity: finding.SevInfo,
			Title:    fmt.Sprintf("Member %s of Cloudflare account %q (%s)", m.email(), label, strings.Join(roles, ", ")),
			Evidence: ev,
			Remediation: finding.Remediation{
				Summary: "Remove members who no longer need the account and give the rest the narrowest role.",
				URL:     urlRoles,
			},
		}
		if m.Status == "accepted" && m.superAdmin() {
			admins = append(admins, m.email())
		}
		if m.User != nil {
			ev["two_factor"] = m.User.TwoFactor
			if m.Status == "accepted" && !m.User.TwoFactor {
				f.Severity = finding.SevMedium
				f.Title = fmt.Sprintf("Member %s of Cloudflare account %q has no two-factor authentication", m.email(), label)
				f.Remediation = finding.Remediation{
					Summary: "Ask the member to turn on two-factor authentication (My Profile > Authentication), and enforce it for the account.",
					URL:     url2FA,
				}
				if enforced {
					// Enforcement keeps them out until they enrol.
					f.Severity = finding.SevLow
				}
			}
		}
		fs = append(fs, f)
	}
	sort.Strings(admins)
	f := finding.Finding{
		Account:  label,
		Resource: finding.Resource{Type: "cloudflare_super_admins", ID: accountID, Name: label},
		Kind:     finding.KindGrant,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("Cloudflare account %q has %d super administrator(s)", label, len(admins)),
		Evidence: map[string]any{"super_administrators": admins},
		Remediation: finding.Remediation{
			Summary: "Keep one super administrator (two if a second person must be able to recover the account); give everyone else a narrower role.",
			URL:     urlRoles,
		},
	}
	if len(admins) > 1 {
		f.Severity = finding.SevMedium
		f.Title = fmt.Sprintf("Cloudflare account %q has %d super administrators", label, len(admins))
	}
	return append(fs, f)
}

type zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
}

func (z zone) accountLabel() string {
	switch {
	case z.Account.Name != "":
		return z.Account.Name
	case z.Account.ID != "":
		return z.Account.ID
	}
	return userAccount
}

// zoneSetting is one setting; value is a string for the ones read here.
type zoneSetting struct {
	ID    string          `json:"id"`
	Value json.RawMessage `json:"value"`
}

func (s zoneSetting) value() string {
	var v string
	if json.Unmarshal(s.Value, &v) == nil {
		return v
	}
	return strings.TrimSpace(string(s.Value))
}

type dnssec struct {
	Status string `json:"status"`
}

func zoneFinding(z zone, setting string, sev finding.Severity, title string, ev map[string]any, fix, link string) finding.Finding {
	return finding.Finding{
		Account:     z.accountLabel(),
		Resource:    finding.Resource{Type: "cloudflare_zone_setting", ID: z.ID + "/" + setting, Name: z.Name},
		Kind:        finding.KindSetting,
		Severity:    sev,
		Title:       title,
		Evidence:    ev,
		Remediation: finding.Remediation{Summary: fix, URL: link},
	}
}

// settingFinding grades one zone setting; ok is false for a setting this connector does not read.
func settingFinding(z zone, id, v string) (finding.Finding, bool) {
	ev := map[string]any{"setting": id, "value": v}
	switch id {
	case "ssl":
		sev, title := finding.SevInfo, fmt.Sprintf("Zone %s encrypts to the origin and validates its certificate (SSL mode %s)", z.Name, v)
		switch v {
		case "off":
			sev, title = finding.SevHigh, fmt.Sprintf("Zone %s has SSL off: visitors get plain HTTP", z.Name)
		case "flexible":
			sev, title = finding.SevMedium, fmt.Sprintf("Zone %s uses Flexible SSL: Cloudflare talks to the origin over plain HTTP", z.Name)
		case "full":
			sev, title = finding.SevLow, fmt.Sprintf("Zone %s uses Full SSL: the origin certificate is not validated", z.Name)
		}
		return zoneFinding(z, id, sev, title, ev, "SSL/TLS > Overview: use Full (strict) with a valid or Origin CA certificate on the origin.", urlSSLModes), true
	case "always_use_https":
		sev, title := finding.SevInfo, fmt.Sprintf("Zone %s redirects HTTP to HTTPS", z.Name)
		if v != "on" {
			sev, title = finding.SevLow, fmt.Sprintf("Zone %s does not redirect HTTP to HTTPS (Always Use HTTPS off)", z.Name)
		}
		return zoneFinding(z, id, sev, title, ev, "SSL/TLS > Edge Certificates > Always Use HTTPS: on.", urlHTTPS), true
	case "min_tls_version":
		sev, title := finding.SevInfo, fmt.Sprintf("Zone %s accepts TLS %s and newer", z.Name, v)
		if v == "1.0" || v == "1.1" {
			sev, title = finding.SevMedium, fmt.Sprintf("Zone %s still accepts TLS %s", z.Name, v)
		}
		return zoneFinding(z, id, sev, title, ev, "SSL/TLS > Edge Certificates > Minimum TLS Version: 1.2.", urlMinTLS), true
	}
	return finding.Finding{}, false
}

func dnssecFinding(z zone, status string) finding.Finding {
	sev, title := finding.SevInfo, fmt.Sprintf("Zone %s has DNSSEC %s", z.Name, status)
	switch status {
	case "disabled", "pending-disabled":
		sev, title = finding.SevLow, fmt.Sprintf("Zone %s does not sign its DNS (DNSSEC %s)", z.Name, status)
	case "error":
		sev, title = finding.SevLow, fmt.Sprintf("Zone %s has a DNSSEC error", z.Name)
	}
	return zoneFinding(z, "dnssec", sev, title, map[string]any{"setting": "dnssec", "status": status},
		"DNS > Settings > DNSSEC: enable it and add the DS record at the registrar (automatic when the registrar is Cloudflare).", urlDNSSEC)
}
