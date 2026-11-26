package googlepersonal

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

const (
	urlPasskeys           = "https://myaccount.google.com/signinoptions/passkeys"
	urlAdvancedProtection = "https://landing.google.com/advancedprotection/"
)

// signInSummary folds an account's Sign in with Google links into one finding: each link alone
// judges nothing, the list is what to review.
func signInSummary(account, connections string, signIns []finding.Finding) (finding.Finding, bool) {
	if len(signIns) == 0 {
		return finding.Finding{}, false
	}
	names := make([]string, 0, len(signIns))
	apps := make([]map[string]any, 0, len(signIns))
	for _, f := range signIns {
		names = append(names, f.Resource.Name)
		app := map[string]any{"name": f.Resource.Name, "url": f.Remediation.URL}
		if f.CreatedAt != nil {
			app["created_at"] = f.CreatedAt.Format(time.DateOnly)
		}
		apps = append(apps, app)
	}
	return finding.Finding{
		ID:       finding.StableID(name, account, "sign_in_with_google_summary"),
		Account:  account,
		Resource: finding.Resource{Type: "sign_in_with_google_summary", ID: account, Name: account},
		Kind:     finding.KindGrant,
		Severity: finding.SevInfo,
		Title:    fmt.Sprintf("%s is the Sign in with Google login for %d %s", account, len(signIns), textfmt.Plural(len(signIns), "app", "apps")),
		Evidence: map[string]any{"services": names, "apps": apps},
		Remediation: finding.Remediation{
			Summary: "Review the list once in a while. " + summarySignIn,
			URL:     connections,
		},
	}, true
}

type loginService struct {
	re    *regexp.Regexp
	moves bool // can move money out
}

// loginServices match the name or domain Google shows for a linked app.
var loginServices = []loginService{
	{rx(`\b(binance|bybit|coinbase|kraken|bitstamp|bitpanda|okx|kucoin|crypto\.com)\b`), true},
	{rx(`\b(wise|transferwise|revolut|paypal|stripe|n26|qonto|payoneer)\b`), true},
	{rx(`\b(bank|banco|banca|bbva|santander|caixabank|bankinter|sabadell|openbank|ibercaja|unicaja|kutxabank|abanca)\b`), true},
	{rx(`\b(crowdcube|wefunder|seedrs|angellist|republic\.co|startengine|indexa|myinvestor|trade republic|degiro|interactive brokers|cointracking|flexile)\b`), false},
	{rx(`\b(amazon web services|aws|cloudflare|digitalocean|hetzner|ovhcloud|vercel|netlify|heroku|supabase|microsoft azure)\b`), false},
}

func loginDependency(account string, apps []finding.Finding) (finding.Finding, bool) {
	var names []string
	moves := false
	seen := map[string]bool{}
	for _, f := range apps {
		n := f.Resource.Name
		for _, s := range loginServices {
			if s.re.MatchString(n) && !seen[n] {
				seen[n] = true
				names = append(names, n)
				moves = moves || s.moves
			}
		}
	}
	if len(names) == 0 {
		return finding.Finding{}, false
	}
	sev := finding.SevMedium
	if moves {
		sev = finding.SevHigh
	}
	return finding.Finding{
		ID:       finding.StableID(name, account, "google_login_dependency"),
		Account:  account,
		Resource: finding.Resource{Type: "google_login_dependency", ID: account, Name: account},
		Kind:     finding.KindSetting,
		Severity: sev,
		Title: fmt.Sprintf("Google account %s is the login for %d financial/cloud %s: use a passkey/security key and consider Advanced Protection",
			account, len(names), textfmt.Plural(len(names), "service", "services")),
		Evidence: map[string]any{"services": names, "can_move_money": moves},
		Blast:    finding.BlastLogin,
		Remediation: finding.Remediation{
			Summary: "Whoever takes over this Google account signs in to " + strings.Join(names, ", ") +
				". Add a passkey or security key and remove SMS as a second step, and consider Advanced Protection (" + urlAdvancedProtection +
				"), which then requires one at every sign-in. Where a service offers its own passkey or 2FA, turn it on too.",
			URL: urlPasskeys,
		},
	}, true
}
