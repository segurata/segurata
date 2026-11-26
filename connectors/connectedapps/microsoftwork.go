package connectedapps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/finding"
)

// Microsoft work and school accounts, checked 2026-11-24. My Apps fills its tiles from one call,
// api/v2/me/tiles; AzureADThirdParty tiles are the tenant's enterprise apps, without permissions.
// No user page lists delegated consents: only an admin reads them, in the Entra admin center.
// Security info asks for a fresh MFA sign-in first, so its reauth carries its own scope and leaves
// the apps inspected; the page past the prompt has not been seen, so it is reported unverified.
const (
	msWorkAppsURL       = "https://myapplications.microsoft.com/"
	msWorkSecurityURL   = "https://mysignins.microsoft.com/security-info"
	msWorkSecurityScope = "microsoft-work:security-info"
	msWorkRevoke        = "My Apps cannot revoke an app. If you no longer use it, a tenant admin removes your access in the Microsoft Entra admin center › Enterprise applications › the app › Users and groups, and its delegated permissions under Permissions."
)

var (
	msWorkTilesRE = regexp.MustCompile(`api\.myapplications\.microsoft\.com/api/v2/me/tiles`)
	msLoginRE     = regexp.MustCompile(`^https://login\.(microsoftonline|live|microsoft)\.com/`)
	msMFAClaimRE  = regexp.MustCompile(`(?i)[?&]claims=[^&]*mfa`)
	msStepUpRE    = regexp.MustCompile(`(?i)Especificar el código|Escriba el código|Enter code|Enter the code|Aprobar (la )?solicitud de inicio de sesión|Approve sign[- ]in request|Verify your identity|Comprobar (su|tu) identidad|Verificar (su|tu) identidad`)

	msWorkAppsJS     = fetchedJS("/api/v2/me/tiles")
	msWorkSecurityJS = fetchedJS("/api/authenticationmethods/")
)

// msLoginState is "" off Microsoft's sign-in host, reauth when it asks for a second factor, and
// signedout otherwise.
func msLoginState(p fetchPage) finding.State {
	switch {
	case !msLoginRE.MatchString(p.URL):
		return ""
	case msMFAClaimRE.MatchString(p.URL) || msStepUpRE.MatchString(p.Text):
		return finding.StateReauth
	}
	return finding.StateSignedOut
}

var msStepUpMethods = []struct {
	re   *regexp.Regexp
	what string
}{
	{rx(`Authenticator`), "the Microsoft Authenticator app"},
	{rx(`passkey|clave de acceso|security key|llave de seguridad`), "a passkey or security key"},
	{rx(`text|SMS|mensaje`), "an SMS code"},
	{rx(`call|llam`), "a phone call"},
}

func msStepUpMethod(text string) string {
	for _, m := range msStepUpMethods {
		if m.re.MatchString(text) {
			return m.what
		}
	}
	return ""
}

// msReady passes on two reads in a row that have fetched the list or show the same sign-in page:
// My Apps passes through the sign-in host on every load, and a prompt fills in after its URL.
func msReady() func(fetchPage) bool {
	var prev *fetchPage
	return func(p fetchPage) bool {
		was := prev
		prev = nil
		if p.URL == "" {
			return false
		}
		login := !p.Fetched && msLoginState(p) != "" && strings.TrimSpace(p.Text) != ""
		if !p.Fetched && !login {
			return false
		}
		prev = &p
		return was != nil && (p.Fetched && was.Fetched || login && was.URL == p.URL && was.Text == p.Text)
	}
}

func microsoftWork(ctx context.Context, e *env) {
	p, resp, err := capture(ctx, e, msWorkAppsURL, msWorkAppsJS, msReady(), 60, msWorkTilesRE)
	if err != nil {
		e.fail("", err)
		return
	}
	switch st := msLoginState(p); {
	case p.URL == "" || st == finding.StateSignedOut:
		e.status("", finding.StateSignedOut, "not signed in to a Microsoft work or school account in the browser: %s", msWorkAppsURL)
		return
	case st == finding.StateReauth:
		e.status("", finding.StateReauth, "Microsoft asks for a second factor before My Apps: open %s, complete it, and run again", msWorkAppsURL)
		return
	}
	if tiles, err := parseMSTiles(resp); err != nil {
		e.status("", finding.StateUnverified, "%v, so segurata does not parse it: review %s by hand", err, msWorkAppsURL)
	} else {
		msWorkApps(e, tiles)
	}
	msWorkSecurityInfo(ctx, e)
}

func msWorkApps(e *env, tiles []msTile) {
	others := map[string]int{}
	listed := 0
	for _, t := range tiles {
		if t.Provider != "AzureADThirdParty" {
			others[t.Provider]++
			continue
		}
		listed++
		e.report(grant{resType: "microsoft_work_app", name: t.DisplayName, key: t.ProviderID, url: msWorkAppsURL, revoke: msWorkRevoke,
			note:  "My Apps does not show the permissions an app holds; a tenant admin sees them in the Microsoft Entra admin center › Enterprise applications › the app › Permissions",
			extra: map[string]any{"assignment_type": t.AssignmentType}})
	}
	e.status("", finding.StateOK, "%d enterprise apps in My Apps%s; delegated permissions are not shown to users", listed, msOthers(others))
}

// msOthers words the tiles not listed, by provider: "; not listed: 6 OfficeFirstParty".
func msOthers(others map[string]int) string {
	if len(others) == 0 {
		return ""
	}
	var parts []string
	for p, n := range others {
		parts = append(parts, fmt.Sprintf("%d %s", n, p))
	}
	sort.Strings(parts)
	return "; not listed: " + strings.Join(parts, ", ")
}

// msTile drops the launch URLs, which carry the sign-in name.
type msTile struct {
	Provider       string `json:"provider"`
	ProviderID     string `json:"providerId"`
	DisplayName    string `json:"displayName"`
	AssignmentType string `json:"assignmentType"`
}

func parseMSTiles(resp *cdp.Response) ([]msTile, error) {
	if resp == nil {
		return nil, errors.New("My Apps did not fetch its app tiles")
	}
	var body struct {
		Value *[]msTile `json:"value"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.Value == nil {
		return nil, fmt.Errorf("My Apps' tiles did not have the expected shape (HTTP %d)", resp.Status)
	}
	return *body.Value, nil
}

func msWorkSecurityInfo(ctx context.Context, e *env) {
	status := func(st finding.State, format string, args ...any) {
		e.emit.Status(finding.Status{Account: e.account(""), Scope: msWorkSecurityScope, State: st, Detail: fmt.Sprintf(format, args...)})
	}
	p, err := load(ctx, e, msWorkSecurityURL, msWorkSecurityJS, msReady(), 60)
	if err != nil {
		status(finding.StateError, "%v", err)
		return
	}
	switch msLoginState(p) {
	case finding.StateReauth:
		why := "tenant policy"
		if m := msStepUpMethod(p.Text); m != "" {
			why += "; the prompt asks for " + m
		}
		status(finding.StateReauth, "Security info asks for a fresh MFA sign-in (%s): open %s, complete it, and run again", why, msWorkSecurityURL)
	case finding.StateSignedOut:
		status(finding.StateSignedOut, "not signed in to Security info in the browser: %s", msWorkSecurityURL)
	default:
		status(finding.StateUnverified, "segurata has never seen Security info past the MFA prompt, so it does not parse it: check by hand at %s that an authenticator app, passkey or security key is registered, not only a phone", msWorkSecurityURL)
	}
}
