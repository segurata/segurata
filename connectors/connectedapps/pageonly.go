package connectedapps

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/segurata/segurata/internal/finding"
)

// pageOnly is a service whose app list has never been seen with apps in it. It tells a signed-out
// browser and a verified empty list apart; anything else is reported as unverified, with the
// page to review by hand, rather than parsed by guesswork.
type pageOnly struct {
	url       string
	signedOut *regexp.Regexp // matches the URL a signed-out browser lands on
	empty     *regexp.Regexp // matches the empty list's text; nil when it was never seen
	loaded    *regexp.Regexp // matches text present once the page has rendered
}

func (s pageOnly) run(ctx context.Context, e *env) {
	raw, err := e.b.load(ctx, s.url, pageTextJS, func(raw json.RawMessage) bool {
		p, ok := decode[listPage](raw)
		return ok && (s.signedOut.MatchString(p.URL) || s.loaded.MatchString(p.Text))
	}, 40)
	if err != nil {
		e.fail("", err)
		return
	}
	p, _ := decode[listPage](raw)
	switch {
	case p.URL == "" || s.signedOut.MatchString(p.URL):
		e.status("", finding.StateSignedOut, "not signed in in the browser: %s", s.url)
	case s.empty != nil && s.empty.MatchString(p.Text):
		e.status("", finding.StateOK, "no connected apps")
	default:
		e.status("", finding.StateUnverified, "signed in, but segurata has never seen this page with apps on it, so it does not parse it: review %s by hand", s.url)
	}
}

var (
	// Checked 2026-11-24, signed in with no apps: "Apps and websites", tabs Active, Expired,
	// Removed, then the empty message.
	instagram = pageOnly{
		url:       "https://www.instagram.com/accounts/manage_access/",
		signedOut: regexp.MustCompile(`/accounts/login|/challenge`),
		empty:     regexp.MustCompile(`(?i)No has autorizado a ninguna aplicación|(haven.t|have not) authorized any (app|application)s?`),
		loaded:    regexp.MustCompile(`(?i)No has autorizado|authorized any|Estos son los sitios web|These are (the )?(apps|websites)`),
	}.run

	// /mypreferences/d/permitted-services now redirects to data-sharing-for-permitted-services,
	// which is where the list of permitted services lives. Checked 2026-11-24 with none granted.
	linkedin = pageOnly{
		url:       "https://www.linkedin.com/mypreferences/d/data-sharing-for-permitted-services",
		signedOut: regexp.MustCompile(`/login|/authwall|/uas/|/checkpoint`),
		empty:     regexp.MustCompile(`(?i)not granted access to any services|No has (concedido|otorgado) acceso a ningún servicio`),
		loaded:    regexp.MustCompile(`(?i)Permitted services|Servicios permitidos`),
	}.run

	// Signed out when this connector was written: only the sign-in redirect is known.
	microsoft = pageOnly{
		url:       "https://account.live.com/consent/Manage",
		signedOut: regexp.MustCompile(`login\.(live|microsoftonline)\.com`),
		loaded:    regexp.MustCompile(`(?s).{400}`),
	}.run

	dropbox = pageOnly{
		url:       "https://www.dropbox.com/account/connected_apps",
		signedOut: regexp.MustCompile(`dropbox\.com/login`),
		loaded:    regexp.MustCompile(`(?s).{400}`),
	}.run
)
