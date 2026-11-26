package connectedapps

import (
	"context"
	"regexp"

	"github.com/segurata/segurata/internal/finding"
)

// pageOnly is a service whose app list has never been seen with apps in it: anything but signed
// out or a verified empty list is unverified, never parsed by guesswork.
type pageOnly struct {
	title     string
	url       string
	signedOut *regexp.Regexp // URL
	empty     *regexp.Regexp // text; nil when never seen
	loaded    *regexp.Regexp // text once rendered
	hint      string         // appended to the signed-out detail
}

func (s pageOnly) run(ctx context.Context, e *env) {
	p, err := load(ctx, e, s.url, pageTextJS, func(p listPage) bool {
		return s.signedOut.MatchString(p.URL) || s.loaded.MatchString(p.Text)
	}, 40)
	if err != nil {
		e.fail("", err)
		return
	}
	switch {
	case p.URL == "" || s.signedOut.MatchString(p.URL):
		e.status("", finding.StateSignedOut, "not signed in in the browser: %s%s", s.url, s.hint)
	case s.empty != nil && s.empty.MatchString(p.Text):
		e.status("", finding.StateOK, "no connected apps")
	default:
		e.status("", finding.StateUnverified, "signed in, but segurata has never seen this page with apps on it, so it does not parse it: review %s by hand", s.url)
	}
}

var (
	// checked 2026-11-24 with no apps
	instagramPage = pageOnly{
		title:     "Instagram",
		url:       "https://www.instagram.com/accounts/manage_access/",
		signedOut: regexp.MustCompile(`/accounts/login|/challenge`),
		empty:     regexp.MustCompile(`(?i)No has autorizado a ninguna aplicación|(haven.t|have not) authorized any (app|application)s?`),
		loaded:    regexp.MustCompile(`(?i)No has autorizado|authorized any|Estos son los sitios web|These are (the )?(apps|websites)`),
	}

	// checked 2026-11-24 with none granted
	linkedinPage = pageOnly{
		title:     "LinkedIn",
		url:       "https://www.linkedin.com/mypreferences/d/data-sharing-for-permitted-services",
		signedOut: regexp.MustCompile(`/login|/authwall|/uas/|/checkpoint`),
		empty:     regexp.MustCompile(`(?i)not granted access to any services|No has (concedido|otorgado) acceso a ningún servicio`),
		loaded:    regexp.MustCompile(`(?i)Permitted services|Servicios permitidos`),
	}

	// Personal accounts only. login.live.com cannot tell a missing account from a signed-out one
	// without typing an address, hence the hint.
	microsoftPage = pageOnly{
		title:     "your Microsoft account",
		url:       "https://account.live.com/consent/Manage",
		signedOut: regexp.MustCompile(`login\.(live|microsoftonline)\.com`),
		loaded:    regexp.MustCompile(`(?s).{400}`),
		hint:      `. This page is for personal Microsoft accounts; with only a work or school account, leave "microsoft" out of the connected-apps "services" config (microsoft-work reads that account)`,
	}
)
