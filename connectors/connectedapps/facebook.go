package connectedapps

import (
	"context"
	"net/url"
	"regexp"

	"github.com/segurata/segurata/connectors/internal/pagetext"
	"github.com/segurata/segurata/internal/finding"
)

// Settings › Apps and websites (checked 2026-11-24) shows the first apps and a "See more" button
// that fetches the rest: segurata does not click it, and the status says the list was cut.
// Accounts Center's "App connections" is a different list (Meta AI links to other services).
const (
	fbURL    = "https://www.facebook.com/settings/?tab=applications"
	fbRevoke = `Open the page and choose "Remove". Facebook offers to delete the posts the app made; the app keeps data it already received.`
)

const fbAppSel = `a[href*="/settings/applications/app_details/"]`

var fbListJS = inPage(`
  const more = [...document.querySelectorAll('[role=button], button')].some((b) => /^(Ver más aplicaciones|See more apps)/i.test((b.getAttribute("aria-label") || b.innerText || "").trim()));
  return {...page, rows: rows('` + fbAppSel + `'), more};`)

type fbListPage struct {
	listPage
	More bool `json:"more"`
}

var (
	fbSignedOutRE = regexp.MustCompile(`/login`)
	fbReauthRE    = regexp.MustCompile(`/checkpoint`)
	fbLoadedRE    = regexp.MustCompile(`(?i)aplicaciones y sitios web suprimidos|removed apps and websites`)
	fbAddedRE     = regexp.MustCompile(`^(Añadida el|Added on|Added) (.+)$`)
	fbStateRE     = regexp.MustCompile(`^(Activa|Active|Caducada|Expired|Suprimida|Removed)$`)
	fbButtonRE    = regexp.MustCompile(`^(Ver y editar|View and edit|Suprimir|Remove)$`)
	fbSharingRE   = regexp.MustCompile(`(?m)^(Información que estás compartiendo con|Info(rmation)? you.re sharing with) `)
	fbShareEndRE  = regexp.MustCompile(`^(To learn more|Para (obtener|saber) más|If you contact|Si te pones en contacto|Condiciones y|Terms and|Denunciar|Report this)`)
	fbNoiseRE     = regexp.MustCompile(`^(Esto forma parte|This is part of|Obligatori|Required|Opcional|Optional|Desactivad|Turned off)`)
	fbLoginWithRE = regexp.MustCompile(`^(Sesión iniciada con Facebook|Logged in with Facebook)$`)
	fbAudienceRE  = regexp.MustCompile(`^(Solo yo|Only me|Amigos|Friends|Público|Public|Personalizado|Custom)$`)
)

type fbApp struct {
	id, name, added, state, href string
}

func parseFacebookRow(r row) fbApp {
	a := fbApp{href: r.Href}
	if u, err := url.Parse(r.Href); err == nil {
		a.id = u.Query().Get("app_id")
	}
	for _, l := range r.Lines {
		switch {
		case fbButtonRE.MatchString(l):
		case fbAddedRE.MatchString(l):
			a.added = fbAddedRE.FindStringSubmatch(l)[2]
		case fbStateRE.MatchString(l):
			a.state = l
		case a.name == "":
			a.name = l
		}
	}
	return a
}

type fbDetail struct {
	scopes   []string // never nil
	login    bool     // also a Facebook login
	audience string   // of what the app posts for you
}

func parseFacebookDetail(text string) fbDetail {
	d := fbDetail{scopes: []string{}}
	in := false
	for _, l := range pagetext.Lines(text) {
		switch {
		case fbLoginWithRE.MatchString(l):
			d.login = true
		case !in && d.audience == "" && fbAudienceRE.MatchString(l):
			d.audience = l
		case fbSharingRE.MatchString(l):
			in = true
		case !in:
		case fbShareEndRE.MatchString(l):
			return d
		case !fbNoiseRE.MatchString(l):
			d.scopes = append(d.scopes, l)
		}
	}
	return d
}

// fbListed: apps, or the removed-apps section every list has.
func fbListed(p fbListPage) bool { return len(p.Rows) > 0 || fbLoadedRE.MatchString(p.Text) }

func facebook(ctx context.Context, e *env) {
	p, err := load(ctx, e, fbURL, fbListJS, func(p fbListPage) bool {
		return fbSignedOutRE.MatchString(p.URL) || fbReauthRE.MatchString(p.URL) || fbListed(p)
	}, 40)
	if err != nil {
		e.fail("", err)
		return
	}
	switch {
	case p.URL == "" || fbSignedOutRE.MatchString(p.URL):
		e.status("", finding.StateSignedOut, "not signed in to Facebook in the browser: %s", fbURL)
		return
	case fbReauthRE.MatchString(p.URL):
		e.status("", finding.StateReauth, "Facebook wants you to confirm your identity: open %s and run again", fbURL)
		return
	case len(p.Rows) == 0:
		e.status("", finding.StateUnverified, "no apps found on %s; the empty list was never seen, so check it by hand", fbURL)
		return
	}
	failed := 0
	for _, r := range p.Rows {
		if ctx.Err() != nil {
			return
		}
		a := parseFacebookRow(r)
		dp, err := load(ctx, e, a.href, pageTextJS, func(p listPage) bool { return fbSharingRE.MatchString(p.Text) }, 30)
		var d fbDetail
		if err != nil {
			failed++
			e.status("", finding.StateError, "%s: %v", a.name, err)
		} else {
			d = parseFacebookDetail(dp.Text)
		}
		e.report(grant{resType: "facebook_app", name: a.name, scopes: d.scopes, created: pagetext.Date(a.added, e.now),
			url: a.href, revoke: fbRevoke, extra: map[string]any{"state": a.state, "facebook_login": d.login, "audience": d.audience, "app_id": a.id}})
	}
	more := ""
	if p.More {
		more = `; Facebook lists more behind "See more", which segurata does not click: review the rest at ` + fbURL
	}
	e.status("", finding.StateOK, "%d apps, %d without details%s", len(p.Rows), failed, more)
}
