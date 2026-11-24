package connectedapps

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// SignInPage is where the owner clears a signedout or reauth status: the page the service's run
// reads, which the service replaces with its sign-in or confirmation page until the owner is
// through. Each page is through on the same tests the run applies (signed-out URL gone, list or
// empty message shown). A status about the gh CLI has no page: its detail names the command.
func (*Connector) SignInPage(st finding.Status) (connector.SignInPage, bool) {
	service, who, _ := strings.Cut(st.Account, ":")
	if st.State != finding.StateSignedOut && st.State != finding.StateReauth {
		return connector.SignInPage{}, false
	}
	signedOut := st.State == finding.StateSignedOut
	switch service {
	case "github":
		switch {
		case signedOut && strings.Contains(st.Detail, "in the browser"):
			return listSignIn(ghSettings+"/applications", "sign in to GitHub", ghOAuthJS, func(p listPage) bool {
				return ghOnSettings(p) && ghListReady(p)
			}), true
		case !signedOut:
			u, js := ghSettings+"/apps/authorizations", ghAuthorizedJS
			if strings.Contains(st.Detail, "/installations") {
				u, js = ghSettings+"/installations", ghInstalledJS
			}
			p := listSignIn(u, "confirm your GitHub password or passkey (sudo mode lasts minutes: segurata runs connected-apps right after)", js, func(p listPage) bool {
				return ghOnSettings(p) && !ghSudo(p) && ghListReady(p)
			})
			p.Brief = true
			return p, true
		}
	case "x":
		if signedOut {
			return listSignIn(xURL, "sign in to X", xJS, func(p listPage) bool { return !xSignedOutRE.MatchString(p.URL) && xReady(p) }), true
		}
	case "slack":
		if !signedOut {
			break
		}
		if who == "" {
			return listSignIn(slackSignin, "sign in to your Slack workspaces", slackSigninJS, slackSignedIn), true
		}
		return listSignIn("https://"+who+"/apps/manage", "sign in to the Slack workspace "+who, slackAppsJS, func(p listPage) bool {
			return !slackSignedOutRE.MatchString(p.URL) && slackListed(p)
		}), true
	case "notion":
		if signedOut {
			return connector.SignInPage{URL: notionURL, Do: "sign in to Notion", Expr: notionJS, Done: func(raw json.RawMessage) bool {
				p, ok := decode[notionPage](raw)
				return ok && p.URL != "" && !notionSignedOutRE.MatchString(p.URL) && notionListed(p)
			}}, true
		}
	case "facebook":
		do := "sign in to Facebook"
		if !signedOut {
			do = "confirm your identity on Facebook"
		}
		return connector.SignInPage{URL: fbURL, Do: do, Expr: fbListJS, Done: func(raw json.RawMessage) bool {
			p, ok := decode[fbListPage](raw)
			return ok && p.URL != "" && !fbSignedOutRE.MatchString(p.URL) && !fbReauthRE.MatchString(p.URL) && fbListed(p)
		}}, true
	default:
		if s, ok := pageOnlyServices[service]; ok && signedOut {
			return listSignIn(s.page.url, "sign in to "+s.title, pageTextJS, func(p listPage) bool {
				return !s.page.signedOut.MatchString(p.URL) && s.page.loaded.MatchString(p.Text)
			}), true
		}
	}
	return connector.SignInPage{}, false
}

// pageOnlyServices are the services read by a pageOnly, with the name the owner knows them by.
var pageOnlyServices = map[string]struct {
	page  pageOnly
	title string
}{
	"instagram": {instagramPage, "Instagram"},
	"linkedin":  {linkedinPage, "LinkedIn"},
	"microsoft": {microsoftPage, "your Microsoft account"},
	"dropbox":   {dropboxPage, "Dropbox"},
}

// listSignIn is a sign-in page whose expression returns a listPage: through once the URL is set and
// through accepts it.
func listSignIn(u, do, expr string, through func(listPage) bool) connector.SignInPage {
	return connector.SignInPage{URL: u, Do: do, Expr: expr, Done: readyWhen(func(p listPage) bool { return p.URL != "" && through(p) })}
}

// ghOnSettings reports whether the page is one of GitHub's settings pages, not the sign-in or
// sudo form it redirects to.
func ghOnSettings(p listPage) bool {
	u, err := url.Parse(p.URL)
	return err == nil && u.Host == "github.com" && strings.HasPrefix(u.Path, "/settings/") && !ghSignedOut(p)
}
