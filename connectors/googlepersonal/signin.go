package googlepersonal

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// SignInPage is the account's connections page, which Google replaces with "Verify it's you"
// until the owner signs in again.
func (GooglePersonal) SignInPage(st finding.Status) (connector.SignInPage, bool) {
	switch st.State {
	case finding.StateReauth:
		if !strings.Contains(st.Account, "@") {
			return connector.SignInPage{}, false
		}
		return connectionsSignIn("https://myaccount.google.com/connections?authuser="+url.QueryEscape(st.Account),
			"sign in to "+st.Account+" again in Google (\"Verify it's you\")", st.Account), true
	case finding.StateSignedOut:
		return connectionsSignIn(connectionsURL(0), "sign in to your Google account", ""), true
	}
	return connector.SignInPage{}, false
}

func connectionsSignIn(u, do, account string) connector.SignInPage {
	return connector.SignInPage{
		URL:  u,
		Do:   do,
		Expr: connectionsJS,
		Done: func(raw json.RawMessage) bool { return connectionsShown(raw, account) },
	}
}

// connectionsShown accepts any account when account is empty.
func connectionsShown(raw json.RawMessage, account string) bool {
	p, ok := decode[connectionsPage](raw)
	if !ok || p.Mail == "" || isReauth(p.Text) || !strings.HasPrefix(p.URL, "https://myaccount.google.com/") {
		return false
	}
	if account != "" && !strings.EqualFold(p.Mail, account) {
		return false
	}
	return len(p.Apps) > 0 || len(p.Text) > 200
}
