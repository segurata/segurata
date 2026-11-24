package github

import (
	"fmt"
	"net/textproto"
	"strings"
)

// scopes are the OAuth scopes of gh's token, from the X-OAuth-Scopes header. A fine-grained or
// app token sends no such header: known is false and every check is attempted, with refusals
// read from the responses instead.
type scopes struct {
	known bool
	set   map[string]bool
}

// implied lists the scopes that include another one (docs.github.com, "Scopes for OAuth apps").
var implied = map[string][]string{
	"read:user": {"user"},
	"read:org":  {"write:org", "admin:org"},
}

func parseScopes(h textproto.MIMEHeader) scopes {
	v, ok := h["X-Oauth-Scopes"]
	if !ok {
		return scopes{}
	}
	s := scopes{known: true, set: map[string]bool{}}
	for _, f := range strings.Split(strings.Join(v, ","), ",") {
		if f = strings.TrimSpace(f); f != "" {
			s.set[f] = true
		}
	}
	return s
}

// has reports whether the token holds the scope or one that includes it. Unknown scopes count as
// held: the request is made and GitHub decides.
func (s scopes) has(scope string) bool {
	if !s.known || s.set[scope] {
		return true
	}
	for _, wider := range implied[scope] {
		if s.set[wider] {
			return true
		}
	}
	return false
}

// refresh is the command that adds a scope to gh's token, keeping the ones it has.
func refresh(scope string) string {
	return fmt.Sprintf("gh auth refresh -h github.com -s %s", scope)
}
