package github

import (
	"fmt"
	"net/textproto"
	"strings"
)

// scopes come from X-OAuth-Scopes. A fine-grained or app token sends none: known is false, every
// check is attempted and refusals are read from the responses.
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

// has counts unknown scopes as held: the request is made and GitHub decides.
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

func refresh(scope string) string {
	return fmt.Sprintf("gh auth refresh -h github.com -s %s", scope)
}
