package connectedapps

import (
	"fmt"
	"strings"
)

// dependency is a grant segurata runs on: the fix is to narrow it, never revoke it.
type dependency struct {
	label  string
	fix    string
	remove []string // as `gh auth refresh -r` names them
}

// ghRemovable maps the scopes segurata does not need, as GitHub's app page words them, to gh's
// names. gh refuses to remove its minimum (repo, read:org, gist).
var ghRemovable = []struct{ text, scope string }{
	{"Delete repositories", "delete_repo"},
	{"Full control of orgs and teams", "admin:org"},
	{"Full control of enterprises", "admin:enterprise"},
}

func dependencyOf(g grant) (dependency, bool) {
	if g.resType != "github_oauth_app" || g.name != "GitHub CLI" {
		return dependency{}, false
	}
	var remove []string
	for _, r := range ghRemovable {
		for _, s := range g.scopes {
			if strings.HasPrefix(s, r.text) {
				remove = append(remove, r.scope)
				break
			}
		}
	}
	fix := "segurata reads GitHub through gh: do not revoke it."
	if len(remove) > 0 {
		fix += fmt.Sprintf(" Drop the scopes it does not need with `gh auth refresh -h github.com -r %s`", strings.Join(remove, ","))
		fix += " (`segurata remediate` runs it in your terminal)"
		fix += " and give segurata a read-only token (a fine-grained token with read-only permissions, in GH_TOKEN for its runs). Without admin:org the github connector reports the organization settings check as noscope."
	} else {
		fix += " Its scopes hold nothing segurata would drop; keep it."
	}
	return dependency{label: "segurata depends on it", fix: fix, remove: remove}, true
}
