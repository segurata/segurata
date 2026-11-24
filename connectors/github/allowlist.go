package github

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
)

// seg is one owner, repository or URL-escaped branch name in a path. "." and "..", escaped or
// not, are refused separately, so a path cannot climb out of the endpoint it names.
const seg = `[A-Za-z0-9_.%-]+`

// readPaths are the only REST paths this connector may request, each with the query string it
// always sends. Every one is a GET documented at docs.github.com/rest (checked 2026-11-24).
var readPaths = compile(
	`/rate_limit`,
	`/user`,
	`/user/memberships/orgs\?state=active&per_page=100`,
	`/orgs/`+seg,
	`/orgs/`+seg+`/members\?filter=2fa_disabled&per_page=100`,
	`/orgs/`+seg+`/outside_collaborators\?per_page=100`,
	`/orgs/`+seg+`/outside_collaborators\?filter=2fa_disabled&per_page=100`,
	`/orgs/`+seg+`/code-security/configurations/defaults`,
	`/orgs/`+seg+`/actions/permissions`,
	`/orgs/`+seg+`/actions/permissions/workflow`,
	`/user/repos\?affiliation=owner,organization_member&per_page=100`,
	`/repos/`+seg+`/`+seg,
	`/repos/`+seg+`/`+seg+`/hooks\?per_page=100`,
	`/repos/`+seg+`/`+seg+`/keys\?per_page=100`,
	`/repos/`+seg+`/`+seg+`/actions/permissions`,
	`/repos/`+seg+`/`+seg+`/actions/permissions/workflow`,
	`/repos/`+seg+`/`+seg+`/branches/`+seg+`/protection`,
	`/repos/`+seg+`/`+seg+`/rules/branches/`+seg+`\?per_page=100`,
)

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(`^` + p + `$`)
	}
	return out
}

// readOnly admits exactly `gh api --method GET [--include|--paginate] <path>` with a path from
// readPaths. Fields (-f, -F, --input) would turn the request into a POST, so no other flag is
// accepted, in any position.
var readOnly = cli.CheckFunc(func(args []string) error {
	if allowed(args) {
		return nil
	}
	return fmt.Errorf("%w: gh %s", cli.ErrRefused, strings.Join(args, " "))
})

func allowed(args []string) bool {
	if len(args) < 4 || args[0] != "api" || args[1] != "--method" || args[2] != "GET" {
		return false
	}
	rest := args[3:]
	if len(rest) == 2 {
		if rest[0] != "--include" && rest[0] != "--paginate" {
			return false
		}
		rest = rest[1:]
	}
	return len(rest) == 1 && allowedPath(rest[0])
}

func allowedPath(p string) bool {
	path, _, _ := strings.Cut(p, "?")
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return false
	}
	for _, s := range strings.Split(decoded, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	for _, re := range readPaths {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}
