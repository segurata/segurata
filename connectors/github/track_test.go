package github

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestTrack(t *testing.T) {
	c := New()
	res := func(typ, id, name string) finding.Finding {
		return finding.Finding{Account: "acme", Resource: finding.Resource{Type: typ, ID: id, Name: name}}
	}
	org := c.Track(res("github_org_setting", string(orgNo2FARequirement), "acme"))
	if org.Group != finding.GroupCheck || org.Count != finding.CountAccounts || org.Title != "Two-factor authentication not required in {count}" || org.Nouns != "GitHub orgs" {
		t.Errorf("org check %+v", org)
	}
	if got := c.Track(res("github_org_setting", "org-some-new-check", "acme")).Title; got != "some new check in {count}" {
		t.Errorf("unknown check %q", got)
	}
	repo := c.Track(res("github_repo", "1", "acme/api"))
	if repo.Group != finding.GroupAccount || repo.Repo != "acme/api" || repo.Title != "Repository security settings off in {count} of acme" {
		t.Errorf("repo %+v", repo)
	}
	if got := c.Track(res("github_account", "two-factor-authentication", "me")); got != nil {
		t.Errorf("account finding groups by default, got %+v", got)
	}
}
