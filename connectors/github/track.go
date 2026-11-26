package github

import (
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

var checkPhrases = map[check]string{
	orgNo2FARequirement:      "Two-factor authentication not required",
	orgMembersNo2FA:          "Members without two-factor authentication",
	orgCollaboratorsNo2FA:    "Outside collaborators without two-factor authentication",
	orgDefaultPermission:     "Every member can write to every repository",
	orgWorkflowWrite:         "Workflows get a read and write GITHUB_TOKEN by default",
	orgAllActions:            "Workflows may use any action from any author",
	orgActionsApprovePRs:     "Workflows can create and approve pull requests",
	orgPublicRepoCreation:    "Members can create public repositories",
	orgNoPublicScanning:      "New public repositories get no secret scanning or push protection",
	orgNoPrivateScanning:     "New private repositories get no secret scanning or push protection",
	repoNoDependabotUpdates:  "Repositories without Dependabot security updates",
	repoForkNoSecretScanning: "Forks without secret scanning or push protection",
	repoForkWorkflowWrite:    "Forks whose workflows get a read and write GITHUB_TOKEN",
	repoPrivateNoScanning:    "Private repositories without secret scanning or push protection",
}

// Track groups an organization or repository-setting check into one item across organizations
// ("Two-factor authentication not required in 5 GitHub orgs") and a repository's own settings into
// one item per organization; a finding about a repository says which, for decision rules.
func (c *Connector) Track(f finding.Finding) *finding.Track {
	var t finding.Track
	if strings.Count(f.Resource.Name, "/") == 1 {
		t.Repo = f.Resource.Name
	}
	switch f.Resource.Type {
	case "github_org_setting", "github_repo_setting":
		phrase, ok := checkPhrases[check(f.Resource.ID)]
		if !ok {
			phrase = strings.ReplaceAll(strings.TrimPrefix(f.Resource.ID, "org-"), "-", " ")
		}
		t.Group, t.Count, t.Noun, t.Nouns = finding.GroupCheck, finding.CountAccounts, "GitHub org", "GitHub orgs"
		t.Title = phrase + " in {count}"
	case "github_repo":
		t.Group, t.Noun, t.Nouns = finding.GroupAccount, "repository", "repositories"
		t.Title = "Repository security settings off in {count} of " + f.Account
	default:
		if t.Repo == "" {
			return nil
		}
	}
	return &t
}
