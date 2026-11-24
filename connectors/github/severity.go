package github

import "github.com/segurata/segurata/internal/finding"

// check names one thing this connector looks at. Its severity comes from the table below, so
// every finding of a kind gets the same answer.
type check string

const (
	accountNo2FA      check = "account-2fa-disabled"
	accountNo2FAOwner check = "account-2fa-disabled-org-owner"

	orgNo2FARequirement   check = "org-2fa-not-required"
	orgMembersNo2FA       check = "org-members-without-2fa"
	orgCollaboratorsNo2FA check = "org-outside-collaborators-without-2fa"
	orgDefaultPermission  check = "org-default-repository-permission"
	orgPublicRepoCreation check = "org-members-can-create-public-repos"
	orgWorkflowWrite      check = "org-default-workflow-permissions-write"
	orgActionsApprovePRs  check = "org-actions-can-approve-pull-requests"
	orgAllActions         check = "org-all-actions-allowed"
	orgNoPrivateScanning  check = "org-new-private-repos-without-secret-scanning"
	orgNoPublicScanning   check = "org-new-public-repos-without-secret-scanning"

	repoInsecureHook         check = "insecure-webhook"
	repoInsecureHookInactive check = "insecure-webhook-inactive"
	repoWriteDeployKey       check = "write-deploy-key"
	repoWorkflowWrite        check = "public-repo-workflow-write"
	repoNoSecretScanning     check = "secret-scanning-disabled"
	repoNoPushProtection     check = "push-protection-disabled"
	repoForkNoSecretScanning check = "fork-secret-scanning-disabled"
	repoNoDependabotUpdates  check = "dependabot-security-updates-disabled"
	repoUnprotectedDefault   check = "public-default-branch-unprotected"
)

var severities = map[check]finding.Severity{
	// The account's own 2FA guards everything else; owning organizations widens the blast radius.
	accountNo2FA:      finding.SevHigh,
	accountNo2FAOwner: finding.SevCritical,

	orgNo2FARequirement:   finding.SevHigh,
	orgMembersNo2FA:       finding.SevHigh,
	orgCollaboratorsNo2FA: finding.SevHigh,
	orgDefaultPermission:  finding.SevMedium, // every member can push to (or administer) every repository
	orgPublicRepoCreation: finding.SevLow,
	orgWorkflowWrite:      finding.SevMedium,
	orgActionsApprovePRs:  finding.SevLow,
	orgAllActions:         finding.SevLow,
	orgNoPrivateScanning:  finding.SevMedium,
	orgNoPublicScanning:   finding.SevLow, // secret scanning is free on public repositories, but not on by default here

	repoInsecureHook:         finding.SevHigh, // payloads, and the signing secret, sent in clear or to an unverified host
	repoInsecureHookInactive: finding.SevMedium,
	repoWriteDeployKey:       finding.SevMedium,
	repoWorkflowWrite:        finding.SevMedium,
	repoNoSecretScanning:     finding.SevMedium,
	repoNoPushProtection:     finding.SevMedium,
	repoForkNoSecretScanning: finding.SevLow, // a fork rarely receives your own commits
	repoNoDependabotUpdates:  finding.SevLow,
	repoUnprotectedDefault:   finding.SevLow,
}

// issue is one failed check on a repository, kept in the repository's single finding.
type issue struct {
	Check    check            `json:"check"`
	Severity finding.Severity `json:"severity"`
	Detail   string           `json:"detail"`
	fix, url string
}

func newIssue(c check, detail, fix, url string) issue {
	return issue{Check: c, Severity: severities[c], Detail: detail, fix: fix, url: url}
}
