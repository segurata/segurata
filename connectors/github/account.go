package github

import (
	"context"

	"github.com/segurata/segurata/internal/finding"
)

type user struct {
	Login string `json:"login"`
	// TwoFactor is only in the private profile, which needs read:user; nil without it.
	TwoFactor *bool `json:"two_factor_authentication"`
}

func (r *run) user(ctx context.Context) (user, bool) {
	var u user
	if err := r.get(ctx, "/user", &u); err != nil || u.Login == "" {
		if err == nil {
			r.status("github", finding.StateError, "gh api /user returned no login")
		} else {
			r.status("github", stateOf(err), "%s", describe(err, "check `gh auth status`"))
		}
		return u, false
	}
	return u, true
}

func (r *run) account2FA(u user, ownsOrgs bool) {
	acct := account(u.Login)
	switch {
	case u.TwoFactor == nil:
		r.scopedStatus(acct, userScope(u.Login), finding.StateNoScope, "two-factor authentication not checked: gh's token lacks read:user; run: %s", refresh("read:user"))
		return
	case *u.TwoFactor:
		return
	}
	c := accountNo2FA
	if ownsOrgs {
		c = accountNo2FAOwner
	}
	r.emit.Finding(finding.Finding{
		Account:  acct,
		Scope:    userScope(u.Login),
		Resource: finding.Resource{Type: "github_account", ID: "two-factor-authentication", Name: u.Login},
		Kind:     finding.KindSetting,
		Severity: severities[c],
		Title:    "GitHub account " + u.Login + " has no two-factor authentication",
		Evidence: map[string]any{"check": string(c), "owns_organizations": ownsOrgs},
		Remediation: finding.Remediation{
			Summary: "Enable two-factor authentication with a passkey or security key, and keep the recovery codes in the password manager.",
			URL:     web + "/settings/security",
		},
	})
}
