package tracker

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestStatusActionPutsTheDetailsCommandInNext(t *testing.T) {
	cases := []struct {
		st                 finding.Status
		lbl, cmd, inAction string
	}{
		{finding.Status{Connector: "gcp", Account: "a@x.com", State: finding.StateReauth, Detail: "projects list: credentials expired: run gcloud auth login for this account"},
			"gcp", "gcloud auth login a@x.com", "Then: segurata inventory gcp."},
		{finding.Status{Connector: "github", State: finding.StateNoScope, Detail: "two-factor authentication not checked: gh's token lacks read:user; run: gh auth refresh -h github.com -s read:user"},
			"github", "gh auth refresh -h github.com -s read:user", "Then: segurata inventory github. On purpose? segurata track expect T-0009"},
		{finding.Status{Connector: "github", State: finding.StateNoScope, Detail: "gh lacks the admin:gpg_key scope; run: gh auth refresh -h github.com -s admin:gpg_key."},
			"github", "gh auth refresh -h github.com -s admin:gpg_key", "Grant the missing permission with the command below."},
		{finding.Status{Connector: "vercel", State: finding.StateMissingCredentials, Detail: "VERCEL_TOKEN is not configured: create a token, store it with `security add-generic-password -s segurata-vercel -a \"$USER\" -w` and reference it"},
			"vercel", `security add-generic-password -s segurata-vercel -a "$USER" -w`, `connectors."vercel".secrets`},
		{finding.Status{Connector: "anthropic", Instance: "personal", State: finding.StateMissingCredentials, Detail: "ANTHROPIC_ADMIN_KEY: environment variable ANTHROPIC_ADMIN_KEY is not set"},
			"anthropic:personal", "segurata inventory anthropic:personal", `connectors."anthropic:personal".secrets`},
		{finding.Status{Connector: "github", State: finding.StateNoScope, Detail: "the token lacks a permission"},
			"github", "segurata inventory github", "Grant the permission the detail names to the credential this connector uses."},
		{finding.Status{Connector: "connected-apps", Account: "microsoft", State: finding.StateSignedOut, Detail: "not signed in in the browser: https://account.live.com/consent/Manage"},
			"connected-apps", "segurata inventory connected-apps", `connectors."connected-apps".config.services`},
		{finding.Status{Connector: "aws", Account: "1234", State: finding.StateError, Detail: "root user: aws iam get-account-summary: exit status 254: An error occurred (AccessDenied) when calling the GetAccountSummary operation"},
			"aws", "segurata inventory aws", "segurata track expect T-0009"},
		{finding.Status{Connector: "macos", State: finding.StateError, Detail: "boom"}, "macos", "segurata inventory macos --verbose", "connector logs"},
	}
	for _, c := range cases {
		action, cmd := StatusAction(c.st, c.lbl, "T-0009")
		if cmd != c.cmd || !strings.Contains(action, c.inAction) {
			t.Errorf("%s %q:\n got %q, %q\nwant %q, action with %q", c.st.State, c.st.Detail, action, cmd, c.cmd, c.inAction)
		}
		if strings.Contains(action, "Do what the status detail says") || strings.Contains(action, "drop it from the config") {
			t.Errorf("generic action %q", action)
		}
	}
}

func TestAdminOnlyChecksAskForNoInstall(t *testing.T) {
	action, _ := StatusAction(finding.Status{Connector: "macos", State: finding.StateUnsupported, Detail: "remote-login: systemsetup needs admin; the listening ports check covers SSH"}, "macos", "")
	if strings.Contains(action, "Install") || !strings.Contains(action, "administrator rights") || !strings.Contains(action, "On purpose? segurata track expect <item>") {
		t.Errorf("admin-only: %q", action)
	}
	action, _ = StatusAction(finding.Status{Connector: "azure", State: finding.StateUnsupported, Detail: "az not found"}, "azure", "")
	if !strings.Contains(action, "Install what the detail names") {
		t.Errorf("unsupported: %q", action)
	}
	// A reauth without a fix must not assume a browser connector.
	if got, _ := StatusAction(finding.Status{State: finding.StateReauth, Detail: "InvalidClientTokenId"}, "aws", ""); strings.Contains(got, "drives over CDP") {
		t.Errorf("aws reauth should not point to the browser only: %q", got)
	}
}

func TestSetupTitleCountsStatusesSharingAKey(t *testing.T) {
	gcp := func(p, what string) finding.Status {
		return finding.Status{Connector: "gcp", Account: "a@x.com", Scope: p, State: finding.StateError, Detail: "project " + p + ": " + what}
	}
	cases := []struct {
		sts  []finding.Status
		want string
	}{
		{[]finding.Status{gcp("p1", "permission denied for iam policy")}, "gcp · a@x.com: failed"},
		{[]finding.Status{gcp("p1", "permission denied for iam policy"), gcp("p2", "permission denied for api keys")}, "gcp: permission denied on 2 projects for a@x.com"},
		{[]finding.Status{gcp("p1", "permission denied for iam policy"), gcp("p2", "quota exceeded")}, "gcp · a@x.com: failed on 2 projects"},
		{[]finding.Status{{Detail: "SSH signing keys not listed: x"}, {Detail: "GPG keys not listed: y"}}, "gcp · a@x.com: failed (2 problems)"},
	}
	for _, c := range cases {
		if got := setupTitle("gcp", "a@x.com", finding.StateError, c.sts); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestStatusURLIsThePageTheDetailSaysToOpen(t *testing.T) {
	st := finding.Status{State: finding.StateReauth, Detail: "authorized GitHub Apps need sudo mode: open https://github.com/settings/apps/authorizations, confirm your identity, and run again"}
	if got := StatusURL(st); got != "https://github.com/settings/apps/authorizations" {
		t.Errorf("%q", got)
	}
	if got := StatusURL(finding.Status{Detail: "not signed in in the browser: https://example.com"}); got != "" {
		t.Errorf("%q", got)
	}
}
