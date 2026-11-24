package tracker

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestStatusActionPrefersTheConnectorsOwnFix(t *testing.T) {
	cases := []struct {
		st   finding.Status
		want string
	}{
		{finding.Status{State: finding.StateReauth, Detail: "projects list: credentials expired: run gcloud auth login for this account"}, "Do what the status detail says."},
		{finding.Status{State: finding.StateNoScope, Detail: "gh lacks the admin:gpg_key scope; run: gh auth refresh -h github.com -s admin:gpg_key"}, "Do what the status detail says."},
		{finding.Status{State: finding.StateNoScope, Detail: "the token lacks a permission"}, "Grant the permission the detail names to the credential this connector uses."},
	}
	for _, c := range cases {
		if got, _ := StatusAction(c.st, "x"); got != c.want {
			t.Errorf("%s %q: got %q", c.st.State, c.st.Detail, got)
		}
	}
	// A reauth without a fix must not assume a browser connector.
	if got, _ := StatusAction(finding.Status{State: finding.StateReauth, Detail: "InvalidClientTokenId"}, "aws"); strings.Contains(got, "drives over CDP") {
		t.Errorf("aws reauth should not point to the browser only: %q", got)
	}
}
