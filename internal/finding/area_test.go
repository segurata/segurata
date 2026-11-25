package finding

import "testing"

func TestAreaAudited(t *testing.T) {
	st := func(scope string, s State) Status { return Status{Scope: scope, State: s} }
	user := Area{ID: "github-owner-2fa", Scope: "user:"}
	tenant := Area{ID: "workspace"}
	for _, c := range []struct {
		area     Area
		statuses []Status
		want     bool
	}{
		{user, []Status{st("", StateOK)}, true},                                   // nothing said about the user: read
		{user, []Status{st("", StateOK), st("user:me", StateNoScope)}, false},     // the user could not be read
		{user, []Status{st("user:me", StateOK), st("user:me", StateError)}, true}, // one read is enough
		{user, nil, true},
		{tenant, []Status{st("", StateError), st("", StateOK)}, true},
		{tenant, []Status{st("", StateError)}, false},
	} {
		if got := c.area.Audited(c.statuses); got != c.want {
			t.Errorf("%s over %+v: %v, want %v", c.area.ID, c.statuses, got, c.want)
		}
	}
}
