package finding

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCoverageMatchesScopesAccountsAndWildcards(t *testing.T) {
	var tally Tally
	tally.Status(Status{Account: "me@x.com", State: StateOK})
	tally.Status(Status{Account: "me@x.com", Scope: "locked", State: StateError, Detail: "permission denied"})
	tally.Status(Status{Account: "x", State: StateSignedOut})
	tally.Declare("repo:*", false, "repositories not listed")
	end := tally.End("c", "", time.Now(), time.Now(), nil)
	if end.Complete || end.Scopes.InspectedCount != 1 || end.Scopes.SkippedCount != 3 {
		t.Fatalf("run_end %+v", end)
	}
	c := CoverageOf(&end)
	for _, tc := range []struct {
		account, scope string
		unchecked      bool
		why            string
	}{
		{"me@x.com", "open", false, ""},
		{"me@x.com", "locked", true, "locked: error: permission denied"},
		{"x:@me", "x", true, "x: signedout"},   // a service signed out, findings named by user
		{"x", "x:other", true, "x: signedout"}, // the status's account matches the finding's
		{"github:acme", "repo:acme/a", true, "repo:*: repositories not listed"},
		{"github:acme", "github:acme", false, ""},
		{"me@x.com", "", true, "recorded without a scope, and this run skipped locked"}, // scope unknown: any skip counts
	} {
		why, unchecked := c.Unchecked(tc.account, tc.scope)
		if unchecked != tc.unchecked || !strings.HasPrefix(why, tc.why) {
			t.Errorf("Unchecked(%q, %q) = %q %v", tc.account, tc.scope, why, unchecked)
		}
	}
	if _, none := c.NoneChecked(); none || c.Complete() {
		t.Error("a partial run is neither empty nor complete")
	}
}

func TestCoverageOfRunsThatProveNothing(t *testing.T) {
	if why, none := CoverageOf(nil).NoneChecked(); !none || !strings.Contains(why, "no run_end") {
		t.Errorf("no run_end: %q %v", why, none)
	}
	if _, none := CoverageOf(&RunEnd{}).NoneChecked(); !none {
		t.Error("a zero record is no run_end")
	}
	var empty Tally
	end := empty.End("c", "", time.Now(), time.Now(), nil)
	if why, none := CoverageOf(&end).NoneChecked(); !none || !strings.Contains(why, "no account") {
		t.Errorf("nothing said ok: %q %v", why, none)
	}
	var ok Tally
	ok.Status(Status{Account: "a", State: StateOK})
	end = ok.End("c", "", time.Now(), time.Now(), errors.New("browser went away"))
	if why, none := CoverageOf(&end).NoneChecked(); !none || why != "browser went away" || end.Error != why || end.Complete {
		t.Errorf("connector error: %q %v %+v", why, none, end)
	}
	end = ok.End("c", "", time.Now(), time.Now(), nil)
	if !CoverageOf(&end).Complete() || !end.Complete || end.Scopes.Skipped == nil || end.Scopes.Inspected[0] != "a" {
		t.Errorf("complete run %+v", end)
	}
}

func TestScopeOfFallsBackToAccount(t *testing.T) {
	if ScopeOf(Finding{Account: "a"}) != "a" || ScopeOf(Finding{Account: "a", Scope: "s"}) != "s" {
		t.Fatal("ScopeOf")
	}
}

// A scope the owner's config leaves out does not make a run partial for people, though it still
// proves nothing gone there.
func TestCoverageCompleteAsConfigured(t *testing.T) {
	var tally Tally
	tally.Declare("a", true, "")
	tally.Declare("sys-1", false, "expected: in the config's skip list")
	end := tally.End("prowler", "", time.Time{}, time.Time{}, nil)
	c := CoverageOf(&end)
	if c.Complete() || !c.CompleteAsConfigured() || len(c.Missed()) != 0 {
		t.Fatalf("expected skip only: complete %v as configured %v missed %v", c.Complete(), c.CompleteAsConfigured(), c.Missed())
	}
	if _, unchecked := c.Unchecked("me", "sys-1"); !unchecked {
		t.Error("a scope left out on purpose was taken as checked")
	}
	tally.Declare("b", false, "denied")
	end = tally.End("prowler", "", time.Time{}, time.Time{}, nil)
	if c := CoverageOf(&end); c.CompleteAsConfigured() || len(c.Missed()) != 1 || c.Missed()[0].Scope != "b" {
		t.Fatalf("a real skip: %v", c.Missed())
	}
}
