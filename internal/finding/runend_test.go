package finding

import (
	"errors"
	"fmt"
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

// A path the run could not read holds what is at it, or inside it, and nothing else of its scope.
func TestCoverageHoldsWhatIsAtAnUnreadablePath(t *testing.T) {
	var tally Tally
	tally.Declare("files", true, "")
	tally.Declare(PathScope("files", "~/Library/Mail"), false, UnreadableReason)
	tally.Declare(PathScope("files", "~/.config/locked.env"), false, UnreadableReason)
	end := tally.End("c", "", time.Now(), time.Now(), nil)
	c := CoverageOf(&end)
	for _, tc := range []struct {
		path      string
		unchecked bool
	}{
		{"~/.config/locked.env", true},
		{"~/Library/Mail/V10/x.emlx", true},
		{"~/Library", true}, // a repository or directory holding an unreadable path
		{"~/Library/Mailbox/x", false},
		{"~/.config/locked.env.bak", false},
		{"~/.config/other.env", false},
		{"", false},
	} {
		if _, unchecked := c.UncheckedPath("local", "files", tc.path); unchecked != tc.unchecked {
			t.Errorf("UncheckedPath(%q) = %v", tc.path, unchecked)
		}
	}
	if _, unchecked := c.Unchecked("local", "files"); unchecked {
		t.Error("an unreadable path left the whole files scope unchecked")
	}
	if !c.CompleteAsConfigured() || c.Complete() || c.Unreadable() != 2 {
		t.Errorf("unreadable paths are expected skips: complete as configured %v, complete %v, unreadable %d",
			c.CompleteAsConfigured(), c.Complete(), c.Unreadable())
	}
	if _, unchecked := c.UncheckedPath("local", "history:~/Library", "~/Library/Mail"); unchecked {
		t.Error("a files path held another scope")
	}
}

// More skips than run_end lists prove nothing, though every listed one is expected.
func TestTooManyExpectedSkipsProveNothing(t *testing.T) {
	var tally Tally
	tally.Declare("files", true, "")
	for i := range maxSkippedListed + 1 {
		tally.Declare(PathScope("files", fmt.Sprintf("~/locked/%d", i)), false, UnreadableReason)
	}
	end := tally.End("c", "", time.Now(), time.Now(), nil)
	c := CoverageOf(&end)
	if why, none := c.NoneChecked(); !none || why != "201 scopes not inspected, too many to list" {
		t.Errorf("none checked %v: %q", none, why)
	}
	if c.CompleteAsConfigured() || len(c.Missed()) != 1 || c.Missed()[0].Scope != ScopeAll {
		t.Errorf("complete as configured %v, missed %v", c.CompleteAsConfigured(), c.Missed())
	}
	if len(end.Scopes.Skipped) != maxSkippedListed {
		t.Errorf("run_end lists %d skips", len(end.Scopes.Skipped))
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

// A finding's coverage scope falls back to its account, and its path is its repository, else its
// file, when either is a local path.
func TestAFindingsScopeAndPath(t *testing.T) {
	if ScopeOf(Finding{Account: "a"}) != "a" || ScopeOf(Finding{Account: "a", Scope: "s"}) != "s" {
		t.Fatal("ScopeOf")
	}
	for _, c := range []struct {
		evidence map[string]any
		want     string
	}{
		{map[string]any{"repo": "~/src/x", "path": "~/src/x/.env"}, "~/src/x"},
		{map[string]any{"repo": "github.com/a/b", "path": "/etc/x.env"}, "/etc/x.env"},
		{map[string]any{"path": "relative/x.env"}, ""},
		{nil, ""},
	} {
		if got := PathOf(Finding{Evidence: c.evidence}); got != c.want {
			t.Errorf("PathOf(%v) = %q, want %q", c.evidence, got, c.want)
		}
	}
	var tally Tally
	tally.Declare("files", true, "")
	tally.Declare(PathScope("files", "~/locked"), false, UnreadableReason)
	end := tally.End("c", "", time.Now(), time.Now(), nil)
	at := func(p string) Finding {
		return Finding{Account: "local", Scope: "files", Evidence: map[string]any{"path": p}}
	}
	if _, unchecked := CoverageOf(&end).UncheckedFinding(at("~/locked/x")); !unchecked {
		t.Error("a finding under an unreadable path was taken as checked")
	}
	if _, unchecked := CoverageOf(&end).UncheckedFinding(at("~/open/x")); unchecked {
		t.Error("a finding elsewhere in the scope was taken as unchecked")
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
	for reason, want := range map[string]bool{
		"expected": true, "expected: in the config's skip list": true,
		"expected a 200 from the API, got 403": false, "expectedly empty": false, "not expected": false,
	} {
		if got := (Skipped{Scope: "s", Reason: reason}).Expected(); got != want {
			t.Errorf("Skipped with reason %q: expected %v, want %v", reason, got, want)
		}
	}
	tally.Declare("b", false, "denied")
	end = tally.End("prowler", "", time.Time{}, time.Time{}, nil)
	if c := CoverageOf(&end); c.CompleteAsConfigured() || len(c.Missed()) != 1 || c.Missed()[0].Scope != "b" {
		t.Fatalf("a real skip: %v", c.Missed())
	}
}
