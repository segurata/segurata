package tracker

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
)

// The coverage line names every configured instance: when it last ran and whether it saw
// everything, never run, failed or partial with the first scope left out.
func TestCoverageLine(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	// An info finding dates each run (runtest takes its time from the findings).
	at := func(c string, when time.Time) finding.Finding {
		return fnd(c, "", "a", "info", "i", "i", finding.SevInfo, "i", when)
	}
	writeRun(t, out, t0, "github.jsonl", at("github", t0), okStatus("github", "github:me"),
		finding.Status{Type: "status", Connector: "github", Account: "github:me", Scope: "user:me", State: finding.StateNoScope, Detail: "two-factor authentication not checked: gh's token lacks read:user"})
	writeRun(t, out, t0.Add(-26*time.Hour), "aws.jsonl", at("aws", t0.Add(-26*time.Hour)), okStatus("aws", "1"))
	writeRun(t, out, t0, "gcp.jsonl", at("gcp", t0), okStatus("gcp", "me@x.com"), errors.New("gcloud exited 1"))
	// Only a status the config expects: nothing was inspected, on purpose.
	writeRun(t, out, t0, "anthropic.jsonl", at("anthropic", t0), finding.Status{Type: "status", Connector: "anthropic", State: finding.StateMissingCredentials, Detail: "no admin key"})
	writeRun(t, out, t0, "openai.jsonl", at("openai", t0), finding.Status{Type: "status", Connector: "openai", State: finding.StateMissingCredentials, Detail: "no admin key"})
	tr := New(t0)
	expect := func(st *finding.Status) {
		if st.Connector == "anthropic" {
			st.State = finding.StateExpected
		}
	}
	if _, err := tr.Sync(SyncOptions{OutDir: out, Expect: expect}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := tr.coverageLine([]string{"aws", "cloudflare", "gcp", "github"}, t0.Add(3*time.Hour))
	want := "Coverage: anthropic: 3 h ago (1 scope left out as expected); aws: 29 h ago; cloudflare: never run; gcp: 3 h ago, failed: gcloud exited 1; " +
		"github: 3 h ago, partial: user:me not checked; openai: 3 h ago, partial: nothing checked."
	if got != want {
		t.Errorf("coverage line\n got %q\nwant %q", got, want)
	}
}

// Areas no connector audits are coverage items, apart from what fails: the owner's own GitHub
// 2FA while gh lacks read:user (closed once a run reads it), hibp until it runs, and the manual
// areas, which stay until the owner marks them done.
func TestCoverageItems(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	writeRun(t, out, t0, "github.jsonl", okStatus("github", "github:me"),
		finding.Status{Type: "status", Connector: "github", Account: "github:me", Scope: "user:me", State: finding.StateNoScope, Detail: "gh lacks read:user"})
	tr := New(t0)
	rep := syncOrDie(t, tr, out, t0.Add(time.Minute))
	gh := tr.ByKey("coverage:github-owner-2fa")
	if gh == nil || gh.Kind != KindReview || gh.Theme != coverageTheme || gh.Priority != "" || gh.Next.Command != "gh auth refresh -h github.com -s read:user && segurata inventory github" {
		t.Fatalf("github 2FA coverage item %+v", gh)
	}
	for _, slug := range []string{"google-recovery", "apple-account", "stripe-keys", "hibp", "password-manager"} {
		if it := tr.ByKey("coverage:" + slug); it == nil || it.Status != Open || it.Next == nil || it.Next.Action == "" {
			t.Errorf("%s: %+v", slug, it)
		}
	}
	if tr.ByKey("coverage:workspace") != nil {
		t.Error("no workspace tenant is configured: no workspace coverage item")
	}
	if rep.Coverage.Opened != 6 {
		t.Errorf("opened %d", rep.Coverage.Opened)
	}

	var b strings.Builder
	_ = doc.Render(&b, tr.Status("tracker.json", t0.Add(time.Hour), View{}), doc.Text)
	s := b.String()
	doNext := s[strings.Index(s, "Do next"):strings.Index(s, "Pending decisions")]
	if !strings.Contains(s, "Not audited on this machine") || !strings.Contains(s, "[not audited] Two-factor authentication of your own GitHub account is not audited") ||
		strings.Contains(doNext, "not audited") || !strings.Contains(s, "Not audited here: 6.") || !strings.Contains(s, "2 open: P0 0") {
		t.Errorf("status:\n%s", s)
	}

	// read:user granted, hibp set up, the Apple review done by hand.
	if err := tr.ByKey("coverage:apple-account").Start(t0, ""); err != nil {
		t.Fatal(err)
	}
	tr.ByKey("coverage:apple-account").Done(t0.Add(2*time.Minute), "checked")
	day2 := t0.Add(24 * time.Hour)
	writeRun(t, out, day2, "github.jsonl", okStatus("github", "github:me"), finding.Status{Type: "status", Connector: "github", Account: "github:me", Scope: "user:me", State: finding.StateOK})
	writeRun(t, out, day2, "hibp.jsonl", okStatus("hibp", "me@x.com"))
	rep = syncOrDie(t, tr, out, day2.Add(time.Minute))
	for _, slug := range []string{"github-owner-2fa", "hibp"} {
		if it := tr.ByKey("coverage:" + slug); it.Status != Done || it.VerifiedAt == nil || !strings.HasPrefix(it.lastDetail(actAutoDone), "covered: ") {
			t.Errorf("%s: %s %q", slug, it.Status, it.lastDetail(actAutoDone))
		}
	}
	if rep.Coverage.Covered != 2 || tr.ByKey("coverage:apple-account").Status != Done {
		t.Errorf("covered %d; apple %s", rep.Coverage.Covered, tr.ByKey("coverage:apple-account").Status)
	}
	// gh lost the scope again: the item segurata closed opens again.
	day3 := day2.Add(24 * time.Hour)
	writeRun(t, out, day3, "github.jsonl", okStatus("github", "github:me"),
		finding.Status{Type: "status", Connector: "github", Account: "github:me", Scope: "user:me", State: finding.StateNoScope, Detail: "gh lacks read:user"})
	syncOrDie(t, tr, out, day3.Add(time.Minute))
	if it := tr.ByKey("coverage:github-owner-2fa"); it.Status != Open {
		t.Errorf("github 2FA after the scope was lost: %s", it.Status)
	}

	// A workspace tenant configured but unreadable is a gap too.
	writeRun(t, out, day3, "workspace-x.com.jsonl", finding.Status{Type: "status", Connector: "workspace", Instance: "x.com", Account: "x.com", State: finding.StateMissingCredentials, Detail: "no admin credentials"})
	syncOrDie(t, tr, out, day3.Add(2*time.Minute))
	if it := tr.ByKey("coverage:workspace"); it == nil || it.Status != Open {
		t.Errorf("workspace coverage item %+v", it)
	}
}

// A github run from before connectors declared their areas says nothing of the owner's account
// (the item is left as it is); a declared one that could not read it opens the gap, and its report
// stands while no github run is folded.
func TestGithubOwner2FAFromDeclaredRuns(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	noScope := finding.Status{Type: "status", Connector: "github", Account: "github:me", Scope: "user:me", State: finding.StateNoScope, Detail: "gh lacks read:user"}
	runtest.Write(t, filepath.Join(out, t0.Format(time.DateOnly), "github.jsonl"), okStatus("github", "github:org"), noScope)
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	if it := tr.ByKey("coverage:github-owner-2fa"); it != nil {
		t.Fatalf("from a run before declarations: %+v", it)
	}
	writeRun(t, out, t0.Add(time.Hour), "github.jsonl", okStatus("github", "github:org"), noScope)
	syncOrDie(t, tr, out, t0.Add(time.Hour+time.Minute))
	if it := tr.ByKey("coverage:github-owner-2fa"); it == nil || it.Status != Open {
		t.Fatalf("from a declared run: %+v", it)
	}
	other := filepath.Join(t.TempDir(), "other")
	writeRun(t, other, t0.Add(2*time.Hour), "macos.jsonl", okStatus("macos", "Mac"))
	syncOrDie(t, tr, other, t0.Add(2*time.Hour))
	if it := tr.ByKey("coverage:github-owner-2fa"); it.Status != Open {
		t.Errorf("with no github run folded: %s", it.Status)
	}
	if line := tr.coverageLine(nil, t0.Add(3*time.Hour)); !strings.Contains(line, "github: ") {
		t.Errorf("line %q", line)
	}
}
