package tracker

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/secretrisk"
)

const ghFP = "c7c7c7c7c7c7c7c7"

// ghLeak is a GitHub token pushed to a repository's history (P0 as it is) and kept in a working
// .env, with the liveness result of the run, if any.
func ghLeak(at time.Time, l *secretrisk.Liveness) []secretrisk.Evidence {
	return []secretrisk.Evidence{
		{Fingerprint: ghFP, Type: "github", Redacted: "ghp_…wxyz(40)", Path: "~/src/shop/deploy.sh", Repo: "~/src/shop", Source: "gitleaks",
			Kind: "repo", Tracked: true, Remote: true, Bucket: "0-git", Count: 1, Date: "2021-03-04", Liveness: l},
		{Fingerprint: ghFP, Type: "github", Redacted: "ghp_…wxyz(40)", Path: "~/src/shop/.env", Source: "scan", Kind: "repo",
			Mode: "600", Bucket: "3-local", Count: 1, Liveness: l},
	}
}

// localLeak is a medium-impact key in a closed local file only (P3 as it is).
func localLeak(fp string, l *secretrisk.Liveness) secretrisk.Evidence {
	return secretrisk.Evidence{Fingerprint: fp, Type: "openai-project", Redacted: "sk-proj-…abcd(164)", Path: "~/.config/tool/env",
		Source: "scan", Kind: "config", Mode: "600", Bucket: "3-local", Count: 1, Liveness: l}
}

func writeSecrets(t *testing.T, out string, at time.Time, evs ...secretrisk.Evidence) {
	t.Helper()
	var recs []any
	for _, e := range evs {
		recs = append(recs, leak(e, at))
	}
	writeRun(t, out, at, "local-secrets.jsonl", append(recs, okStatus(SecretsConnector, "local"))...)
}

func checked(state secretrisk.LiveState, at time.Time, account string) *secretrisk.Liveness {
	reason := map[secretrisk.LiveState]string{secretrisk.Live: "HTTP 200", secretrisk.Dead: "HTTP 401", secretrisk.Unknown: "HTTP 503"}[state]
	return &secretrisk.Liveness{State: state, CheckedAt: at, Provider: "github", Endpoint: "GET api.github.com/user", Reason: reason, Account: account, Rules: secretrisk.LivenessRules}
}

// ghHistory is ghLeak without its working copy: the token only in pushed history.
func ghHistory(at time.Time, l *secretrisk.Liveness) []secretrisk.Evidence {
	return ghLeak(at, l)[:1]
}

// A secret the provider still accepts is proven live like one a connector reports: P0 once a copy
// left the machine, first among secrets, "live" in its reasons; a local one keeps its priority.
func TestLiveSecretIsP0WhenLeaked(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	writeSecrets(t, out, t0, append(ghLeak(t0, checked(secretrisk.Live, t0, "github:octocat")), localLeak("d8d8d8d8d8d8d8d8", checked(secretrisk.Live, t0, "")))...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	gh := mustRotate(t, tr, ghFP[:8])
	if gh.Priority != secretrisk.P0 || !gh.LiveAndLeaked() || gh.Secret.Liveness == nil || gh.Secret.Liveness.State != secretrisk.Live {
		t.Fatalf("live leaked token: %s %+v", gh.Priority, gh.Secret.Liveness)
	}
	if r := strings.Join(gh.Secret.Reasons, "; "); !strings.HasPrefix(r, "live key, leaked in shop:deploy.sh") || !strings.Contains(r, "live: GET api.github.com/user accepted it on 2026-") || !strings.Contains(r, "as github:octocat") {
		t.Errorf("reasons %q", gh.Secret.Reasons)
	}
	local := mustRotate(t, tr, "d8d8d8d8")
	if local.Priority != secretrisk.P3 || local.LiveAndLeaked() {
		t.Errorf("a live key that never left the machine keeps its priority: %s", local.Priority)
	}
	if f := livenessFactor(local); f.Value != 1.5 {
		t.Errorf("liveness factor %+v", f)
	}
	if f := confidenceFactor(local); f.Value != 1 {
		t.Errorf("a key the provider accepts is not doubtful: %+v", f)
	}
}

// The account a provider says the secret signs in as is attribution: the owner's GitHub login
// makes it mine.
func TestLivenessAccountAttributes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	writeSecrets(t, out, t0, ghLeak(t0, checked(secretrisk.Live, t0, "github:OctoCat"))...)
	if _, err := tr.Sync(SyncOptions{OutDir: out, Owned: attribution.Owned{GitHub: []string{"octocat"}}}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	gh := mustRotate(t, tr, ghFP[:8])
	if gh.Owner() != attribution.Mine || !strings.Contains(gh.Secret.Attribution.Reasons[0], "GitHub account OctoCat is yours") {
		t.Errorf("attribution %+v", gh.Secret.Attribution)
	}
}

// A secret every provider host rejects is closed as done once no working file holds it: nobody
// can use it, which is where a rotation ends too. A copy in a working file keeps it open (or opens
// it again): the owner still has a file to clean. A later check that finds it live opens it, and
// the owner reopening it by hand sticks.
func TestDeadSecretClosesAsDone(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	writeSecrets(t, out, t0, ghLeak(t0, nil)...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	gh := mustRotate(t, tr, ghFP[:8])
	if gh.Status != Open || gh.LivenessLabel() != "unchecked" {
		t.Fatalf("before any check: %s %s", gh.Status, gh.LivenessLabel())
	}

	// Dead, but still in .env: it stays open, its reasons say dead.
	day2 := t0.Add(24 * time.Hour)
	writeSecrets(t, out, day2, ghLeak(day2, checked(secretrisk.Dead, day2, ""))...)
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if gh.Status != Open || gh.LivenessLabel() != "dead" {
		t.Fatalf("a dead key in a working file closed: %s %+v", gh.Status, gh.History[len(gh.History)-1])
	}
	if r := strings.Join(gh.Secret.Reasons, "; "); !strings.Contains(r, "dead: GET api.github.com/user rejected it on 2026-11-24 (HTTP 401)") {
		t.Errorf("reasons %q", gh.Secret.Reasons)
	}

	// The .env copy is gone: closed as done.
	day3 := day2.Add(24 * time.Hour)
	writeSecrets(t, out, day3, ghHistory(day3, checked(secretrisk.Dead, day2, ""))...)
	syncOrDie(t, tr, out, day3.Add(time.Minute))
	last := gh.History[len(gh.History)-1]
	if gh.Status != Done || last.Action != actDead || last.Detail != "key no longer valid (checked 2026-11-24: GET api.github.com/user answered HTTP 401)" {
		t.Fatalf("dead: %s %+v", gh.Status, last)
	}

	// A working copy is back: it opens again, and the same sync does not close it.
	day4 := day3.Add(24 * time.Hour)
	writeSecrets(t, out, day4, ghLeak(day4, checked(secretrisk.Dead, day2, ""))...)
	syncOrDie(t, tr, out, day4.Add(time.Minute))
	last = gh.History[len(gh.History)-1]
	if gh.Status != Open || last.Action != actAutoReopen || !strings.Contains(last.Detail, ".env") {
		t.Fatalf("a dead-closed key back in a working file: %s %+v", gh.Status, last)
	}
	syncOrDie(t, tr, out, day4.Add(2*time.Minute))
	if gh.Status != Open {
		t.Fatalf("the next sync closed it again: %s", gh.Status)
	}

	// Gone from .env and dead again: done; then live (a key re-enabled, or a check that was wrong):
	// it opens, proven live.
	day5 := day4.Add(24 * time.Hour)
	writeSecrets(t, out, day5, ghHistory(day5, checked(secretrisk.Dead, day5, ""))...)
	syncOrDie(t, tr, out, day5.Add(time.Minute))
	if gh.Status != Done {
		t.Fatalf("dead again: %s", gh.Status)
	}
	day6 := day5.Add(24 * time.Hour)
	writeSecrets(t, out, day6, ghHistory(day6, checked(secretrisk.Live, day6, ""))...)
	syncOrDie(t, tr, out, day6.Add(time.Minute))
	last = gh.History[len(gh.History)-1]
	if gh.Status != Open || last.Action != actProvenLive || !strings.Contains(last.Detail, "proven live by the liveness check of 2026-11-28") {
		t.Fatalf("live again: %s %+v", gh.Status, last)
	}

	// Dead again, but the owner reopened it by hand after that check: it stays open.
	day7 := day6.Add(24 * time.Hour)
	writeSecrets(t, out, day7, ghHistory(day7, checked(secretrisk.Dead, day7, ""))...)
	syncOrDie(t, tr, out, day7.Add(time.Minute))
	if gh.Status != Done {
		t.Fatalf("dead again: %s", gh.Status)
	}
	gh.Reopen(day7.Add(time.Hour), "I do not trust that check")
	syncOrDie(t, tr, out, day7.Add(2*time.Hour))
	if gh.Status != Open {
		t.Errorf("reopened by hand after the check: %s", gh.Status)
	}
}

// A dead verdict of the old rules (no rules version: a bare 401 could close a key that works) never
// closes an open item.
func TestUntrustedDeadNeverCloses(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	old := checked(secretrisk.Dead, t0, "")
	old.Rules = 0
	writeSecrets(t, out, t0, ghHistory(t0, old)...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	gh := mustRotate(t, tr, ghFP[:8])
	if gh.Status != Open || gh.LivenessLabel() != "unchecked" {
		t.Errorf("an old-rules dead verdict: %s %s", gh.Status, gh.LivenessLabel())
	}
}

// The repair of items the old rules closed (testdata/old-dead-closed.json, written by the tracker
// before LivenessRules 2: a GitHub token kept in .env and two OpenAI keys in history, every one
// closed "key no longer valid" on a bare 401). The next sync drops those verdicts: an item opens
// again unless a check of the current rules finds it dead, and one with a working copy opens again
// whatever the check says.
func TestOldDeadClosesAreRepaired(t *testing.T) {
	tr, err := Load(filepath.Join("testdata", "old-dead-closed.json"))
	if err != nil {
		t.Fatal(err)
	}
	gh, unchecked, stillDead := mustRotate(t, tr, ghFP[:8]), mustRotate(t, tr, "b2b2b2b2"), mustRotate(t, tr, "c3c3c3c3")
	for _, it := range []*Item{gh, unchecked, stillDead} {
		if it.Status != Done || !it.closedDead() {
			t.Fatalf("fixture: %s %s", it.ID, it.Status)
		}
	}
	hist := func(fp string, l *secretrisk.Liveness) secretrisk.Evidence {
		return secretrisk.Evidence{Fingerprint: fp, Type: "openai-project", Redacted: "sk-proj-…abcd(164)", Path: "~/src/shop/app.py", Repo: "~/src/shop", Source: "gitleaks",
			Kind: "repo", Tracked: true, Remote: true, Bucket: "0-git", Count: 1, Date: "2021-03-04", Liveness: l}
	}
	day4 := t0.Add(72 * time.Hour)
	dead := &secretrisk.Liveness{State: secretrisk.Dead, CheckedAt: day4, Provider: "anthropic", Endpoint: "GET api.anthropic.com/v1/models", Reason: "authentication_error", Rules: secretrisk.LivenessRules}
	out := filepath.Join(t.TempDir(), "out")
	writeSecrets(t, out, day4, append(ghLeak(day4, checked(secretrisk.Unknown, day4, "")), hist("b2b2b2b2b2b2b2b2", nil), hist("c3c3c3c3c3c3c3c3", dead))...)
	syncOrDie(t, tr, out, day4.Add(time.Minute))
	if gh.Status != Open || gh.LivenessLabel() != "unknown" {
		t.Errorf("token in .env, unknown now: %s %s %+v", gh.Status, gh.LivenessLabel(), gh.History[len(gh.History)-1])
	}
	if unchecked.Status != Open || unchecked.LivenessLabel() != "unchecked" {
		t.Errorf("history-only key not checked again yet: %s %s", unchecked.Status, unchecked.LivenessLabel())
	}
	if last := unchecked.History[len(unchecked.History)-1]; last.Action != actAutoReopen || !strings.Contains(last.Detail, "no longer stands") {
		t.Errorf("reopen event %+v", last)
	}
	if stillDead.Status != Done || stillDead.LivenessLabel() != "dead" || stillDead.Secret.Liveness.Rules != secretrisk.LivenessRules {
		t.Errorf("history-only key dead by the current rules: %s %+v", stillDead.Status, stillDead.Secret.Liveness)
	}
	n := len(stillDead.History)
	syncOrDie(t, tr, out, day4.Add(2*time.Minute))
	if gh.Status != Open || unchecked.Status != Open || stillDead.Status != Done || len(stillDead.History) != n {
		t.Errorf("the next sync moved them: %s %s %s %+v", gh.Status, unchecked.Status, stillDead.Status, stillDead.History[n-1:])
	}
}

// Dead never closes what the owner settled (ignored, accepted), nor a secret a connector reports
// live; unknown changes nothing; a run without a result keeps the last one.
func TestDeadLeavesOthersAlone(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	writeSecrets(t, out, t0, append(ghLeak(t0, checked(secretrisk.Unknown, t0, "")),
		localLeak("e9e9e9e9e9e9e9e9", nil), localLeak("f0f0f0f0f0f0f0f0", nil))...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	gh := mustRotate(t, tr, ghFP[:8])
	if gh.Status != Open || gh.Priority != secretrisk.P0 || gh.LivenessLabel() != "unknown" {
		t.Fatalf("unknown: %s %s %s", gh.Status, gh.Priority, gh.LivenessLabel())
	}
	ign, acc := mustRotate(t, tr, "e9e9e9e9"), mustRotate(t, tr, "f0f0f0f0")
	if err := ign.Ignore(t0.Add(time.Hour), "test key"); err != nil {
		t.Fatal(err)
	}
	if err := acc.Accept(t0.Add(time.Hour), "kept", ""); err != nil {
		t.Fatal(err)
	}
	day2 := t0.Add(24 * time.Hour)
	dead := checked(secretrisk.Dead, day2, "")
	writeSecrets(t, out, day2, localLeak("e9e9e9e9e9e9e9e9", dead), localLeak("f0f0f0f0f0f0f0f0", dead))
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if ign.Status != Ignored || acc.Status != Accepted {
		t.Errorf("settled items: %s %s", ign.Status, acc.Status)
	}
	if gh.Secret.Liveness == nil || gh.Secret.Liveness.State != secretrisk.Unknown {
		t.Errorf("a run without the secret's result keeps the last one: %+v", gh.Secret.Liveness)
	}
	// An older result never replaces a newer one.
	writeSecrets(t, out, day2.Add(time.Hour), ghLeak(day2, checked(secretrisk.Dead, t0.Add(-time.Hour), ""))...)
	syncOrDie(t, tr, out, day2.Add(2*time.Hour))
	if gh.Status != Open || gh.Secret.Liveness.State != secretrisk.Unknown {
		t.Errorf("an older dead result: %s %+v", gh.Status, gh.Secret.Liveness)
	}

	// A connector reports the key live: dead from the check does not close it.
	out2 := filepath.Join(t.TempDir(), "out")
	tr2 := New(t0)
	awsKeyRuns(t, out2, t0, awsFP)
	syncOrDie(t, tr2, out2, t0.Add(time.Minute))
	day3 := t0.Add(time.Hour)
	cred := secretrisk.Evidence{Fingerprint: awsFP, Type: "aws-access-key-id", Redacted: "AKIA…(20)", Path: "~/.aws/credentials",
		Source: "scan", Kind: "config", Mode: "600", Bucket: "3-local", Count: 1, Liveness: &secretrisk.Liveness{State: secretrisk.Dead, CheckedAt: day3, Provider: "aws"}}
	writeSecrets(t, out2, day3, cred)
	syncOrDie(t, tr2, out2, day3.Add(time.Minute))
	if rot := mustRotate(t, tr2, awsFP[:8]); rot.Status != Open {
		t.Errorf("connector proof vs a dead check: %s", rot.Status)
	}
}

// Coverage: how many tracked secrets a check settled, live or dead.
func TestLivenessCoverage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	writeSecrets(t, out, t0, append(ghLeak(t0, checked(secretrisk.Live, t0, "")),
		localLeak("e9e9e9e9e9e9e9e9", checked(secretrisk.Dead, t0, "")),
		localLeak("f0f0f0f0f0f0f0f0", checked(secretrisk.Unknown, t0, "")),
		localLeak("a1a1a1a1a1a1a1a1", nil),
		localLeak("b2b2b2b2b2b2b2b2", sshLookup(secretrisk.Unregistered, t0)))...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	want := "Liveness checked for 3 of 5 secrets: 1 live, 1 dead, 1 unregistered, 1 unknown, 1 unchecked."
	if got := tr.LivenessLine(); got != want {
		t.Errorf("line %q, want %q", got, want)
	}
	var b strings.Builder
	_ = doc.Render(&b, tr.Status("tracker.json", t0.Add(time.Hour), View{}), doc.Text)
	if !strings.Contains(b.String(), want) {
		t.Errorf("status lacks the line:\n%s", b.String())
	}
	if got := New(t0).LivenessLine(); got != "" {
		t.Errorf("no secrets: %q", got)
	}
}

// sshLookup is a private key looked up among the owner's registered SSH keys.
func sshLookup(state secretrisk.LiveState, at time.Time) *secretrisk.Liveness {
	reason := map[secretrisk.LiveState]string{secretrisk.Live: "GitHub SSH key 'laptop'", secretrisk.Dead: "Inactive in account 123456789012",
		secretrisk.Unregistered: "registered nowhere segurata can see"}[state]
	return &secretrisk.Liveness{State: state, CheckedAt: at, Provider: "ssh-keys", Endpoint: "GET api.github.com/user/keys", Reason: reason, ByOwner: true}
}

// sshLeak is a private key pushed to a repository's history: P0 as it is.
func sshLeak(at time.Time, l *secretrisk.Liveness) secretrisk.Evidence {
	return secretrisk.Evidence{Fingerprint: "d4d4d4d4d4d4d4d4", Type: "private-key", Redacted: "PEM", Path: "~/src/shop/deploy/id_ed25519", Repo: "~/src/shop",
		Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "0-git", Count: 1, Date: "2021-03-04", Liveness: l}
}

// A lookup with the owner's credentials reads as such: a registered key is live and P0 once
// leaked, a key absent from the owner's inventory closes as dead, and one registered nowhere
// segurata can see drops one priority, with a reason that says it is not proof of death.
func TestLookupByOwner(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	writeSecrets(t, out, t0, sshLeak(t0, nil))
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	key := mustRotate(t, tr, "d4d4d4d4")
	if key.Priority != secretrisk.P0 {
		t.Fatalf("a pushed private key: %s", key.Priority)
	}

	day2 := t0.Add(24 * time.Hour)
	writeSecrets(t, out, day2, sshLeak(day2, sshLookup(secretrisk.Unregistered, day2)))
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if key.Priority != secretrisk.P1 || key.Status != Open || key.LivenessLabel() != "unregistered" {
		t.Fatalf("unregistered: %s %s %s", key.Priority, key.Status, key.LivenessLabel())
	}
	if r := strings.Join(key.Secret.Reasons, "; "); !strings.Contains(r, "unregistered: registered nowhere segurata can see (GET api.github.com/user/keys) on 2026-11-24; not proof it is dead") {
		t.Errorf("reasons %q", key.Secret.Reasons)
	}

	day3 := day2.Add(24 * time.Hour)
	writeSecrets(t, out, day3, sshLeak(day3, sshLookup(secretrisk.Live, day3)))
	syncOrDie(t, tr, out, day3.Add(time.Minute))
	if key.Priority != secretrisk.P0 || !key.LiveAndLeaked() {
		t.Fatalf("registered: %s", key.Priority)
	}
	if r := strings.Join(key.Secret.Reasons, "; "); !strings.Contains(r, "live: GitHub SSH key 'laptop' (GET api.github.com/user/keys) on 2026-11-25") {
		t.Errorf("reasons %q", key.Secret.Reasons)
	}

	day4 := day3.Add(24 * time.Hour)
	writeSecrets(t, out, day4, sshLeak(day4, sshLookup(secretrisk.Dead, day4)))
	syncOrDie(t, tr, out, day4.Add(time.Minute))
	last := key.History[len(key.History)-1]
	if key.Status != Done || last.Detail != "key no longer valid (checked 2026-11-26: Inactive in account 123456789012 (GET api.github.com/user/keys))" {
		t.Errorf("dead by lookup: %s %+v", key.Status, last)
	}
}

// An unknown answer (a 429, a 5xx, a timeout) never replaces a held live or dead one, however
// newer: a live leaked key stays P0, a dead history-only key stays done.
func TestUnknownNeverOverwrites(t *testing.T) {
	for _, held := range []secretrisk.LiveState{secretrisk.Live, secretrisk.Dead} {
		out := filepath.Join(t.TempDir(), "out")
		tr := New(t0)
		writeSecrets(t, out, t0, ghHistory(t0, checked(held, t0, ""))...)
		syncOrDie(t, tr, out, t0.Add(time.Minute))
		gh := mustRotate(t, tr, ghFP[:8])
		prio, status := gh.Priority, gh.Status
		day2 := t0.Add(48 * time.Hour)
		writeSecrets(t, out, day2, ghHistory(day2, checked(secretrisk.Unknown, day2, ""))...)
		syncOrDie(t, tr, out, day2.Add(time.Minute))
		if gh.LivenessLabel() != string(held) || gh.Priority != prio || gh.Status != status {
			t.Errorf("%s then unknown: %s %s %s", held, gh.LivenessLabel(), gh.Priority, gh.Status)
		}
	}
}

// A result dated after the sync (a clock that jumped forward) never sticks: seen, it is skipped;
// held, it is dropped, so it neither beats later checks nor re-closes the item on every sync.
func TestFutureLivenessNeverSticks(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	future := t0.Add(30 * 24 * time.Hour)
	writeSecrets(t, out, t0, ghHistory(t0, checked(secretrisk.Dead, future, ""))...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	gh := mustRotate(t, tr, ghFP[:8])
	if gh.Status != Open || gh.Secret.Liveness != nil {
		t.Fatalf("a future dead result: %s %+v", gh.Status, gh.Secret.Liveness)
	}
	gh.Secret.Liveness = checked(secretrisk.Dead, future, "") // held by an older segurata
	day2 := t0.Add(24 * time.Hour)
	writeSecrets(t, out, day2, ghHistory(day2, checked(secretrisk.Live, day2, ""))...)
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if gh.Status != Open || gh.LivenessLabel() != "live" {
		t.Errorf("a held future result beat a real check: %s %s", gh.Status, gh.LivenessLabel())
	}
}

// A key raised to P0 by a live check is news once: an unknown answer after it (a 429 past the live
// result's day) keeps it P0, so live → unknown → live raises, and notifies, only the first time.
func TestLiveUnknownLiveRaisesOnce(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	pushed := func(at time.Time, l *secretrisk.Liveness) secretrisk.Evidence {
		e := localLeak("b5b5b5b5b5b5b5b5", l)
		e.Path, e.Repo, e.Source, e.Kind, e.Mode, e.Bucket, e.Tracked, e.Remote, e.Date = "~/src/shop/app.py", "~/src/shop", "gitleaks", "repo", "", "0-git", true, true, "2021-03-04"
		return e
	}
	writeSecrets(t, out, t0, pushed(t0, nil))
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	key := mustRotate(t, tr, "b5b5b5b5")
	if key.Priority == secretrisk.P0 {
		t.Fatalf("an unchecked medium key is P0 already: the test needs one a live check raises")
	}
	raised := func() int {
		n := 0
		for _, e := range key.History {
			if e.Action == actRaised {
				n++
			}
		}
		return n
	}
	for i, st := range []secretrisk.LiveState{secretrisk.Live, secretrisk.Unknown, secretrisk.Live} {
		day := t0.Add(time.Duration(i+1) * 48 * time.Hour)
		writeSecrets(t, out, day, pushed(day, checked(st, day, "")))
		syncOrDie(t, tr, out, day.Add(time.Minute))
		if key.Priority != secretrisk.P0 || raised() != 1 {
			t.Fatalf("after %s: %s, %d raises", st, key.Priority, raised())
		}
		if i > 0 && key.NewsSince(day) {
			t.Errorf("after %s: news again", st)
		}
	}
}
