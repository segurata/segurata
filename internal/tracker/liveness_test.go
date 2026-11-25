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
	return &secretrisk.Liveness{State: state, CheckedAt: at, Provider: "github", Endpoint: "GET api.github.com/user", Reason: reason, Account: account}
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

// A secret every provider host rejects is closed as done: nobody can use it, which is where a
// rotation ends too. A copy left in a working file does not reopen it, a later check that finds it
// live does, and the owner reopening it by hand sticks.
func TestDeadSecretClosesAsDone(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	writeSecrets(t, out, t0, ghLeak(t0, nil)...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	gh := mustRotate(t, tr, ghFP[:8])
	if gh.Status != Open || gh.LivenessLabel() != "unchecked" {
		t.Fatalf("before any check: %s %s", gh.Status, gh.LivenessLabel())
	}

	day2 := t0.Add(24 * time.Hour)
	writeSecrets(t, out, day2, ghLeak(day2, checked(secretrisk.Dead, day2, ""))...)
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	last := gh.History[len(gh.History)-1]
	if gh.Status != Done || last.Action != actDead || last.Detail != "key no longer valid (checked 2026-11-24: GET api.github.com/user answered HTTP 401)" || gh.LivenessLabel() != "dead" {
		t.Fatalf("dead: %s %+v %s", gh.Status, last, gh.LivenessLabel())
	}
	if r := strings.Join(gh.Secret.Reasons, "; "); !strings.Contains(r, "dead: GET api.github.com/user rejected it on 2026-11-24 (HTTP 401)") {
		t.Errorf("reasons %q", gh.Secret.Reasons)
	}

	// Still in .env and history on the next run: it stays done, with the history-only note.
	day3 := day2.Add(24 * time.Hour)
	writeSecrets(t, out, day3, ghLeak(day3, checked(secretrisk.Dead, day2, ""))...)
	syncOrDie(t, tr, out, day3.Add(time.Minute))
	if gh.Status != Done {
		t.Fatalf("a dead key in a working file reopened it: %s %+v", gh.Status, gh.History[len(gh.History)-1])
	}

	// Live again (a key re-enabled, or a check that was wrong): it opens, proven live.
	day4 := day3.Add(24 * time.Hour)
	writeSecrets(t, out, day4, ghLeak(day4, checked(secretrisk.Live, day4, ""))...)
	syncOrDie(t, tr, out, day4.Add(time.Minute))
	last = gh.History[len(gh.History)-1]
	if gh.Status != Open || last.Action != actProvenLive || !strings.Contains(last.Detail, "proven live by the liveness check of 2026-11-26") {
		t.Fatalf("live again: %s %+v", gh.Status, last)
	}

	// Dead again, but the owner reopened it by hand after that check: it stays open.
	day5 := day4.Add(24 * time.Hour)
	writeSecrets(t, out, day5, ghLeak(day5, checked(secretrisk.Dead, day5, ""))...)
	syncOrDie(t, tr, out, day5.Add(time.Minute))
	if gh.Status != Done {
		t.Fatalf("dead again: %s", gh.Status)
	}
	gh.Reopen(day5.Add(time.Hour), "I do not trust that check")
	syncOrDie(t, tr, out, day5.Add(2*time.Hour))
	if gh.Status != Open {
		t.Errorf("reopened by hand after the check: %s", gh.Status)
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
		localLeak("a1a1a1a1a1a1a1a1", nil))...)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	want := "Liveness checked for 2 of 4 secrets: 1 live, 1 dead, 1 unknown, 1 unchecked."
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
