package tracker

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
	"github.com/segurata/segurata/internal/secretrisk"
)

// leak is a local-secrets finding of one copy of a secret.
func leak(e secretrisk.Evidence, at time.Time) finding.Finding {
	f := fnd(SecretsConnector, "", "local", "secret", e.Source+":"+e.Path+"#"+e.Fingerprint, e.Type, finding.SevHigh, e.Type+" in "+e.Path, at)
	raw, _ := json.Marshal(e)
	_ = json.Unmarshal(raw, &f.Evidence)
	return f
}

// withEvidence sets a connector finding's evidence.
func withEvidence(f finding.Finding, ev map[string]any) finding.Finding {
	f.Evidence = ev
	return f
}

const awsFP = "a5a5a5a5a5a5a5a5"

// awsKeyRuns writes the default AWS key: in ~/.aws/credentials and pushed to a repository's history
// (local-secrets), and reported by the aws connector with the fingerprint it gives the key id.
func awsKeyRuns(t *testing.T, out string, at time.Time, connectorFP string) {
	t.Helper()
	cred := secretrisk.Evidence{Fingerprint: awsFP, Type: "aws-access-key-id", Redacted: "AKIA…(20)", Path: "~/.aws/credentials",
		Source: "scan", Kind: "config", Mode: "600", Bucket: "3-local", Count: 1}
	git := secretrisk.Evidence{Fingerprint: awsFP, Type: "aws-access-key-id", Redacted: "AKIA…(20)", Path: "~/src/legacyco/data/s3.py",
		Repo: "~/src/legacyco/data", Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "0-git", Count: 1, Date: "2019-05-02"}
	writeRun(t, out, at, "local-secrets.jsonl", leak(cred, at), leak(git, at), okStatus(SecretsConnector, "local"))
	key := withEvidence(fnd("aws", "", "local", "aws_local_credentials", "/x/.aws/credentials#default", "default", finding.SevMedium,
		`Long-lived AWS access key for profile "default" stored in plain text; aws sts says it works for account 012345678901`, at),
		map[string]any{"file": "~/.aws/credentials", "key_id": "AKIARB…(20)", "fingerprint": connectorFP, "sts_account": "012345678901"})
	writeRun(t, out, at, "aws.jsonl", key, okStatus("aws", "012345678901"))
}

// The aws connector's plain-text key and the leaked AWS key are one problem: the rotate item owns
// it (P0, "live key, leaked in …" first, the aws finding attached as live evidence), the aws item
// closes as merged into it, and opens again once the key in the file is another one.
func TestConnectorCredentialMergesIntoTheRotateItem(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	// Before local-secrets ran, the aws key had an item of its own.
	writeRun(t, out, t0, "aws.jsonl", withEvidence(fnd("aws", "", "local", "aws_local_credentials", "/x/.aws/credentials#default", "default",
		finding.SevMedium, `Long-lived AWS access key for profile "default" stored in plain text`, t0), map[string]any{"file": "~/.aws/credentials", "key_id": "AKIARB…(20)"}))
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	awsItem := byTitle(t, tr, "Long-lived AWS access key")
	if awsItem.Status != Open {
		t.Fatalf("aws item %s", awsItem.Status)
	}

	day2 := t0.Add(24 * time.Hour)
	awsKeyRuns(t, out, day2, awsFP)
	rep := syncOrDie(t, tr, out, day2.Add(time.Minute))
	rot := mustRotate(t, tr, awsFP[:8])
	if rot.Priority != secretrisk.P0 || len(rot.Secret.Reasons) == 0 || rot.Secret.Reasons[0] != "live key, leaked in legacyco/data:s3.py" {
		t.Errorf("rotate item: %s %q", rot.Priority, rot.Secret.Reasons)
	}
	if !strings.Contains(strings.Join(rot.Secret.Reasons, "; "), "live: aws: Long-lived AWS access key for profile \"default\" stored in plain text; aws sts says it works for account 012345678901") {
		t.Errorf("live evidence missing from the reasons: %q", rot.Secret.Reasons)
	}
	if len(rot.Findings) != 1 || rot.Findings[0].Match != byFingerprint || !rot.liveAndLeaked() {
		t.Errorf("rotate item refs: %+v", rot.Findings)
	}
	if awsItem.Status != Merged || awsItem.MergedInto != rot.ID || len(awsItem.Findings) != 0 || rep.Merged != 1 {
		t.Errorf("aws item: %s into %q, %d refs, merged %d", awsItem.Status, awsItem.MergedInto, len(awsItem.Findings), rep.Merged)
	}
	if !strings.Contains(awsItem.Next.Action, rot.ID+" owns this now") {
		t.Errorf("merged next step: %+v", awsItem.Next)
	}
	// Another sync of the same runs changes nothing.
	syncOrDie(t, tr, out, day2.Add(2*time.Minute))
	if awsItem.Status != Merged || len(rot.Findings) != 1 {
		t.Errorf("not stable: %s, %d refs", awsItem.Status, len(rot.Findings))
	}

	// The key in the file was rotated: the aws finding is another key, the leaked one is not live.
	day3 := day2.Add(24 * time.Hour)
	awsKeyRuns(t, out, day3, "b6b6b6b6b6b6b6b6")
	// The hint still fits and the old key's locations still name the file (locations are never
	// dropped), but the new key's fingerprint says it is another key.
	writeRun(t, out, day3, "local-secrets.jsonl", leak(secretrisk.Evidence{Fingerprint: awsFP, Type: "aws-access-key-id", Redacted: "AKIA…(20)",
		Path: "~/src/legacyco/data/s3.py", Repo: "~/src/legacyco/data", Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "0-git", Count: 1}, day3),
		okStatus(SecretsConnector, "local"))
	syncOrDie(t, tr, out, day3.Add(time.Minute))
	if awsItem.Status != Open || awsItem.MergedInto != "" || len(awsItem.Findings) != 1 {
		t.Errorf("aws item after the key changed: %s %q %d refs", awsItem.Status, awsItem.MergedInto, len(awsItem.Findings))
	}
	if len(rot.live()) != 0 || rot.liveAndLeaked() {
		t.Errorf("the rotated key is still live: %+v", rot.Findings)
	}
}

// An ignored secret that a connector proves live opens again: the connector's own item merges into
// it, so leaving it ignored would leave a live, leaked key with no open item. A rule's ignore gives
// way the same way and does not close it again; the owner ignoring it after the proof sticks. An
// accepted secret stays accepted: that risk was kept on purpose.
func TestProofOfALiveKeyReopensAnIgnoredSecret(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	cred := secretrisk.Evidence{Fingerprint: awsFP, Type: "aws-access-key-id", Redacted: "AKIA…(20)", Path: "~/src/legacyco/data/s3.py",
		Repo: "~/src/legacyco/data", Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "0-git", Count: 1, Date: "2019-05-02"}
	writeRun(t, out, t0, "local-secrets.jsonl", leak(cred, t0), okStatus(SecretsConnector, "local"))
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	rot := mustRotate(t, tr, awsFP[:8])
	d := tr.addDecision("manual:legacy", "Is legacyco dead?", []string{"yes"}, t0)
	d.Decision.Effects = []OptionEffect{{Option: "yes", Effect: effectIgnore, Scope: "path:~/src/legacyco"}}
	if _, closed, err := tr.decideWithEffects(d, t0.Add(2*time.Minute), "yes", nil, nil, nil); err != nil || closed != 1 || rot.Status != Ignored {
		t.Fatalf("decide: %d %v %s", closed, err, rot.Status)
	}

	day2 := t0.Add(24 * time.Hour)
	awsKeyRuns(t, out, day2, awsFP)
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if rot.Status != Open || rot.Priority != secretrisk.P0 {
		t.Fatalf("proven live: %s %s", rot.Status, rot.Priority)
	}
	// The proof reopens it, and raises it from the P2 of a key id alone to P0.
	n := len(rot.History)
	last, raised := rot.History[n-2], rot.History[n-1]
	if raised.Detail != "raised to P0 from P2" {
		t.Errorf("history %+v", raised)
	}
	if last.Action != actProvenLive || !strings.Contains(last.Detail, "proven live by aws") || !strings.Contains(last.Detail, "by decision "+d.ID) {
		t.Errorf("history %+v", last)
	}
	// The next sync of the same runs leaves it open: the rule does not close it again.
	syncOrDie(t, tr, out, day2.Add(2*time.Minute))
	if rot.Status != Open {
		t.Fatalf("closed again: %s", rot.Status)
	}

	// Ignored by hand after the proof: it stays ignored.
	if err := rot.ignore(day2.Add(time.Hour), "a canary key, live on purpose"); err != nil {
		t.Fatal(err)
	}
	syncOrDie(t, tr, out, day2.Add(2*time.Hour))
	if rot.Status != Ignored {
		t.Errorf("ignored after the proof: %s", rot.Status)
	}

	// Accepted: stays accepted.
	if err := rot.accept(day2.Add(3*time.Hour), "kept until the migration", ""); err != nil {
		t.Fatal(err)
	}
	day3 := day2.Add(24 * time.Hour)
	awsKeyRuns(t, out, day3, awsFP)
	syncOrDie(t, tr, out, day3.Add(time.Minute))
	if rot.Status != Accepted {
		t.Errorf("accepted: %s", rot.Status)
	}
}

// A secret marked rotated whose old value a connector still signs in with, in a run after the
// rotation, opens again: the old key works, so it was not rotated. Proof from a run before the
// rotation, or a match less certain than the fingerprint (a file's new key matched by path), does
// not reopen it; marking it rotated again holds until a later run proves the old key live again.
func TestProofOfALiveKeyReopensARotatedSecret(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	tr := New(t0)
	cred := secretrisk.Evidence{Fingerprint: awsFP, Type: "aws-access-key-id", Redacted: "AKIA…(20)", Path: "~/src/legacyco/data/s3.py",
		Repo: "~/src/legacyco/data", Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "0-git", Count: 1, Date: "2019-05-02"}
	key := func(at time.Time, fp string) finding.Finding {
		return withEvidence(fnd("aws", "", "local", "aws_local_credentials", "/x/.aws/credentials#default", "default", finding.SevMedium,
			`Long-lived AWS access key for profile "default" stored in plain text; aws sts says it works for account 012345678901`, at),
			map[string]any{"file": "~/.aws/credentials", "key_id": "AKIARB…(20)", "fingerprint": fp, "sts_account": "012345678901"})
	}
	writeRun(t, out, t0, "local-secrets.jsonl", leak(cred, t0), okStatus(SecretsConnector, "local"))
	writeRun(t, out, t0, "aws.jsonl", key(t0, awsFP), okStatus("aws", "012345678901"))
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	rot := mustRotate(t, tr, awsFP[:8])
	rot.Done(t0.Add(time.Hour), "rotated in the console")
	// The same runs, from before the rotation, prove nothing.
	syncOrDie(t, tr, out, t0.Add(2*time.Hour))
	if rot.Status != Done {
		t.Fatalf("reopened by a run older than the rotation: %s", rot.Status)
	}

	day2 := t0.Add(24 * time.Hour)
	writeRun(t, out, day2, "local-secrets.jsonl", leak(cred, day2), okStatus(SecretsConnector, "local"))
	writeRun(t, out, day2, "aws.jsonl", key(day2, awsFP), okStatus("aws", "012345678901"))
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if rot.Status != Open {
		t.Fatalf("the old key still works: %s", rot.Status)
	}
	last := rot.History[len(rot.History)-1]
	if last.Action != actProvenLive || !strings.Contains(last.Detail, "proven live by aws") || !strings.Contains(last.Detail, "after it was marked rotated: rotated in the console") {
		t.Errorf("history %+v", last)
	}

	// Rotated again, and the next run reports another key in the file: it stays rotated.
	rot.Done(day2.Add(time.Hour), "")
	day3 := day2.Add(24 * time.Hour)
	writeRun(t, out, day3, "local-secrets.jsonl", leak(cred, day3), okStatus(SecretsConnector, "local"))
	writeRun(t, out, day3, "aws.jsonl", key(day3, "b6b6b6b6b6b6b6b6"), okStatus("aws", "012345678901"))
	syncOrDie(t, tr, out, day3.Add(time.Minute))
	if rot.Status != Done {
		t.Errorf("reopened by another key: %s", rot.Status)
	}
}

// Without a fingerprint, a provider key matches by its redacted hint and service, a credential
// file by its path; info findings (a key in use) are evidence too, and a secret a connector signs
// in with (run_end) is live.
func TestCorrelationByHintPathAndConnectorSecrets(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	or := secretrisk.Evidence{Fingerprint: "0123012301230123", Type: "openrouter", Redacted: "sk-or-v1-…fd4d(73)", Path: "~/.claude/projects/p/s.jsonl",
		Source: "scan", Kind: "transcript", Mode: "600", Bucket: "2-trail", Count: 1}
	sa := secretrisk.Evidence{Fingerprint: "4567456745674567", Type: "gcp-service-account", Redacted: "PEM", Path: "~/.config/gcloud/legacy_credentials/pp@x.iam.gserviceaccount.com/adc.json",
		Source: "scan", Kind: "config", Mode: "600", Bucket: "3-local", Count: 1}
	vc := secretrisk.Evidence{Fingerprint: "89ab89ab89ab89ab", Type: "vercel-api-token", Redacted: "…wxyz(24)", Path: "~/src/site/.env",
		Source: "scan", Kind: "repo", Mode: "600", Bucket: "3-local", Count: 1}
	other := secretrisk.Evidence{Fingerprint: "cdefcdefcdefcdef", Type: "openrouter", Redacted: "sk-or-v1-…0000(73)", Path: "~/.zshrc",
		Source: "scan", Kind: "config", Mode: "600", Bucket: "3-local", Count: 1}
	writeRun(t, out, t0, "local-secrets.jsonl", leak(or, t0), leak(sa, t0), leak(vc, t0), leak(other, t0), okStatus(SecretsConnector, "local"))
	writeRun(t, out, t0, "openrouter-personal.jsonl",
		withEvidence(fnd("openrouter", "personal", "Default Workspace", "api_key", "k1", "Claude Code", finding.SevInfo, `API key "Claude Code": in use with a credit limit`, t0),
			map[string]any{"redacted": "sk-or-v1-27e...d4d", "usage_month": 40.5}),
		withEvidence(fnd("openrouter", "personal", "Default Workspace", "api_key", "k2", "Old", finding.SevMedium, `API key "Old": never used`, t0),
			map[string]any{"redacted": "sk-or-v1-999...111"}),
		okStatus("openrouter", "Default Workspace"))
	writeRun(t, out, t0, "gcp.jsonl", withEvidence(fnd("gcp", "", "local", "local_credential", "/x/adc.json", "adc.json", finding.SevHigh,
		"Service account private key for pp@x.iam.gserviceaccount.com on disk (gcloud config folder)", t0),
		map[string]any{"path": "~/.config/gcloud/legacy_credentials/pp@x.iam.gserviceaccount.com/adc.json"}), okStatus("gcp", "me@x.com"))
	writeRun(t, out, t0, "vercel.jsonl", okStatus("vercel", "vercel"), runtest.Fingerprints{"VERCEL_TOKEN": "89ab89ab89ab89ab"})
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Minute))

	key := mustRotate(t, tr, "01230123")
	if len(key.Findings) != 1 || key.Findings[0].Match != byHint || key.Priority != secretrisk.P0 ||
		key.Secret.Reasons[0] != "live key, leaked in ~/.claude/projects/p/s.jsonl" {
		t.Errorf("openrouter key: %s %+v %q", key.Priority, key.Findings, key.Secret.Reasons)
	}
	if o := mustRotate(t, tr, "cdefcdef"); len(o.Findings) != 0 {
		t.Errorf("a key with another tail was matched: %+v", o.Findings)
	}
	byTitle(t, tr, "Revoke or limit 1 OpenRouter API key") // the unmatched key keeps its own item

	sak := mustRotate(t, tr, "45674567")
	if len(sak.Findings) != 1 || sak.Findings[0].Match != byPath || sak.Priority != secretrisk.P1 {
		t.Errorf("service-account key: %s %+v (the connector's high raises a local P2)", sak.Priority, sak.Findings)
	}
	for _, it := range tr.Items {
		if strings.HasPrefix(it.Title, "Service account private key") {
			t.Errorf("the claimed gcp finding got an item of its own: %s", it.ID)
		}
	}

	tok := mustRotate(t, tr, "89ab89ab")
	if len(tok.Findings) != 1 || !strings.Contains(tok.Findings[0].Title, "segurata's vercel connector signs in with it (VERCEL_TOKEN) and its run of") {
		t.Errorf("vercel token: %+v", tok.Findings)
	}
}

// A connector finding whose item the owner accepted stays there.
func TestAcceptedConnectorFindingIsNotClaimed(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	key := withEvidence(fnd("aws", "", "local", "aws_local_credentials", "/x/.aws/credentials#default", "default", finding.SevMedium,
		`Long-lived AWS access key for profile "default" stored in plain text`, t0), map[string]any{"file": "~/.aws/credentials", "fingerprint": awsFP})
	writeRun(t, out, t0, "aws.jsonl", key)
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Minute))
	it := byTitle(t, tr, "Long-lived AWS access key")
	if err := it.accept(t0.Add(2*time.Minute), "kept on purpose", ""); err != nil {
		t.Fatal(err)
	}
	day2 := t0.Add(24 * time.Hour)
	awsKeyRuns(t, out, day2, awsFP)
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if rot := mustRotate(t, tr, awsFP[:8]); it.Status != Accepted || len(it.Findings) != 1 || len(rot.live()) != 0 {
		t.Errorf("accepted finding claimed: %s, %d refs, live %+v", it.Status, len(it.Findings), rot.live())
	}
}

// A provider key matched by its hint puts the provider's facts in the rotate item's title (its name,
// in use, spend this month), with the confidence of the match; a hint that fits two secrets merges
// into neither and is recorded on both as possible, leaving the connector's item alone.
func TestHintMatchConfidenceFactsAndAmbiguity(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	ev := func(fp, redacted, path string) secretrisk.Evidence {
		typ := "openrouter"
		if strings.HasPrefix(redacted, "sk-proj-") {
			typ = "openai"
		}
		return secretrisk.Evidence{Fingerprint: fp, Type: typ, Redacted: redacted, Path: path, Source: "scan", Kind: "transcript", Mode: "600", Bucket: "2-trail", Count: 1}
	}
	used := t0.Add(-48 * time.Hour)
	key := func(id, name, redacted string, spend float64) finding.Finding {
		f := withEvidence(fnd("openrouter", "personal", "Default Workspace", "api_key", id, name, finding.SevMedium, `API key "`+name+`": in use with a credit limit`, t0),
			map[string]any{"redacted": redacted, "usage_month": spend})
		f.LastUsedAt = &used
		return f
	}
	writeRun(t, out, t0, "local-secrets.jsonl",
		leak(ev("1111111111111111", "sk-or-v1-…fd4d(73)", "~/.claude/projects/a/s.jsonl"), t0),
		leak(ev("2222222222222222", "sk-or-v1-…ab12(73)", "~/.claude/projects/b/s.jsonl"), t0),
		leak(ev("3333333333333333", "sk-or-v1-…ab12(73)", "~/.claude/projects/c/s.jsonl"), t0),
		leak(ev("4444444444444444", "sk-proj-…j_MA(164)", "~/.claude/projects/d/s.jsonl"), t0),
		okStatus(SecretsConnector, "local"))
	writeRun(t, out, t0, "openrouter-personal.jsonl",
		key("k1", "Claude Code", "sk-or-v1-27e…d4d(?)", 42),
		key("k2", "Shared", "sk-or-v1-9f0…ab12(?)", 0),
		okStatus("openrouter", "Default Workspace"))
	writeRun(t, out, t0, "openai.jsonl",
		withEvidence(fnd("openai", "", "org", "api_key", "key_x", "ci", finding.SevMedium, `API key "ci" in project "lab": never used`, t0),
			map[string]any{"redacted": "sk-proj-…j_MA(164)"}),
		okStatus("openai", "org"))
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Minute))

	cc := mustRotate(t, tr, "11111111")
	if len(cc.Findings) != 1 || cc.Findings[0].Match != byHint || cc.Findings[0].Confidence != confMedium {
		t.Errorf("Claude Code key refs: %+v", cc.Findings)
	}
	if want := `sk-or-v1-…fd4d(73) = "Claude Code" (in use, $42.00 this month) in `; !strings.Contains(cc.Title, want) {
		t.Errorf("title %q lacks %q", cc.Title, want)
	}

	// The OpenAI key shows its length and four characters: a high-confidence match, never used.
	ci := mustRotate(t, tr, "44444444")
	if len(ci.Findings) != 1 || ci.Findings[0].Confidence != confHigh || !strings.Contains(ci.Title, `(164) = "ci" in `) {
		t.Errorf("OpenAI key: %q %+v", ci.Title, ci.Findings)
	}

	for _, fp := range []string{"22222222", "33333333"} {
		it := mustRotate(t, tr, fp)
		if len(it.Findings) != 0 || len(it.Possible) != 1 || it.Possible[0].Match != byPossible || it.Possible[0].Resource != "k2" {
			t.Errorf("%s: findings %+v possible %+v", fp, it.Findings, it.Possible)
		}
		if strings.Contains(it.Title, `"Shared"`) || it.Priority != secretrisk.P1 && it.Priority != secretrisk.P2 && it.Priority != secretrisk.P3 {
			t.Errorf("%s: a possible match named or raised the item: %s %q", fp, it.Priority, it.Title)
		}
		if r := strings.Join(it.Secret.Reasons, "; "); !strings.Contains(r, `possibly: openrouter:personal: API key "Shared": in use with a credit limit (its hint fits 2 secrets)`) {
			t.Errorf("%s: reasons %q", fp, r)
		}
	}
	// The ambiguous key keeps its own item.
	shared := byTitle(t, tr, "Revoke or limit 1 OpenRouter API key")
	if len(shared.Findings) != 1 || shared.Findings[0].Resource != "k2" || shared.Status != Open {
		t.Errorf("shared key item: %s %+v", shared.Status, shared.Findings)
	}

	// The next sync without the ambiguous key drops the possible refs.
	writeRun(t, out, t0.Add(time.Hour), "openrouter-personal.jsonl", key("k1", "Claude Code", "sk-or-v1-27e…d4d(?)", 42), okStatus("openrouter", "Default Workspace"))
	syncOrDie(t, tr, out, t0.Add(2*time.Hour))
	if it := mustRotate(t, tr, "22222222"); len(it.Possible) != 0 {
		t.Errorf("stale possible refs: %+v", it.Possible)
	}
}
