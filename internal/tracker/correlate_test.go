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
	if len(rot.Findings) != 1 || rot.Findings[0].Match != byFingerprint || !rot.LiveAndLeaked() {
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
	if len(rot.live()) != 0 || rot.LiveAndLeaked() {
		t.Errorf("the rotated key is still live: %+v", rot.Findings)
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
	if err := it.Accept(t0.Add(2*time.Minute), "kept on purpose", ""); err != nil {
		t.Fatal(err)
	}
	day2 := t0.Add(24 * time.Hour)
	awsKeyRuns(t, out, day2, awsFP)
	syncOrDie(t, tr, out, day2.Add(time.Minute))
	if rot := mustRotate(t, tr, awsFP[:8]); it.Status != Accepted || len(it.Findings) != 1 || len(rot.live()) != 0 {
		t.Errorf("accepted finding claimed: %s, %d refs, live %+v", it.Status, len(it.Findings), rot.live())
	}
}

func TestNormalHint(t *testing.T) {
	for in, want := range map[string]secretrisk.Hint{
		"AKIA…(20)":               {Prefix: "AKIA", Len: 20},
		"sk-or-v1-27e...d4d":      {Prefix: "sk-or-v1-27e", Tail: "d4d"},
		"sk-proj-********xxkA":    {Prefix: "sk-proj-", Tail: "xxkA"},
		"sk-ant-api03-R2D...igAA": {Prefix: "sk-ant-api03-R2D", Tail: "igAA"},
		"sk-or-v1-…fd4d(73)":      {Prefix: "sk-or-v1-", Tail: "fd4d", Len: 73},
		"sk-proj-****…****j_MA":   {Prefix: "sk-proj-", Tail: "j_MA"},
	} {
		if got, ok := normalHint(in); !ok || got != want {
			t.Errorf("normalHint(%q) = %+v %v, want %+v", in, got, ok, want)
		}
	}
	if _, ok := normalHint("PEM"); ok {
		t.Error("PEM is not a hint of one value")
	}
	if !hintsFit(secretrisk.Hint{Prefix: "AKIA", Len: 20}, secretrisk.Hint{Prefix: "AKIARB", Len: 20}) ||
		hintsFit(secretrisk.Hint{Prefix: "AKIA", Len: 20}, secretrisk.Hint{Tail: "NCZX", Len: 40}) {
		t.Error("hintsFit")
	}
}
