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

func fnd(connector, instance, account, resType, resID, name string, sev finding.Severity, title string, at time.Time) finding.Finding {
	f := finding.Finding{Connector: connector, Instance: instance, Account: account, Resource: finding.Resource{Type: resType, ID: resID, Name: name},
		Severity: sev, Title: title, ObservedAt: at, Remediation: finding.Remediation{Summary: "Fix: " + title, URL: "https://example.com/" + resID}}
	f.Fill(at)
	return f
}

// dumpFinding is a local-secrets data_dump finding of one file of a repository, as the connector
// writes it.
func dumpFinding(repo, path string, sev finding.Severity, size int64, at time.Time) finding.Finding {
	f := fnd(SecretsConnector, "", "local", "data_dump", repo+":"+path, path, sev, "Database dump committed to "+repo+": "+path+" ("+secretrisk.HumanSize(size)+", pushed)", at)
	f.Evidence = map[string]any{"source": "data-dump", "repo": repo, "path": path, "size_bytes": float64(size), "size": secretrisk.HumanSize(size), "remote": true}
	return f
}

func okStatus(connector, account string) finding.Status {
	return finding.Status{Type: "status", Connector: connector, Account: account, State: finding.StateOK}
}

// writeRun writes one connector instance's finished output under out/<date>/<file>.
func writeRun(t *testing.T, out string, at time.Time, file string, recs ...any) {
	t.Helper()
	runtest.Write(t, filepath.Join(out, at.Format(time.DateOnly), file), recs...)
}

func syncOrDie(t *testing.T, tr *Tracker, out string, now time.Time) SyncReport {
	t.Helper()
	rep, err := tr.Sync(SyncOptions{OutDir: out}, now)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func byTitle(t *testing.T, tr *Tracker, prefix string) *Item {
	t.Helper()
	var hit *Item
	for _, it := range tr.Items {
		if strings.HasPrefix(it.Title, prefix) {
			if hit != nil {
				t.Fatalf("two items start with %q: %s and %s", prefix, hit.ID, it.ID)
			}
			hit = it
		}
	}
	if hit == nil {
		var titles []string
		for _, it := range tr.Items {
			titles = append(titles, it.Title)
		}
		t.Fatalf("no item starts with %q in %q", prefix, titles)
	}
	return hit
}

func countKind(tr *Tracker, k Kind) int {
	n := 0
	for _, it := range tr.Items {
		if it.Kind == k {
			n++
		}
	}
	return n
}

func TestGroupingRules(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	var gh []any
	for _, org := range []string{"acme-labs", "northwind", "globex", "initech", "umbrella-co"} {
		gh = append(gh, fnd("github", "", "github:"+org, "github_org_setting", "org-2fa-not-required", org, finding.SevHigh, org+" does not require two-factor authentication", t0))
	}
	gh = append(gh,
		fnd("github", "", "github:acme-labs", "github_org_setting", "org-all-actions-allowed", "acme-labs", finding.SevLow, "Workflows in acme-labs may use any action from any author", t0),
		fnd("github", "", "github:acme", "github_repo", "1", "acme/a", finding.SevMedium, "acme/a: secret scanning is off", t0),
		fnd("github", "", "github:acme", "github_repo", "2", "acme/b", finding.SevMedium, "acme/b: secret scanning is off", t0),
		okStatus("github", "github:octocat"))
	writeRun(t, out, t0, "github.jsonl", gh...)

	var apps []any
	for _, n := range []string{"Flickr", "Budge", "Klout.com"} {
		apps = append(apps, fnd("connected-apps", "", "x:@me", "x_app", "x:"+n, n, finding.SevHigh, n+" can post and delete posts as you", t0))
	}
	apps = append(apps,
		fnd("connected-apps", "", "x:@me", "x_app", "x:Gil", "Gil", finding.SevHigh, "Gil can read your direct messages", t0),
		fnd("connected-apps", "", "x:@me", "x_app", "x:Crunchbase", "Crunchbase", finding.SevMedium, "Crunchbase can read your account", t0),
		fnd("connected-apps", "", "slack:ws.slack.com", "slack_app", "slack:a", "A", finding.SevHigh, "A can use 31 permissions in ws.slack.com", t0),
		fnd("connected-apps", "", "slack:ws.slack.com", "slack_app", "slack:b", "B", finding.SevHigh, "B can use 17 permissions in ws.slack.com", t0),
		finding.Status{Type: "status", Connector: "connected-apps", Account: "microsoft", State: finding.StateSignedOut, Detail: "not signed in"})
	writeRun(t, out, t0, "connected-apps.jsonl", apps...)

	gcp := func(project, name string) finding.Finding {
		f := fnd("gcp", "", "me@gmail.com", "api_key", project+"/"+name, name, finding.SevHigh, `API key "`+name+`" in `+project+" has no API restrictions", t0)
		f.Evidence = map[string]any{"project": project}
		return f
	}
	writeRun(t, out, t0, "gcp.jsonl", gcp("example", "k1"), gcp("example", "k2"), gcp("example", "k3"),
		finding.Status{Type: "status", Connector: "gcp", Account: "admin@x.com", State: finding.StateReauth, Detail: "run gcloud auth login admin@x.com"})

	writeRun(t, out, t0, "macos.jsonl",
		fnd("macos", "", "Mac", "macos_setting", "backup-none", "backup-none", finding.SevHigh, "No Time Machine backup is configured", t0),
		fnd("macos", "", "Mac", "macos_setting", "updates-pending", "updates-pending", finding.SevMedium, "macOS has updates waiting to be installed", t0),
		fnd("macos", "", "Mac", "background_item", "bg1", "bg1", finding.SevInfo, "Background item bg1", t0),
		okStatus("macos", "Mac"))

	dump := func(path string, sev finding.Severity) finding.Finding {
		return dumpFinding("~/src/api", path, sev, 365<<10, t0)
	}
	secret := func(fp, kind, path string) finding.Finding {
		f := fnd(SecretsConnector, "", "local", "secret", "scan:"+path+"#"+fp, "Stripe live key", finding.SevCritical, "Stripe live secret key in "+path, t0)
		raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: fp, Type: "stripe-live", Redacted: "sk_live_…" + fp[:4] + "(107)", Path: path,
			Source: "scan", Kind: kind, Mode: "600", Bucket: "b"})
		_ = json.Unmarshal(raw, &f.Evidence)
		return f
	}
	writeRun(t, out, t0, "local-secrets.jsonl", dump("a.sql", finding.SevHigh), dump("b.sql", finding.SevCritical), dump("c.sql", finding.SevInfo),
		secret("aaaaaaaaaaaaaaaa", "repo", "~/src/shop/.env"), secret("aaaaaaaaaaaaaaaa", "transcript", "~/.claude/projects/p/s.jsonl"),
		secret("bbbbbbbbbbbbbbbb", "history", "~/.zsh_history"), okStatus(SecretsConnector, "local"))

	tr := New(t0)
	rep := syncOrDie(t, tr, out, t0.Add(time.Hour))
	if len(rep.Runs) != 5 || rep.Secrets.Created != 2 {
		t.Fatalf("report %+v", rep)
	}

	twoFA := byTitle(t, tr, "Two-factor authentication not required in 5 GitHub orgs")
	if len(twoFA.Findings) != 5 || twoFA.Kind != KindFix || twoFA.Theme != "github-orgs" || twoFA.Priority != secretrisk.P1 || twoFA.Severity != finding.SevHigh {
		t.Errorf("2FA item %+v", twoFA)
	}
	byTitle(t, tr, "Workflows may use any action from any author in 1 GitHub org")
	if it := byTitle(t, tr, "Repository security settings off in 2 repositories of github:acme"); len(it.Findings) != 2 {
		t.Errorf("repos %+v", it)
	}
	posts := byTitle(t, tr, "3 X apps can post and delete posts as you")
	if posts.Kind != KindReview || posts.Theme != "connected-apps" || posts.Next.Command != "segurata track show "+posts.ID {
		t.Errorf("X apps %+v %+v", posts, posts.Next)
	}
	byTitle(t, tr, "Gil can read your direct messages")
	byTitle(t, tr, "Crunchbase can read your account")
	byTitle(t, tr, "Review 2 Slack apps with broad permissions in ws.slack.com")
	byTitle(t, tr, "Restrict 2 API keys in GCP project example")
	byTitle(t, tr, "Restrict 1 API key in GCP project example")
	backup := byTitle(t, tr, "No Time Machine backup is configured")
	if backup.Theme != "mac" || backup.Key != pinnedKey(backup.Findings[0].ID) || backup.Next.URL != "https://example.com/backup-none" {
		t.Errorf("mac item %+v", backup)
	}
	byTitle(t, tr, "macOS has updates waiting")
	for _, it := range tr.Items {
		if strings.Contains(it.Title, "Background item") || strings.Contains(it.Title, "c.sql") {
			t.Errorf("an info finding made an item: %s", it.Title)
		}
	}
	// Data dumps: one item per repository, purged in one pass, worst file first; the guide is the
	// page, the breach-notification duty the secondary step.
	dumps := byTitle(t, tr, "2 database dumps in the git history of ~/src/api (730 KB)")
	if dumps.Theme != "data-dumps" || dumps.Priority != secretrisk.P0 || len(dumps.Findings) != 2 || dumps.Next.URL != secretrisk.DumpFixDoc {
		t.Errorf("dumps %+v %+v", dumps, dumps.Next)
	}
	for _, want := range []string{"`git filter-repo --invert-paths --path 'b.sql' --path 'a.sql'` and force-push", "\nFiles: b.sql (365 KB, pushed); a.sql (365 KB, pushed).\n",
		secretrisk.URLAEPDBreaches, secretrisk.URLEDPBBreaches} {
		if !strings.Contains(dumps.Next.Action, want) {
			t.Errorf("dumps next step lacks %q: %s", want, dumps.Next.Action)
		}
	}
	trails := byTitle(t, tr, "Redact secrets from 2 trail files")
	if trails.Theme != "transcripts" || trails.Severity != finding.SevMedium || trails.Next.Who != Segurata || trails.Next.Command != "segurata redact --trails" {
		t.Errorf("trails item %+v %+v", trails, trails.Next)
	}
	if countKind(tr, KindRotate) != 2 {
		t.Errorf("rotate items %d", countKind(tr, KindRotate))
	}
	reauth := byTitle(t, tr, "gcp · admin@x.com: needs a fresh sign-in")
	if reauth.Kind != KindSetup || reauth.Theme != "setup" || !strings.Contains(reauth.Next.Action, "Then: segurata inventory gcp.") ||
		reauth.Next.Command != "gcloud auth login admin@x.com" || reauth.Findings[0].Title != "run gcloud auth login admin@x.com" {
		t.Errorf("setup item %+v %+v", reauth, reauth.Next)
	}
	byTitle(t, tr, "connected-apps · microsoft: is signed out")

	// A second sync of the same runs changes nothing.
	before := len(tr.Items)
	rep = syncOrDie(t, tr, out, t0.Add(2*time.Hour))
	if len(tr.Items) != before || rep.Created != 0 || rep.Verified != 0 || rep.Reopened != 0 || rep.Secrets.Created != 0 {
		t.Errorf("resync: %d -> %d items, %+v", before, len(tr.Items), rep)
	}
}

// lifecycleFixture is a tracker after one macos run reporting two findings; the next runs are
// written by the test.
func lifecycleFixture(t *testing.T) (*Tracker, string, finding.Finding, finding.Finding) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	fw := fnd("macos", "", "Mac", "macos_setting", "firewall", "firewall", finding.SevMedium, "The firewall is off", t0)
	port := fnd("macos", "", "Mac", "listening_port", "listen-445", "TCP 445", finding.SevMedium, "SMB listens on port 445", t0)
	writeRun(t, out, t0, "macos.jsonl", fw, port, okStatus("macos", "Mac"))
	tr := New(t0)
	syncOrDie(t, tr, out, t0)
	return tr, out, fw, port
}

func at(f finding.Finding, when time.Time) finding.Finding {
	f.ObservedAt = when
	return f
}

func lastAction(it *Item) string { return it.History[len(it.History)-1].Action }

func TestVanishedFindingsAutoCloseAsVerified(t *testing.T) {
	tr, out, fw, port := lifecycleFixture(t)
	day1 := t0.AddDate(0, 0, 1)
	writeRun(t, out, day1, "macos.jsonl", at(port, day1), okStatus("macos", "Mac"))
	rep := syncOrDie(t, tr, out, day1)
	it := byTitle(t, tr, "The firewall is off")
	if it.Status != Done || it.VerifiedAt == nil || lastAction(it) != actAutoDone || rep.Verified != 1 {
		t.Fatalf("not auto-done: %+v %+v", it, rep)
	}
	if it.History[len(it.History)-1].Event != EvVerified || !it.Findings[0].Gone {
		t.Errorf("history %+v refs %+v", it.History, it.Findings)
	}
	if byTitle(t, tr, "SMB listens").Status != Open {
		t.Error("the finding still reported was closed")
	}

	// It comes back: reopened.
	day2 := t0.AddDate(0, 0, 2)
	writeRun(t, out, day2, "macos.jsonl", at(fw, day2), at(port, day2), okStatus("macos", "Mac"))
	rep = syncOrDie(t, tr, out, day2)
	if it.Status != Open || it.VerifiedAt != nil || lastAction(it) != actAutoReopen || rep.Reopened != 1 || it.Findings[0].Gone {
		t.Errorf("not reopened: %+v %+v", it, rep)
	}
	_ = fw
}

func TestDoneIsVerifiedOnlyByALaterRunAndReopenedIfStillThere(t *testing.T) {
	tr, out, fw, port := lifecycleFixture(t)
	it := byTitle(t, tr, "The firewall is off")
	marked := t0.Add(2 * time.Hour)
	it.Done(marked, "turned it on")

	// The sync right after marking reads the old run: nothing happens yet.
	rep := syncOrDie(t, tr, out, marked.Add(time.Minute))
	if it.Status != Done || it.VerifiedAt != nil || rep.Reopened+rep.Verified != 0 {
		t.Fatalf("old run judged the item: %+v %+v", it, rep)
	}

	// A later run without it verifies it.
	day1 := t0.AddDate(0, 0, 1)
	writeRun(t, out, day1, "macos.jsonl", at(port, day1), okStatus("macos", "Mac"))
	rep = syncOrDie(t, tr, out, day1)
	if it.Status != Done || it.VerifiedAt == nil || lastAction(it) != actVerified || rep.Verified != 1 {
		t.Fatalf("not verified: %+v %+v", it, rep)
	}

	// Marked done, but a later run still reports it: reopened.
	other := byTitle(t, tr, "SMB listens")
	other.Done(day1.Add(time.Hour), "closed it")
	day2 := t0.AddDate(0, 0, 2)
	writeRun(t, out, day2, "macos.jsonl", at(port, day2), okStatus("macos", "Mac"))
	rep = syncOrDie(t, tr, out, day2)
	if other.Status != Open || lastAction(other) != actAutoReopen || !strings.Contains(other.History[len(other.History)-1].Detail, "macos") {
		t.Errorf("not reopened: %+v", other)
	}
	_ = fw
}

func TestAFindingIsNotGoneWhenItsAccountCouldNotBeInspected(t *testing.T) {
	tr, out, _, _ := lifecycleFixture(t)
	day1 := t0.AddDate(0, 0, 1)
	writeRun(t, out, day1, "macos.jsonl", finding.Status{Type: "status", Connector: "macos", Account: "Mac", State: finding.StateError, Detail: "dscl failed"})
	syncOrDie(t, tr, out, day1)
	if it := byTitle(t, tr, "The firewall is off"); it.Status != Open || it.Findings[0].Gone {
		t.Errorf("closed while the account could not be inspected: %+v", it)
	}
	if byTitle(t, tr, "macos · Mac: failed").Kind != KindSetup {
		t.Error("no setup item for the error")
	}
	// The error clears: its setup item is verified done.
	day2 := t0.AddDate(0, 0, 2)
	writeRun(t, out, day2, "macos.jsonl", okStatus("macos", "Mac"))
	syncOrDie(t, tr, out, day2)
	if it := byTitle(t, tr, "macos · Mac: failed"); it.Status != Done || it.VerifiedAt == nil {
		t.Errorf("setup item %+v", it)
	}
}

func TestSnoozeAndAcceptanceExpiryAndStaleRuns(t *testing.T) {
	tr, out, fw, port := lifecycleFixture(t)
	smb := byTitle(t, tr, "SMB listens")
	if err := smb.Snooze(t0, "2026-11-25", "after the trip"); err != nil {
		t.Fatal(err)
	}
	firewall := byTitle(t, tr, "The firewall is off")
	if err := firewall.Accept(t0, "lab machine", "2026-11-24"); err != nil {
		t.Fatal(err)
	}
	rep := syncOrDie(t, tr, out, t0.AddDate(0, 0, 1))
	if smb.Status != Snoozed || firewall.Status != Accepted || rep.Woken+rep.Lapsed != 0 {
		t.Fatalf("expired too early: %s %s %+v", smb.Status, firewall.Status, rep)
	}
	rep = syncOrDie(t, tr, out, time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC))
	if smb.Status != Open || lastAction(smb) != actWake || firewall.Status != Open || lastAction(firewall) != actAcceptLapse || rep.Woken != 1 || rep.Lapsed != 1 {
		t.Fatalf("not expired: %s %s %+v", smb.Status, firewall.Status, rep)
	}
	if !firewall.AcceptanceExpired(t0) || firewall.Accepted == nil {
		t.Error("a lapsed acceptance must stay visible as expired")
	}
	f := fw
	tr.Annotator(func() time.Time { return t0 })(&f)
	if f.Accepted == nil || !f.Accepted.Expired {
		t.Errorf("annotation after the lapse: %+v", f.Accepted)
	}

	// An older run (another output folder) is never folded over a newer one.
	old := filepath.Join(t.TempDir(), "old")
	writeRun(t, old, t0.AddDate(0, 0, -5), "macos.jsonl", at(port, t0.AddDate(0, 0, -5)), okStatus("macos", "Mac"))
	rep = syncOrDie(t, tr, old, t0.AddDate(0, 0, 3))
	if len(rep.Stale) != 1 || rep.Stale[0] != "macos" || firewall.Status != Open {
		t.Errorf("stale run folded: %+v %s", rep, firewall.Status)
	}
}

func TestAcceptingOneFindingOfAGroupSplitsIt(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	var gh []any
	var first finding.Finding
	for i, org := range []string{"a", "b", "c"} {
		f := fnd("github", "", "github:"+org, "github_org_setting", "org-2fa-not-required", org, finding.SevHigh, org+" does not require 2FA", t0)
		if i == 0 {
			first = f
		}
		gh = append(gh, f)
	}
	writeRun(t, out, t0, "github.jsonl", gh...)
	tr := New(t0)
	syncOrDie(t, tr, out, t0)
	group := byTitle(t, tr, "Two-factor authentication not required in 3")
	it, err := tr.AcceptFinding(first, "a is a sandbox org", "", t0)
	if err != nil {
		t.Fatal(err)
	}
	if it == group || len(group.Findings) != 2 || it.Key != pinnedKey(first.ID) || it.Status != Accepted {
		t.Fatalf("not split: %+v %+v", it, group)
	}
	syncOrDie(t, tr, out, t0.Add(time.Hour))
	if len(group.Findings) != 2 || !strings.Contains(group.Title, "in 2 GitHub orgs") || it.Status != Accepted || len(it.Findings) != 1 {
		t.Errorf("after sync: group %q %d, pinned %s %d", group.Title, len(group.Findings), it.Status, len(it.Findings))
	}
	f := first
	tr.Annotator(func() time.Time { return t0 })(&f)
	if !f.Hidden() {
		t.Error("the accepted finding is not hidden")
	}
	if _, err := tr.Unaccept(first.ID[:6], t0); err != nil || it.Status != Open {
		t.Errorf("unaccept: %v %s", err, it.Status)
	}
}

func TestSeedDecisionsAreCreatedOnce(t *testing.T) {
	tr := New(t0)
	n := countKind(tr, KindDecide)
	if n != len(seedDecisions) {
		t.Fatalf("%d decisions", n)
	}
	d := byTitle(t, tr, "Install the daily scheduled inventory?")
	if err := d.Decide(t0, "yes"); err != nil || d.Status != Done || d.Decision.Answer != "yes" {
		t.Fatalf("decide: %v %+v", err, d)
	}
	tr.seed(t0.Add(time.Hour))
	if countKind(tr, KindDecide) != n {
		t.Error("an answered decision came back")
	}
	if err := tr.newItem(KindFix, "manual:x", "other", "Fix it", t0).Decide(t0, "x"); err == nil {
		t.Error("a fix item took an answer")
	}
}

// Several statuses under one setup key (gcp: one per project it could not read) make one item that
// keeps a ref per distinct detail and counts them in its title.
func TestSetupStatusesSharingAKeyKeepEveryRef(t *testing.T) {
	out := t.TempDir()
	st := func(project string) finding.Status {
		return finding.Status{Type: "status", Connector: "gcp", Account: "a@x.com", Scope: project, State: finding.StateError,
			Detail: "project " + project + ": permission denied for iam policy, service accounts, api keys"}
	}
	writeRun(t, out, t0, "gcp.jsonl", okStatus("gcp", "a@x.com"), st("p1"), st("p2"), st("p3"), st("p3"))
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Hour))
	it := byTitle(t, tr, "gcp: permission denied on 3 projects for a@x.com")
	if len(it.Findings) != 3 || it.Kind != KindSetup || it.Findings[0].LastSeen.IsZero() {
		t.Fatalf("refs %+v", it.Findings)
	}
	// One project becomes readable: its ref is gone, the item stays open with the other two.
	writeRun(t, out, t0.Add(24*time.Hour), "gcp.jsonl", okStatus("gcp", "a@x.com"), st("p1"), st("p2"))
	syncOrDie(t, tr, out, t0.Add(25*time.Hour))
	gone := 0
	for _, r := range it.Findings {
		if r.Gone {
			gone++
		}
	}
	if gone != 1 || it.Status != Open || it.Title != "gcp: permission denied on 2 projects for a@x.com" {
		t.Errorf("after one project cleared: %d gone, %s, %q", gone, it.Status, it.Title)
	}
}

// The core's one missing_credentials status for the instance replaces the per-account one the
// connector used to emit: the old setup item is verified done even though the run inspected nothing.
func TestAnInstanceWideStatusCoversThePerAccountOne(t *testing.T) {
	out := t.TempDir()
	missing := func(account, detail string) finding.Status {
		return finding.Status{Type: "status", Connector: "anthropic", Instance: "personal", Account: account, State: finding.StateMissingCredentials, Detail: detail}
	}
	writeRun(t, out, t0, "anthropic-personal.jsonl", missing("", "ANTHROPIC_ADMIN_KEY: not set"), missing("organization", "set ANTHROPIC_ADMIN_KEY"))
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Hour))
	org := byTitle(t, tr, "anthropic:personal · organization")
	writeRun(t, out, t0.Add(24*time.Hour), "anthropic-personal.jsonl", missing("", "ANTHROPIC_ADMIN_KEY: not set; set ANTHROPIC_ADMIN_KEY"))
	syncOrDie(t, tr, out, t0.Add(25*time.Hour))
	inst := byTitle(t, tr, "anthropic:personal: has no credentials")
	if org.Status != Done || inst.Status != Open {
		t.Errorf("org item %s, instance item %s", org.Status, inst.Status)
	}
	// The instance item's key is reported again with a new detail: the old detail's ref is gone,
	// even though the run inspected nothing.
	reported := 0
	for _, r := range inst.Findings {
		if !r.Gone {
			reported++
		}
	}
	if len(inst.Findings) != 2 || reported != 1 {
		t.Errorf("refs %+v", inst.Findings)
	}
}

// Data dumps used to be one item per file. Those items move into their repository's item, closed
// as merged into it, except one the owner ignored on its own; and a pending decision about purging
// dumps blocks the repository's item, whose next step says so until it is answered.
func TestDumpItemsRegroupPerRepositoryAndWaitOnTheirDecision(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	a, b, c := dumpFinding("~/src/api", "a.sql", finding.SevHigh, 1<<20, t0), dumpFinding("~/src/api", "b.sql", finding.SevHigh, 2<<20, t0),
		dumpFinding("~/src/api", "c.sql", finding.SevMedium, 3<<20, t0)
	writeRun(t, out, t0, "local-secrets.jsonl", a, b, c, okStatus(SecretsConnector, "local"))
	tr := New(t0)
	// Per-file items as an older sync made them.
	old := map[string]*Item{}
	for _, f := range []finding.Finding{a, b, c} {
		it := tr.newItem(KindFix, pinnedKey(f.ID), "data-dumps", f.Title, t0)
		it.Findings = []FindingRef{refOf(f)}
		old[f.ID] = it
	}
	if err := old[c.ID].Ignore(t0, "a fixture"); err != nil {
		t.Fatal(err)
	}
	d := tr.AddDecision("decide:purge-data-dumps", "Purge the data dumps from git history?", []string{"yes", "no"}, t0)
	rep := syncOrDie(t, tr, out, t0.Add(time.Hour))
	repo := byTitle(t, tr, "2 database dumps in the git history of ~/src/api (3.0 MB)")
	for _, f := range []finding.Finding{a, b} {
		if it := old[f.ID]; it.Status != Merged || it.MergedInto != repo.ID || len(it.Findings) != 0 {
			t.Errorf("%s: %s into %q, %d refs", it.ID, it.Status, it.MergedInto, len(it.Findings))
		}
	}
	if it := old[c.ID]; it.Status != Ignored || len(it.Findings) != 1 {
		t.Errorf("the dump ignored on its own moved: %s, %d refs", it.Status, len(it.Findings))
	}
	if rep.Merged != 2 {
		t.Errorf("merged %d", rep.Merged)
	}
	if !strings.HasPrefix(repo.Next.Action, "Blocked by decision "+d.ID+" (Purge the data dumps from git history?): answer it first. ") {
		t.Errorf("next step: %s", repo.Next.Action)
	}
	if got := tr.Unblocks(d, t0.Add(time.Hour)); len(got) != 1 || got[0] != repo {
		t.Errorf("unblocks %v", got)
	}
	// Answered: the note goes away at the next sync, and is never doubled meanwhile.
	syncOrDie(t, tr, out, t0.Add(2*time.Hour))
	if strings.Count(repo.Next.Action, "Blocked by decision") != 1 {
		t.Errorf("note doubled: %s", repo.Next.Action)
	}
	if err := d.Decide(t0.Add(3*time.Hour), "yes"); err != nil {
		t.Fatal(err)
	}
	syncOrDie(t, tr, out, t0.Add(4*time.Hour))
	if strings.Contains(repo.Next.Action, "Blocked by decision") || tr.BlockedBy(repo, t0.Add(4*time.Hour)) != nil {
		t.Errorf("still blocked after the answer: %s", repo.Next.Action)
	}
}
