package tracker

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// scoredItem is an open item with n findings of one resource type and id, which put blast at
// stake.
func scoredItem(tr *Tracker, kind Kind, key, theme, title string, sev finding.Severity, typ, res string, blast finding.Blast, n int) *Item {
	it := tr.newItem(kind, key, theme, title, t0)
	it.Severity, it.Priority = sev, priorityOf(sev)
	for i := range n {
		it.Findings = append(it.Findings, FindingRef{ID: key + string(rune('a'+i)), Type: typ, Resource: res, Severity: sev, Blast: blast})
	}
	it.Next = &Next{Who: You, Action: "Fix " + title + ".", Command: "segurata track show " + it.ID}
	return it
}

// The briefing's own examples (2026-11-24): 2FA not required in five orgs, no Time Machine backup,
// Google apps with high-risk access and a Google account that is the login for financial services
// outrank P1 items of smaller blast radius (an Azure budget, a ChatGPT extension, a GitHub OAuth
// app, old X apps), which ordering by connector put first.
func TestDoNextRanksByBlastRadius(t *testing.T) {
	tr := New(t0)
	low := []*Item{
		scoredItem(tr, KindFix, "group:azure|azure_budget|account:sub|family:x", "cloud", "Subscription has no budget", finding.SevHigh, "azure_budget", "s/none", finding.BlastMoney, 1),
		scoredItem(tr, KindFix, "group:gcp|budget_enforcement|account:me", "cloud", "Budgets on billing account B only notify", finding.SevHigh, "budget_enforcement", "B", finding.BlastMoney, 1),
		scoredItem(tr, KindReview, "finding:chatgpt", "browser-extensions", "Brave extension ChatGPT: remove", finding.SevHigh, "browser_extension", "hehg", "", 1),
		scoredItem(tr, KindReview, "group:connected-apps|github_oauth_app|account:github:me|family:can read your profile", "connected-apps", "5 GitHub OAuth apps can see your profile", finding.SevHigh, "github_oauth_app", "", "", 5),
		scoredItem(tr, KindReview, "group:connected-apps|x_app|account:x:@me|family:can post", "connected-apps", "27 X apps can post and delete posts as you", finding.SevHigh, "x_app", "", finding.BlastPosts, 27),
	}
	high := []*Item{
		scoredItem(tr, KindFix, "group:github|github_org_setting|check:org-2fa-not-required", "github-orgs", "Two-factor authentication not required in 5 GitHub orgs", finding.SevHigh, "github_org_setting", "org-2fa-not-required", finding.BlastOrgAccess, 5),
		scoredItem(tr, KindFix, "finding:backup", "mac", "No Time Machine backup is configured", finding.SevHigh, "macos_setting", "backup-none", finding.BlastDevice, 1),
		scoredItem(tr, KindReview, "group:google-personal|oauth_grant|account:me@gmail.com|severity:high", "google", "Review 5 apps with high-risk access to me@gmail.com", finding.SevHigh, "oauth_grant", "", finding.BlastMailAndFiles, 5),
		scoredItem(tr, KindFix, "group:google-personal|sso|account:me@gmail.com", "google", "Google account me@gmail.com is the login for 7 financial and cloud services", finding.SevHigh, "google_login_dependency", "me@gmail.com", finding.BlastLogin, 1),
	}
	now := t0.Add(time.Hour)
	for _, h := range high {
		for _, l := range low {
			if hs, ls := tr.Score(h, now), tr.Score(l, now); hs.Total <= ls.Total {
				t.Errorf("%q (%s) should outrank %q (%s)", h.Title, hs.Explain(), l.Title, ls.Explain())
			}
		}
	}
	if s := tr.Score(high[0], now).Explain(); s != "27.0 = impact 6 (P1) × blast 3 (one stolen password opens every repository of those orgs) ÷ effort 1 (one change) × quick win 1.5 (one fix closes 5 findings)" {
		t.Errorf("2FA explained as %q", s)
	}

	var b bytes.Buffer
	if err := doc.Render(&b, tr.Status("tracker.json", now, View{Explain: true}), doc.Text); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	section := out[strings.Index(out, "Do next"):strings.Index(out, "Pending decisions")]
	pos := func(title string) int { return strings.Index(section, title) }
	for _, h := range high {
		for _, l := range low {
			if pos(h.Title) < 0 || pos(l.Title) < 0 || pos(h.Title) > pos(l.Title) {
				t.Errorf("Do next lists %q after %q:\n%s", h.Title, l.Title, section)
			}
		}
	}
	for _, want := range []string{"Score: 27.0 = impact 6 (P1)", "quick win: one fix closes 5 findings"} {
		if !strings.Contains(section, want) {
			t.Errorf("Do next lacks %q:\n%s", want, section)
		}
	}
}

// Ranking reads what a connector declares, never the wording of a title: a title that reads like a
// high-blast one changes nothing, and a declared blast counts whatever the title says. Data dumps
// the connector is not sure of are discounted.
func TestBlastAndConfidenceComeFromTheFindingsNotTheTitle(t *testing.T) {
	tr := New(t0)
	now := t0.Add(time.Hour)
	worded := scoredItem(tr, KindFix, "finding:w", "google", "Account x is the login for 7 services; no Time Machine backup; can delete your repositories", finding.SevHigh, "x", "", "", 1)
	declared := scoredItem(tr, KindReview, "finding:d", "connected-apps", "gh can do things", finding.SevHigh, "github_oauth_app", "", finding.BlastAllRepos, 1)
	if f := tr.Score(worded, now).factor("blast"); f.Value != 1 {
		t.Errorf("a title moved the blast: %+v", f)
	}
	if f := tr.Score(declared, now).factor("blast"); f.Value != 1.5 || f.Why != "write access to every repository you own" {
		t.Errorf("declared blast: %+v", f)
	}
	// The worst blast of an item's findings counts.
	mixed := scoredItem(tr, KindReview, "finding:m", "connected-apps", "apps", finding.SevHigh, "x_app", "", finding.BlastPosts, 2)
	mixed.Findings[1].Blast = finding.BlastAllRepos
	if f := tr.Score(mixed, now).factor("blast"); f.Value != 1.5 {
		t.Errorf("mixed blast: %+v", f)
	}

	possible := scoredItem(tr, KindFix, "group:local-secrets|data_dump|repo:~/src/p", "data-dumps", "2 database dumps in the git history of ~/src/p", finding.SevMedium, "data_dump", "", finding.BlastPersonalData, 2)
	for i := range possible.Findings {
		possible.Findings[i].Unconfirmed = true
	}
	if f := tr.Score(possible, now).factor("confidence"); f.Value != 0.7 || f.Why != "possibly not a real problem" {
		t.Errorf("unconfirmed dumps: %+v", f)
	}
	possible.Findings[0].Unconfirmed = false
	if f := tr.Score(possible, now).factor("confidence"); f.Value != 1 {
		t.Errorf("one confirmed dump: %+v", f)
	}
	if f := tr.Score(scoredItem(tr, KindFix, "finding:p", "x", "Possible thing", finding.SevHigh, "x", "", "", 1), now).factor("confidence"); f.Value != 1 {
		t.Errorf("a title moved the confidence: %+v", f)
	}

	// A sync keeps what the connector declared on the item's refs.
	out := filepath.Join(t.TempDir(), "out")
	f := fnd("macos", "", "Mac", "macos_setting", "backup-none", "backup-none", finding.SevHigh, "Backups", t0)
	f.Blast, f.Unconfirmed = finding.BlastDevice, true
	writeRun(t, out, t0, "macos.jsonl", f, okStatus("macos", "Mac"))
	synced := New(t0)
	syncOrDie(t, synced, out, now)
	if r := byTitle(t, synced, "Backups").Findings[0]; r.Blast != finding.BlastDevice || !r.Unconfirmed {
		t.Errorf("ref %+v", r)
	}
}

// A decision that blocks items is a Do next entry worth part of them, and shows what it unblocks.
func TestDecisionThatUnblocksItemsIsADoNextEntry(t *testing.T) {
	tr := New(t0)
	for _, r := range []string{"a", "b", "c"} {
		scoredItem(tr, KindFix, "group:local-secrets|data_dump|repo:~/src/"+r, "data-dumps", "2 database dumps in the git history of ~/src/"+r, finding.SevHigh, "data_dump", "", finding.BlastPersonalData, 2)
	}
	d := tr.AddDecision("decide:purge-data-dumps", "Purge the data dumps from git history?", []string{"yes", "no"}, t0)
	now := t0.Add(time.Hour)
	s := tr.Score(d, now)
	if f := s.factor("quick win"); f.Why != "answering unblocks 3 items" || s.Total <= tr.Score(tr.Items[1], now).Total {
		t.Errorf("decision score %s", s.Explain())
	}
	dump := tr.Score(tr.Items[1], now)
	if f := dump.factor("effort"); f.Value != 6 || !strings.Contains(f.Why, "waits on decision "+d.ID) {
		t.Errorf("blocked dump effort %+v", f)
	}
	var b bytes.Buffer
	_ = doc.Render(&b, tr.Status("tracker.json", now, View{}), doc.Text)
	if out := b.String(); !strings.Contains(out, "Decide: Purge the data dumps from git history?") || !strings.Contains(out, "Unblocks: 3 items (P1 3)") {
		t.Errorf("status:\n%s", out)
	}
}

// The secrets entry names the next secret and why: a live key leaked out of the machine first.
func TestSecretsEntryNamesTheNextSecret(t *testing.T) {
	tr := New(t0)
	leaked := ev("1111111111111111", "aws-access-key-id", "~/src/r/k.py", "gitleaks", "repo", "", true, true)
	leaked.Redacted, leaked.Repo = "AKIA…(20)", "~/src/r"
	other := ev("2222222222222222", "github", "~/src/s/t.py", "gitleaks", "repo", "", true, true)
	other.Redacted, other.Repo = "ghp_…abcd(40)", "~/src/s"
	tr.SyncSecrets([]Sighting{sight(leaked), sight(other)}, t0, false)
	key := mustRotate(t, tr, "11111111")
	key.Findings = []FindingRef{{ID: "aws1", Connector: "aws", Title: "Long-lived AWS access key; aws sts says it works for account 1"}}
	key.derive()
	var b bytes.Buffer
	_ = doc.Render(&b, tr.Status("tracker.json", t0.Add(time.Hour), View{}), doc.Text)
	out := b.String()
	for _, want := range []string{"Rotate 2 P0 secrets", "Next secret: AWS access key id (signs nothing without its secret key) AKIA…(20) in r:k.py (" + key.ID + ")",
		"Why: live key, leaked in r:k.py; live: aws: Long-lived AWS access key", "Then: segurata rotations next --priority P0"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
}

// rotations next: live and leaked first, then a secret a working file holds, one in the owner's
// repository, the most recent commit, the one found in more places.
func TestRotationOrder(t *testing.T) {
	tr := &Tracker{NextID: 1}
	mk := func(fp string, extra ...secretrisk.Evidence) {
		e := ev(fp, "github", "~/src/"+fp[:1]+"/k.py", "gitleaks", "repo", "", true, true)
		e.Redacted, e.Date = "ghp_…"+fp[:4]+"(40)", "2020-01-01"
		tr.SyncSecrets(append([]Sighting{sight(e)}, func() []Sighting {
			var out []Sighting
			for _, x := range extra {
				x.Fingerprint, x.Type = fp, "github"
				out = append(out, sight(x))
			}
			return out
		}()...), t0, false)
	}
	recent := ev("", "", "~/src/r/x.py", "gitleaks", "repo", "", true, true)
	recent.Date = "2025-01-01"
	owned := ev("", "", "~/src/o/x.py", "gitleaks", "repo", "", true, true)
	owned.Origin = secretrisk.OriginOwned
	mk("1111111111111111")                                                                       // plain
	mk("2222222222222222", ev("", "", "~/.config/x.env", "scan", "config", "600", false, false)) // used_in
	mk("3333333333333333", owned)                                                                // owned repository
	mk("4444444444444444", recent)                                                               // recent commit
	mk("5555555555555555", ev("", "", "~/.zsh_history", "scan", "history", "600", false, false)) // more places
	mk("6666666666666666")                                                                       // live and leaked
	live := mustRotate(t, tr, "66666666")
	live.Findings = []FindingRef{{ID: "x", Connector: "github", Title: "token in use"}}
	live.derive()
	items := slices.Clone(tr.Items)
	Sort(items)
	var got []string
	for _, it := range items {
		got = append(got, it.Secret.ID[:1])
	}
	if strings.Join(got, ",") != "6,2,3,4,5,1" {
		t.Errorf("order %v", got)
	}
}
