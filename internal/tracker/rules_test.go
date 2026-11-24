package tracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

func TestParseOptionAndEffect(t *testing.T) {
	label, eff, err := ParseOption("yes=ignore:path:~/src/legacyco")
	if err != nil || label != "yes" || eff == nil || eff.Effect != EffectIgnore || eff.Scope != "path:~/src/legacyco" {
		t.Errorf("%q %+v %v", label, eff, err)
	}
	if label, eff, err := ParseOption("no"); err != nil || label != "no" || eff != nil {
		t.Errorf("%q %+v %v", label, eff, err)
	}
	for _, bad := range []string{"yes=delete:path:~/x", "yes=ignore:host:x", "yes=ignore:path:", "=ignore:path:~/x", "yes=accept:account:["} {
		if _, _, err := ParseOption(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// rulesFixture: three secrets (two only under ~/src/old, one also in a live .env), a data dump in
// ~/src/old, a GitHub repo finding and a GCP API key finding.
func rulesFixture(t *testing.T) (*Tracker, string) {
	t.Helper()
	out := t.TempDir()
	secret := func(fp, path, kind string) finding.Finding {
		f := fnd(SecretsConnector, "", "local", "secret", "scan:"+path+"#"+fp, "AWS key", finding.SevCritical, "AWS key in "+path, t0)
		raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: fp, Type: "aws", Redacted: "AKIA…" + fp[:4] + "(20)", Path: path, Source: "gitleaks",
			Kind: kind, Tracked: true, Remote: true, Bucket: "b"})
		_ = json.Unmarshal(raw, &f.Evidence)
		return f
	}
	dump := dumpFinding("~/src/old/api", "crm.sql", finding.SevHigh, 400<<10, t0)
	repo := fnd("github", "", "github:acme", "github_repo", "1", "acme/legacy", finding.SevMedium, "acme/legacy: secret scanning is off", t0)
	key := fnd("gcp", "", "a@x.com", "api_key", "k1", "Old key", finding.SevHigh, "API key \"Old key\" in old-proj has no restrictions", t0)
	key.Evidence = map[string]any{"project": "old-proj"}
	writeRun(t, out, t0, "local-secrets.jsonl", secret("1111aaaa1111aaaa", "~/src/old/a/.env", "repo"), secret("2222bbbb2222bbbb", "~/src/old/b/x.py", "repo"),
		secret("3333cccc3333cccc", "~/src/old/c/y.py", "repo"), secret("3333cccc3333cccc", "~/src/live/.env", "repo"), dump, okStatus(SecretsConnector, "local"))
	writeRun(t, out, t0, "github.jsonl", repo, okStatus("github", "github:acme"))
	writeRun(t, out, t0, "gcp.jsonl", key, okStatus("gcp", "a@x.com"))
	tr := New(t0)
	syncOrDie(t, tr, out, t0.Add(time.Hour))
	return tr, out
}

func TestDecisionEffectsCloseItemsInScopeNowAndLater(t *testing.T) {
	tr, out := rulesFixture(t)
	d := tr.AddDecision("manual:old", "Are the old repos dead?", []string{"yes", "no"}, t0)
	d.Decision.Effects = []OptionEffect{{Option: "yes", Effect: EffectIgnore, Scope: "path:~/src/old"}}
	now := t0.Add(2 * time.Hour)
	lev := tr.Leverage(d, now)
	if len(lev) != 1 || !strings.Contains(lev[0], `answering "yes" closes 3 open items (P1 3) by ignore path:~/src/old`) {
		t.Fatalf("leverage %q", lev)
	}
	var b strings.Builder
	_ = doc.Render(&b, tr.Status("tracker.json", now, View{}), doc.Text)
	if !strings.Contains(b.String(), `answering "yes" closes 3 open items`) {
		t.Errorf("status lacks the leverage:\n%s", b.String())
	}
	rules, closed, err := tr.DecideWithEffects(d, now, "yes: archive them", nil, []string{"gcp-project:old-proj"}, nil)
	if err != nil || len(rules) != 2 || closed != 4 {
		t.Fatalf("decide: %+v %d %v", rules, closed, err)
	}
	a, _ := tr.FindRotate("1111aaaa")
	if a.Status != Ignored || !strings.HasPrefix(a.lastDetail(actIgnore), "by decision "+d.ID+": Are the old repos dead? yes: archive them") {
		t.Errorf("secret under ~/src/old: %s %q", a.Status, a.lastDetail(actIgnore))
	}
	if c, _ := tr.FindRotate("3333cccc"); c.Status != Open {
		t.Error("a secret also in a live file was closed")
	}
	if byTitle(t, tr, "1 database dump in the git history of ~/src/old/api").Status != Ignored {
		t.Error("the dump under ~/src/old stayed open")
	}
	if it := byTitle(t, tr, "Restrict 1 API key in GCP project old-proj"); it.Status != Accepted || it.Accepted == nil {
		t.Errorf("gcp-project accept: %s", it.Status)
	}
	if byTitle(t, tr, "Repository security settings off in 1 repository of github:acme").Status != Open {
		t.Error("a repo outside every scope was closed")
	}

	// A new secret found later under ~/src/old never opens an item; one reopened by hand stays open.
	b2, _ := tr.FindRotate("2222bbbb")
	b2.Reopen(now.Add(time.Minute), "still used, actually")
	f := fnd(SecretsConnector, "", "local", "secret", "scan:x#4444", "AWS key", finding.SevCritical, "AWS key", t0)
	raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: "4444dddd4444dddd", Type: "aws", Redacted: "AKIA…4444(20)", Path: "~/src/old/d/z.py",
		Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "b"})
	_ = json.Unmarshal(raw, &f.Evidence)
	writeRun(t, out, t0.Add(24*time.Hour), "local-secrets.jsonl", f, okStatus(SecretsConnector, "local"))
	rep := syncOrDie(t, tr, out, t0.Add(25*time.Hour))
	if n, _ := tr.FindRotate("4444dddd"); n.Status != Ignored || rep.Ruled != 1 {
		t.Errorf("new secret in scope: %s, ruled %d", n.Status, rep.Ruled)
	}
	if b2.Status != Open {
		t.Errorf("reopened by hand: %s", b2.Status)
	}
	if n := tr.DropRules(d.ID); n != 2 || len(tr.Rules) != 0 {
		t.Errorf("dropped %d, left %v", n, tr.Rules)
	}
}

// Answering a decision again replaces the rules of the previous answer instead of adding to them:
// "yes" then "no" must not leave "yes"'s ignore rule closing items at every sync.
func TestAnsweringADecisionAgainReplacesThePreviousRules(t *testing.T) {
	tr, out := rulesFixture(t)
	d := tr.AddDecision("manual:old", "Are the old repos dead?", []string{"yes", "no"}, t0)
	d.Decision.Effects = []OptionEffect{{Option: "yes", Effect: EffectIgnore, Scope: "path:~/src/old"}}
	now := t0.Add(2 * time.Hour)
	if _, _, err := tr.DecideWithEffects(d, now, "yes", nil, []string{"gcp-project:old-proj"}, nil); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	rules, _, err := tr.DecideWithEffects(d, later, "no", nil, nil, nil)
	if err != nil || len(rules) != 0 {
		t.Fatalf("second answer: %+v %v", rules, err)
	}
	if len(tr.Rules) != 0 {
		t.Fatalf("the first answer's rules are still applied: %+v", tr.Rules)
	}
	if d.Decision.Answer != "no" || d.Status != Done {
		t.Errorf("decision %q %s", d.Decision.Answer, d.Status)
	}
	if got := d.lastDetail(actReanswer); !strings.Contains(got, `replaces the answer "yes"`) || !strings.Contains(got, "2 rules") {
		t.Errorf("history %q", got)
	}

	// A secret found later under ~/src/old opens an item: no rule covers it any more.
	f := fnd(SecretsConnector, "", "local", "secret", "scan:x#4444", "AWS key", finding.SevCritical, "AWS key", t0)
	raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: "4444dddd4444dddd", Type: "aws", Redacted: "AKIA…4444(20)", Path: "~/src/old/d/z.py",
		Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "b"})
	_ = json.Unmarshal(raw, &f.Evidence)
	writeRun(t, out, t0.Add(24*time.Hour), "local-secrets.jsonl", f, okStatus(SecretsConnector, "local"))
	syncOrDie(t, tr, out, t0.Add(25*time.Hour))
	if n, _ := tr.FindRotate("4444dddd"); n.Status != Open {
		t.Errorf("new secret under ~/src/old: %s", n.Status)
	}
}

func TestRuleScopesOnFindings(t *testing.T) {
	tr, _ := rulesFixture(t)
	repo := byTitle(t, tr, "Repository security settings off in 1 repository of github:acme")
	key := byTitle(t, tr, "Restrict 1 API key in GCP project old-proj")
	for _, c := range []struct {
		scope string
		it    *Item
		want  bool
	}{
		{"repo:acme/legacy", repo, true},
		{"repo:ACME/Legacy", repo, true},
		{"repo:acme/other", repo, false},
		{"account:github:acme", repo, true},
		{"account:github:*", repo, true},
		{"account:a@x.com", repo, false},
		{"gcp-project:old-proj", key, true},
		{"gcp-project:old-proj", repo, false},
		{"path:~/src", key, false},
	} {
		if got := (Rule{Effect: EffectIgnore, Scope: c.scope}).Matches(c.it); got != c.want {
			t.Errorf("%s on %s: %v", c.scope, c.it.Title, got)
		}
	}
	for _, it := range tr.Items {
		if it.Kind == KindDecide && (Rule{Effect: EffectIgnore, Scope: "account:*"}).Matches(it) {
			t.Error("a rule matched a decision")
		}
	}
}

func TestTrackDecideWithEffectsFromTheCLI(t *testing.T) {
	x := newCLIFixture(t)
	if _, e, code := x.run(t, "sync", "--out", x.out); code != 0 {
		t.Fatal(e)
	}
	o, e, code := x.run(t, "add", "--kind", "decide", "--question", "Is the shop dead?", "--option", "yes=ignore:path:~/.claude", "--option", "no")
	if code != 0 {
		t.Fatalf("add: %q", e)
	}
	d := x.item(t, "Is the shop dead?")
	if strings.Join(d.Decision.Options, "|") != "yes|no" || len(d.Decision.Effects) != 1 {
		t.Fatalf("decision %+v (%s)", d.Decision, o)
	}
	if o, _, _ = x.run(t, "show", d.ID); !strings.Contains(o, `if:      answering "yes" closes 2 open items (P0 1, P2 1) by ignore path:~/.claude`) {
		t.Errorf("show:\n%s", o)
	}
	if _, _, code := x.run(t, "decide", d.ID, "--answer", "maybe", "--ignore-scope", "host:x"); code != 1 {
		t.Error("a bad scope was accepted")
	}
	if x.item(t, "Is the shop dead?").Status != Open {
		t.Error("a failed decide closed the decision")
	}
	o, e, code = x.run(t, "decide", d.ID, "--answer", "yes", "--accept-scope", "account:github:*")
	if code != 0 || !strings.Contains(o, "Rule: ignore path:~/.claude, at every sync.") || !strings.Contains(o, "Rule: accept account:github:*") ||
		!strings.Contains(o, "3 items closed now by this decision.") {
		t.Fatalf("decide: %q %q", o, e)
	}
	tr, _ := Load(x.path)
	if len(tr.Rules) != 2 || tr.Rules[0].Decision != d.ID {
		t.Fatalf("rules %+v", tr.Rules)
	}
	if o, _, _ = x.run(t, "show", d.ID); !strings.Contains(o, "rule:      ignore path:~/.claude at every sync") {
		t.Errorf("show answered:\n%s", o)
	}
	if o, _, _ = x.run(t, "reopen", d.ID); !strings.Contains(o, "2 rules of this decision removed") {
		t.Errorf("reopen: %q", o)
	}
	if tr, _ := Load(x.path); len(tr.Rules) != 0 {
		t.Error("rules kept after reopen")
	}
	if _, e, code := x.run(t, "decide", d.ID, "--answer", "yes"); code != 0 {
		t.Fatal(e)
	}
	if o, e, code = x.run(t, "decide", d.ID, "--answer", "no"); code != 0 || !strings.Contains(o, `This answer replaces the answer "yes"; 1 rule of it removed`) {
		t.Errorf("answering again: %q %q", o, e)
	}
	if tr, _ := Load(x.path); len(tr.Rules) != 0 {
		t.Error("the previous answer's rule kept")
	}
}

func TestLoadRejectsABadRule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tracker.json")
	tr := New(t0)
	tr.Rules = []Rule{{Effect: "delete", Scope: "path:~/x", Reason: "r", At: t0}}
	raw, _ := json.Marshal(tr)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "rule 1") {
		t.Errorf("%v", err)
	}
}

// An automatable fix of the finding itself makes segurata the item's next step; a hardening
// action riding on it (a chmod on a key graded for rotation) does not.
func TestOnlyTheFindingsOwnFixMakesSegurataTheNextStep(t *testing.T) {
	for name, c := range map[string]struct {
		rem finding.Remediation
		who Who
	}{
		"own fix":   {finding.Remediation{Summary: "Turn the firewall on.", Action: "macos.firewall.enable", Automatable: true}, Segurata},
		"hardening": {finding.Remediation{Summary: "Rotate it.", Action: "file.chmod600", Severity: finding.SevLow, Automatable: true}, You},
	} {
		p := &proposal{rule: &rule{}}
		p.add(finding.Finding{ID: "f1", Connector: "x", Account: "a", Severity: finding.SevHigh, Title: "t", Remediation: c.rem})
		p.finish("T-0001")
		if p.next.Who != c.who {
			t.Errorf("%s: next step by %v, want %v", name, p.next.Who, c.who)
		}
	}
}
