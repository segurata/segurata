package tracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Tests never read the developer's git email.
func init() { ownerEmail = func() string { return "" } }

const (
	ownAWS     = "111122223333"
	foreignAWS = "999988887777"
	legacy     = "~/segurata-test-nowhere/legacyco"
)

// attributionFixture: three AWS keys committed under legacy, one naming the owner's account (seen
// by the aws connector), one naming another account, one naming none (an old-format key id).
func attributionFixture(t *testing.T) (*Tracker, string) {
	t.Helper()
	out := t.TempDir()
	secret := func(fp, file string, c attribution.Claims) finding.Finding {
		path := legacy + "/" + file
		f := fnd(SecretsConnector, "", "local", "secret", "gitleaks:"+path+"#"+fp, "AWS key", finding.SevCritical, "AWS key in "+path, t0)
		raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: fp, Type: "aws-access-key-id", Redacted: "AKIA…" + fp[:4] + "(20)", Path: path,
			Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "b", Claims: c})
		_ = json.Unmarshal(raw, &f.Evidence)
		return f
	}
	writeRun(t, out, t0, "local-secrets.jsonl",
		secret("1111aaaa1111aaaa", "a/.env", attribution.Claims{AWSAccount: ownAWS, AuthorEmail: "me@x.com"}),
		secret("2222bbbb2222bbbb", "b/x.py", attribution.Claims{AWSAccount: foreignAWS}),
		secret("3333cccc3333cccc", "c/y.py", attribution.Claims{}),
		okStatus(SecretsConnector, "local"))
	writeRun(t, out, t0, "aws.jsonl", finding.Status{Type: "status", Connector: "aws", Account: ownAWS, State: finding.StateNoScope, Detail: "limited"})
	tr := New(t0)
	if _, err := tr.Sync(SyncOptions{OutDir: out, Owned: attribution.Owned{Emails: []string{"me@x.com"}}}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return tr, out
}

func mustRotate(t *testing.T, tr *Tracker, id string) *Item {
	t.Helper()
	it, err := tr.FindRotate(id)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

func TestSyncAttributesSecrets(t *testing.T) {
	tr, _ := attributionFixture(t)
	if tr.Owned == nil || !slices.Equal(tr.Owned.AWSAccounts, []string{ownAWS}) {
		t.Fatalf("discovered %+v", tr.Owned)
	}
	for _, c := range []struct {
		id     string
		owner  attribution.Owner
		reason string
	}{
		{"1111", attribution.Mine, "AWS account " + ownAWS + " is yours"},
		{"2222", attribution.NotMine, "AWS account " + foreignAWS + " is none of your 1 known"},
		{"3333", attribution.Unknown, "names no account"},
	} {
		a := mustRotate(t, tr, c.id).Secret.Attribution
		if a == nil || a.Owner != c.owner || !strings.Contains(strings.Join(a.Reasons, "; "), c.reason) {
			t.Errorf("%s: %+v, want %s with %q", c.id, a, c.owner, c.reason)
		}
	}
	if r := mustRotate(t, tr, "1111").Secret.Attribution.Reasons; !slices.Contains(r, "hint: committed by you (me@x.com)") {
		t.Errorf("authorship hint missing: %q", r)
	}
	counts := tr.OwnerCounts(func(*Item) bool { return true })
	if counts[attribution.Mine] != 1 || counts[attribution.NotMine] != 1 || counts[attribution.Unknown] != 1 {
		t.Errorf("counts %v", counts)
	}
}

// "Rotate mine, ignore the rest": a rule narrowed to not-mine closes only the not-mine key, says
// so beforehand, keeps closing new not-mine keys, and opens an item again when its attribution
// changes to mine.
func TestRuleNarrowedToNotMine(t *testing.T) {
	tr, out := attributionFixture(t)
	d := tr.AddDecision("manual:legacyco", "Is legacyco dead?", []string{"yes", "no"}, t0)
	now := t0.Add(2 * time.Hour)
	preview, err := tr.PreviewDecision(d, now, "rotate mine, ignore the rest", []string{"path:" + legacy}, nil, []attribution.Owner{attribution.NotMine})
	want := "closes 1 open item (P0 1) attributed not-mine, keeps 2 open (mine 1, unknown 1) by ignore@not-mine path:" + legacy
	if err != nil || len(preview) != 1 || preview[0] != want {
		t.Fatalf("preview %q %v, want %q", preview, err, want)
	}
	if d.Status != Open || len(tr.Rules) != 0 {
		t.Fatal("a preview changed the tracker")
	}
	rules, closed, err := tr.DecideWithEffects(d, now, "rotate mine, ignore the rest", []string{"path:" + legacy}, nil, []attribution.Owner{attribution.NotMine})
	if err != nil || len(rules) != 1 || closed != 1 {
		t.Fatalf("%+v %d %v", rules, closed, err)
	}
	theirs := mustRotate(t, tr, "2222")
	if theirs.Status != Ignored || !strings.Contains(theirs.History[len(theirs.History)-1].Detail, "by decision "+d.ID+": Is legacyco dead? rotate mine, ignore the rest; attributed not-mine: AWS account "+foreignAWS) {
		t.Errorf("not-mine key: %s %+v", theirs.Status, theirs.History)
	}
	for _, id := range []string{"1111", "3333"} {
		if it := mustRotate(t, tr, id); it.Status != Open {
			t.Errorf("%s closed: %s", id, it.Status)
		}
	}

	// The account turns out to be the owner's (config owned): the next sync opens it again, and the
	// rule leaves it open from then on.
	later := t0.Add(3 * time.Hour)
	if _, err := tr.Sync(SyncOptions{OutDir: out, Owned: attribution.Owned{AWSAccounts: []string{foreignAWS}}}, later); err != nil {
		t.Fatal(err)
	}
	if theirs.Status != Open || theirs.Owner() != attribution.Mine || theirs.History[len(theirs.History)-1].Action != actAutoReopen {
		t.Errorf("reattributed key: %s %s %+v", theirs.Status, theirs.Owner(), theirs.History[len(theirs.History)-1])
	}
	if _, err := tr.Sync(SyncOptions{OutDir: out, Owned: attribution.Owned{AWSAccounts: []string{foreignAWS}}}, later.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if theirs.Status != Open {
		t.Errorf("closed again: %s", theirs.Status)
	}
	// Ignored by hand, it stays ignored whatever the attribution says.
	if err := theirs.Ignore(later, "a fixture after all"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Sync(SyncOptions{OutDir: out}, later.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if theirs.Status != Ignored {
		t.Errorf("an owner's ignore was undone: %s", theirs.Status)
	}
}

func TestNarrowedRulesNeverCloseItemsWithoutAttribution(t *testing.T) {
	tr, _ := rulesFixture(t)
	r := Rule{Effect: EffectIgnore, Scope: "path:~/src/old", Owners: []attribution.Owner{attribution.NotMine}}
	for _, it := range tr.Items {
		if it.Kind != KindRotate && r.Matches(it) {
			t.Errorf("%s (%s) matched a rule narrowed to owners", it.ID, it.Kind)
		}
	}
}

func TestParseEffectWithOwners(t *testing.T) {
	label, eff, err := ParseOption("yes=ignore@not-mine,unknown:path:~/src/legacyco")
	if err != nil || label != "yes" || eff.Scope != "path:~/src/legacyco" || !slices.Equal(eff.Owners, []attribution.Owner{attribution.NotMine, attribution.Unknown}) {
		t.Errorf("%q %+v %v", label, eff, err)
	}
	if r := (Rule{Effect: eff.Effect, Scope: eff.Scope, Owners: eff.Owners}); r.Spec() != "ignore@not-mine,unknown path:~/src/legacyco" {
		t.Errorf("spec %q", r.Spec())
	}
	for _, bad := range []string{"yes=ignore@:path:~/x", "yes=ignore@theirs:path:~/x", "yes=delete@mine:path:~/x"} {
		if _, _, err := ParseOption(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	tr := New(t0)
	tr.Rules = []Rule{{Effect: EffectIgnore, Scope: "path:~/x", Owners: []attribution.Owner{"theirs"}, Reason: "r", At: t0}}
	if err := tr.validate(); err == nil {
		t.Error("a rule with an unknown owner validated")
	}
}

func TestConfiguredSyncReadsOwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"owned": {"aws_accounts": ["123456789012"], "emails": ["old@x.com"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(f func() string) { ownerEmail = f }(ownerEmail)
	ownerEmail = func() string { return "git@x.com" }
	opt, err := ConfiguredSync(path, SyncOptions{OutDir: "out"})
	if err != nil || opt.OutDir != "out" || !slices.Equal(opt.Owned.AWSAccounts, []string{"123456789012"}) || !slices.Equal(opt.Owned.Emails, []string{"git@x.com", "old@x.com"}) {
		t.Errorf("%+v %v", opt, err)
	}
}

func TestTrackDecideOwnerFromTheCLI(t *testing.T) {
	x := newCLIFixture(t)
	if _, e, code := x.run(t, "sync", "--out", x.out); code != 0 {
		t.Fatal(e)
	}
	if _, e, code := x.run(t, "add", "--kind", "decide", "--question", "Is the shop dead?"); code != 0 {
		t.Fatal(e)
	}
	d := x.item(t, "Is the shop dead?")
	o, e, code := x.run(t, "decide", d.ID, "--answer", "yes", "--ignore-scope", "path:~/.claude", "--owner", "not-mine", "--dry-run")
	if code != 0 || !strings.Contains(o, "Answering closes 0 open items attributed not-mine, keeps 2 open (unknown 1, not secrets 1) by ignore@not-mine path:~/.claude") ||
		!strings.Contains(o, "Nothing written (--dry-run).") {
		t.Fatalf("dry run: %q %q", o, e)
	}
	if x.item(t, "Is the shop dead?").Status != Open {
		t.Fatal("a dry run answered the decision")
	}
	if _, _, code := x.run(t, "decide", d.ID, "--answer", "yes", "--owner", "theirs"); code != 1 {
		t.Error("a bad owner was accepted")
	}
	o, e, code = x.run(t, "decide", d.ID, "--answer", "yes", "--ignore-scope", "path:~/.claude", "--owner", "not-mine")
	if code != 0 || !strings.Contains(o, "Rule: ignore@not-mine path:~/.claude, at every sync.") || !strings.Contains(o, "0 items closed now") {
		t.Fatalf("decide: %q %q", o, e)
	}
}

// Attribution wins over the repository: an AWS key decoding to one of the owner's accounts, found
// only in a third-party repository or in history a fork inherited, is the owner's secret leaked
// there and keeps its full impact (P0 for pushed history). The same copies naming someone else's
// account, or no account, stay noise. A noise summary never reclassifies the owner's key either.
func TestAttributionMineRestoresFullImpactInThirdPartyRepositories(t *testing.T) {
	out := t.TempDir()
	secret := func(fp, origin string, c attribution.Claims) finding.Finding {
		path := "~/src/upstream/lib/s3.py"
		f := fnd(SecretsConnector, "", "local", "secret", "gitleaks:"+path+"#"+fp, "AWS key", finding.SevInfo, "AWS key in "+path, t0)
		raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: fp, Type: "aws-access-key-id", Redacted: "AKIA…(20)", Path: path, Repo: "~/src/upstream",
			Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "b", Origin: origin, Claims: c})
		_ = json.Unmarshal(raw, &f.Evidence)
		return f
	}
	writeRun(t, out, t0, "local-secrets.jsonl",
		secret("1111aaaa1111aaaa", secretrisk.OriginThirdParty, attribution.Claims{AWSAccount: ownAWS}),
		secret("4444dddd4444dddd", secretrisk.OriginForkUpstream, attribution.Claims{AWSAccount: ownAWS}),
		secret("2222bbbb2222bbbb", secretrisk.OriginThirdParty, attribution.Claims{AWSAccount: foreignAWS}),
		secret("3333cccc3333cccc", secretrisk.OriginThirdParty, attribution.Claims{}),
		okStatus(SecretsConnector, "local"))
	writeRun(t, out, t0, "aws.jsonl", finding.Status{Type: "status", Connector: "aws", Account: ownAWS, State: finding.StateOK})
	tr := New(t0)
	if _, err := tr.Sync(SyncOptions{OutDir: out}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{"1111", "4444"} {
		it := mustRotate(t, tr, fp)
		if it.Priority != secretrisk.P0 || it.WorstLabel() != "git+remote" || it.Owner() != attribution.Mine {
			t.Errorf("%s: %s %s %s, want P0 git+remote mine", fp, it.Priority, it.WorstLabel(), it.Owner())
		}
		if r := strings.Join(it.Secret.Reasons, "; "); !strings.Contains(r, "yours by attribution (AWS account "+ownAWS+" is yours)") {
			t.Errorf("%s: reasons %q", fp, r)
		}
	}
	for _, fp := range []string{"2222", "3333"} {
		if _, err := tr.FindRotate(fp); err == nil {
			t.Errorf("%s: a third-party copy not attributed mine got an item", fp)
		}
	}
	if rep := tr.SyncNoise(map[string]string{"1111aaaa1111aaaa": "aws-access-key-id"}, t0.Add(2*time.Hour)); rep.Reclassified != 0 || mustRotate(t, tr, "1111").Status != Open {
		t.Error("a noise summary reclassified a key attributed mine")
	}
}
