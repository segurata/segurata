package tracker

import (
	"encoding/json"
	"os"
	"os/exec"
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
	ownAWS     = "012345678901"
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
		f := fnd(secretrisk.ConnectorName, "", "local", "secret", "gitleaks:"+path+"#"+fp, "AWS key", finding.SevCritical, "AWS key in "+path, t0)
		raw, _ := json.Marshal(secretrisk.Evidence{Fingerprint: fp, Type: "aws-access-key-id", Redacted: "AKIA…" + fp[:4] + "(20)", Path: path,
			Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Bucket: "b", Claims: c})
		_ = json.Unmarshal(raw, &f.Evidence)
		return f
	}
	writeRun(t, out, t0, "local-secrets.jsonl",
		secret("1111aaaa1111aaaa", "a/.env", attribution.Claims{AWSAccount: ownAWS, AuthorEmail: "me@x.com"}),
		secret("2222bbbb2222bbbb", "b/x.py", attribution.Claims{AWSAccount: foreignAWS}),
		secret("3333cccc3333cccc", "c/y.py", attribution.Claims{}),
		okStatus(secretrisk.ConnectorName, "local"))
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
		{"3333", attribution.Unknown, "committed to a git repository with no GitHub remote"},
	} {
		a := mustRotate(t, tr, c.id).Secret.Attribution
		if a == nil || a.Owner != c.owner || !strings.Contains(strings.Join(a.Reasons, "; "), c.reason) {
			t.Errorf("%s: %+v, want %s with %q", c.id, a, c.owner, c.reason)
		}
	}
	if r := mustRotate(t, tr, "1111").Secret.Attribution.Reasons; !slices.Contains(r, "committed by you (me@x.com)") {
		t.Errorf("authorship missing: %q", r)
	}
	counts := tr.ownerCounts(func(*Item) bool { return true })
	if counts[attribution.Mine] != 1 || counts[attribution.NotMine] != 1 || counts[attribution.Unknown] != 1 {
		t.Errorf("counts %v", counts)
	}
}

// "Rotate mine, ignore the rest": a rule narrowed to not-mine closes only the not-mine key, says
// so beforehand, keeps closing new not-mine keys, and opens an item again when its attribution
// changes to mine.
func TestRuleNarrowedToNotMine(t *testing.T) {
	tr, out := attributionFixture(t)
	d := tr.addDecision("manual:legacyco", "Is legacyco dead?", []string{"yes", "no"}, t0)
	now := t0.Add(2 * time.Hour)
	preview, err := tr.previewDecision(d, now, "rotate mine, ignore the rest", []string{"path:" + legacy}, nil, []attribution.Owner{attribution.NotMine})
	want := "closes 1 open item (P2 1) attributed not-mine, keeps 2 open (mine 1, unknown 1) by ignore@not-mine path:" + legacy
	if err != nil || len(preview) != 1 || preview[0] != want {
		t.Fatalf("preview %q %v, want %q", preview, err, want)
	}
	if d.Status != Open || len(tr.Rules) != 0 {
		t.Fatal("a preview changed the tracker")
	}
	rules, closed, err := tr.decideWithEffects(d, now, "rotate mine, ignore the rest", []string{"path:" + legacy}, nil, []attribution.Owner{attribution.NotMine})
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
	if err := theirs.ignore(later, "a fixture after all"); err != nil {
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
	r := Rule{Effect: effectIgnore, Scope: "path:~/src/old", Owners: []attribution.Owner{attribution.NotMine}}
	for _, it := range tr.Items {
		if it.Kind != KindRotate && r.matches(it) {
			t.Errorf("%s (%s) matched a rule narrowed to owners", it.ID, it.Kind)
		}
	}
}

func TestParseEffectWithOwners(t *testing.T) {
	label, eff, err := parseOption("yes=ignore@not-mine,unknown:path:~/src/legacyco")
	if err != nil || label != "yes" || eff.Scope != "path:~/src/legacyco" || !slices.Equal(eff.Owners, []attribution.Owner{attribution.NotMine, attribution.Unknown}) {
		t.Errorf("%q %+v %v", label, eff, err)
	}
	if r := (Rule{Effect: eff.Effect, Scope: eff.Scope, Owners: eff.Owners}); r.spec() != "ignore@not-mine,unknown path:~/src/legacyco" {
		t.Errorf("spec %q", r.spec())
	}
	for _, bad := range []string{"yes=ignore@:path:~/x", "yes=ignore@theirs:path:~/x", "yes=delete@mine:path:~/x"} {
		if _, _, err := parseOption(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	tr := New(t0)
	tr.Rules = []Rule{{Effect: effectIgnore, Scope: "path:~/x", Owners: []attribution.Owner{"theirs"}, Reason: "r", At: t0}}
	if err := tr.validate(); err == nil {
		t.Error("a rule with an unknown owner validated")
	}
}

func TestConfiguredSyncReadsOwned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"owned": {"aws_accounts": ["123456789012"], "emails": ["old@x.com"], "github": ["me"]},
		"connectors": {"local-secrets": {"config": {"owned_owners": ["acme-labs"]}}, "local-secrets:work": {"config": {"owned_owners": ["work-org", "ME"]}},
		"github": {"config": {"owned_owners": ["not-read"]}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(f func() string) { ownerEmail = f }(ownerEmail)
	ownerEmail = func() string { return "git@x.com" }
	opt, err := ConfiguredSync(path, SyncOptions{OutDir: "out"})
	if err != nil || opt.OutDir != "out" || !slices.Equal(opt.Owned.AWSAccounts, []string{"123456789012"}) || !slices.Equal(opt.Owned.Emails, []string{"git@x.com", "old@x.com"}) ||
		!slices.Equal(opt.Owned.GitHub, []string{"acme-labs", "me", "work-org"}) {
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
		f := fnd(secretrisk.ConnectorName, "", "local", "secret", "gitleaks:"+path+"#"+fp, "AWS key", finding.SevInfo, "AWS key in "+path, t0)
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
		okStatus(secretrisk.ConnectorName, "local"))
	writeRun(t, out, t0, "aws.jsonl", finding.Status{Type: "status", Connector: "aws", Account: ownAWS, State: finding.StateOK})
	tr := New(t0)
	if _, err := tr.Sync(SyncOptions{OutDir: out}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, fp := range []string{"1111", "4444"} {
		it := mustRotate(t, tr, fp)
		// A pushed AWS key id's own impact (low: it signs nothing without its secret key) is P2.
		if it.Priority != secretrisk.P2 || it.WorstLabel() != "git+remote" || it.Owner() != attribution.Mine {
			t.Errorf("%s: %s %s %s, want P2 git+remote mine", fp, it.Priority, it.WorstLabel(), it.Owner())
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
	if rep := tr.syncNoise(map[string]string{"1111aaaa1111aaaa": "aws-access-key-id"}, t0.Add(2*time.Hour)); rep.Reclassified != 0 || mustRotate(t, tr, "1111").Status != Open {
		t.Error("a noise summary reclassified a key attributed mine")
	}
}

func TestKnownLendsAttributionToAScan(t *testing.T) {
	tr, _ := attributionFixture(t)
	k := tr.Known(attribution.Owned{GitHub: []string{"octocat"}})
	if !slices.Contains(k.Owned.AWSAccounts, ownAWS) || !slices.Contains(k.Owned.GitHub, "octocat") {
		t.Errorf("owned %+v", k.Owned)
	}
	for fp, want := range map[string]attribution.Owner{"1111aaaa1111aaaa": attribution.Mine, "2222bbbb2222bbbb": attribution.NotMine, "3333cccc3333cccc": attribution.Unknown} {
		if got := k.Of(fp, nil); got != want {
			t.Errorf("%s: %s, want %s", fp, got, want)
		}
	}
}

// repoAttributionFixture is a home in t.TempDir with the owner's repository, a third-party clone,
// the owner's fork, a repository without a remote and a few dot files, and a local-secrets run of
// one secret in each, the noise included.
func repoAttributionFixture(t *testing.T) (*Tracker, string, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	gitRepo := func(dir, origin string) {
		t.Helper()
		cfg := "[core]\n\tbare = false\n"
		if origin != "" {
			cfg += "[remote \"origin\"]\n\turl = " + origin + "\n"
		}
		if err := os.MkdirAll(filepath.Join(home, dir, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, dir, ".git", "config"), []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitRepo("src/mine", "git@github.com:Acme-Labs/app.git")
	gitRepo("src/theirs", "https://github.com/instructure/canvas.git")
	gitRepo("src/fork", "git@github.com:acme-labs/canvas.git")
	gitRepo("work/local", "")
	gitRepo("Downloads/clone", "https://github.com/instructure/demo.git")
	gitRepo(".oh-my-zsh", "https://github.com/ohmyzsh/ohmyzsh.git")

	out := t.TempDir()
	secret := func(fp string, ev secretrisk.Evidence) finding.Finding {
		ev.Fingerprint, ev.Type, ev.Redacted, ev.Bucket = fp, "stripe-live", "sk_live_…"+fp[:4], "b"
		f := fnd(secretrisk.ConnectorName, "", "local", "secret", ev.Source+":"+ev.Path+"#"+fp, "Stripe key", finding.SevCritical, "Stripe key in "+ev.Path, t0)
		raw, _ := json.Marshal(ev)
		_ = json.Unmarshal(raw, &f.Evidence)
		return f
	}
	committed := func(repo, origin, author string) secretrisk.Evidence {
		return secretrisk.Evidence{Source: "gitleaks", Kind: "repo", Tracked: true, Remote: true, Repo: "~/" + repo, Path: "~/" + repo + "/config/app.yml",
			Origin: origin, Claims: attribution.Claims{AuthorEmail: author}}
	}
	working := func(path, kind string) secretrisk.Evidence {
		return secretrisk.Evidence{Source: "scan", Kind: kind, Mode: "600", Path: path}
	}
	writeRun(t, out, t0, "local-secrets.jsonl",
		secret("a1a1a1a1a1a1a1a1", committed("src/mine", secretrisk.OriginOwned, "")),
		secret("b2b2b2b2b2b2b2b2", committed("src/theirs", "", "them@y.com")),
		secret("c3c3c3c3c3c3c3c3", committed("src/fork", secretrisk.OriginForkUpstream, "")),
		secret("d4d4d4d4d4d4d4d4", working("~/.zshrc", "config")),
		secret("d4d4d4d4d4d4d4d4", working("~/.claude/projects/p/s.jsonl", "transcript")),
		secret("e5e5e5e5e5e5e5e5", working("~/Downloads/clone/.env", "config")),
		secret("f6f6f6f6f6f6f6f6", working("~/.claude/projects/p/s.jsonl", "transcript")),
		secret("f6f6f6f6f6f6f6f6", working("~/.zsh_history", "history")),
		secret("a7a7a7a7a7a7a7a7", working("~/.nvm/versions/node/v22/lib/node_modules/pkg/index.js", "config")),
		secret("a8a8a8a8a8a8a8a8", working("~/.oh-my-zsh/plugins/aws/aws.plugin.zsh", "config")),
		secret("a9a9a9a9a9a9a9a9", committed("src/theirs", "", "")),
		secret("a9a9a9a9a9a9a9a9", committed("work/local", "", "")),
		secret("b1b1b1b1b1b1b1b1", committed("src/theirs", secretrisk.OriginThirdParty, "me@x.com")),
		secret("b3b3b3b3b3b3b3b3", working("~/.config/tool/credentials.json", "config")),
		secret("b4b4b4b4b4b4b4b4", working("~/Documents/notes.txt", "config")),
		secret("c1c1c1c1c1c1c1c1", working("~/src/mine/.env.local", "repo")),
		secret("c2c2c2c2c2c2c2c2", secretrisk.Evidence{Source: "scan", Kind: "repo", Mode: "600", Path: "~/src/theirs/.env", Tracked: true, Remote: true}),
		secret("c4c4c4c4c4c4c4c4", working("~/src/mine/.env.example", "repo")),
		secret("c5c5c5c5c5c5c5c5", working("~/src/mine/node_modules/pkg/.env", "repo")),
		secret("c6c6c6c6c6c6c6c6", working("~/src/mine/.venv/.env", "repo")),
		secret("c7c7c7c7c7c7c7c7", working("~/src/mine/test/fixtures/.env", "repo")),
		secret("c8c8c8c8c8c8c8c8", working("~/src/mine/.envrc", "repo")),
		secret("c9c9c9c9c9c9c9c9", working("~/Documents/.env", "config")),
		secret("d1d1d1d1d1d1d1d1", working("~/.env", "config")),
		secret("d2d2d2d2d2d2d2d2", working("~/src/mine/.claude/projects/p/s.jsonl", "transcript")),
		okStatus(secretrisk.ConnectorName, "local"))
	tr := New(t0)
	opt := SyncOptions{OutDir: out, IncludeNoise: true, Owned: attribution.Owned{GitHub: []string{"acme-labs", "octocat"}, Emails: []string{"me@x.com"}}}
	if _, err := tr.Sync(opt, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return tr, out, home
}

func TestSyncAttributesByRepositoryAuthorAndOwnConfig(t *testing.T) {
	tr, _, _ := repoAttributionFixture(t)
	for _, c := range []struct {
		id, why string
		owner   attribution.Owner
		conf    string
		reason  string
	}{
		{"a1a1", "the owner's repository", attribution.Mine, attribution.Medium, "committed in a repository you own (Acme-Labs)"},
		{"b2b2", "a third-party repository, someone else's commit", attribution.NotMine, attribution.Medium,
			"committed in a repository of instructure, none of your 2 GitHub accounts or organizations (owned.github)"},
		{"c3c3", "history the owner's fork inherited", attribution.Unknown, attribution.Low, "names no account"},
		{"d4d4", "the owner's .zshrc, and a transcript", attribution.Mine, attribution.Medium, "kept in your own config file ~/.zshrc"},
		{"e5e5", "an untracked .env in a cloned third-party repository: the owner wrote it", attribution.Mine, attribution.Medium,
			"kept in your own .env file ~/Downloads/clone/.env (not tracked by git)"},
		{"f6f6", "trails only", attribution.Unknown, attribution.Low, "names no account"},
		{"a7a7", "a package store", attribution.Unknown, attribution.Low, "names no account"},
		{"a8a8", "a git clone in a dot folder", attribution.Unknown, attribution.Low, "names no account"},
		{"a9a9", "third-party and no-remote repositories", attribution.Unknown, attribution.Low, "no GitHub remote, so whose it is is unknown (~/work/local)"},
		{"b1b1", "the owner's commit to a third-party repository", attribution.Mine, attribution.Medium, "committed by you (me@x.com)"},
		{"b3b3", "a tool's config folder", attribution.Mine, attribution.Medium, "kept in your own config file ~/.config/tool/credentials.json"},
		{"b4b4", "a document, not config", attribution.Unknown, attribution.Low, "names no account"},
		{"c1c1", "an untracked .env.local in the owner's checkout", attribution.Mine, attribution.Medium, "kept in your own .env file ~/src/mine/.env.local (not tracked by git)"},
		{"c2c2", "a tracked .env follows its repository", attribution.NotMine, attribution.Medium,
			"committed in a repository of instructure, none of your 2 GitHub accounts or organizations (owned.github)"},
		{"c4c4", "a template, not the owner's values", attribution.Unknown, attribution.Low, "names no account"},
		{"c5c5", "a package's .env", attribution.Unknown, attribution.Low, "names no account"},
		{"c6c6", "a virtualenv's .env", attribution.Unknown, attribution.Low, "names no account"},
		{"c7c7", "a fixture", attribution.Unknown, attribution.Low, "names no account"},
		{"c8c8", "not a .env file", attribution.Unknown, attribution.Low, "names no account"},
		{"c9c9", "a .env in no checkout and no dot folder", attribution.Unknown, attribution.Low, "names no account"},
		{"d1d1", "the home's own .env is own config", attribution.Mine, attribution.Medium, "kept in your own config file ~/.env"},
		{"d2d2", "a transcript in a checkout", attribution.Unknown, attribution.Low, "names no account"},
	} {
		a := mustRotate(t, tr, c.id).Secret.Attribution
		if a == nil || a.Owner != c.owner || a.Confidence != c.conf || !slices.Contains(a.Reasons, c.reason) && !strings.Contains(strings.Join(a.Reasons, "; "), c.reason) {
			t.Errorf("%s (%s): %+v, want %s %s with %q", c.id, c.why, a, c.owner, c.conf, c.reason)
		}
	}
	// Mine by authorship is not enough to undo the third-party discount: that copy stays noise.
	if it := mustRotate(t, tr, "b1b1"); it.Secret.Impact != secretrisk.Noise.String() || it.Secret.Locations[0].Reused {
		t.Errorf("an author's commit to someone else's repository counted in full: %s %+v", it.Secret.Impact, it.Secret.Locations)
	}
	if it := mustRotate(t, tr, "a1a1"); it.Secret.Locations[0].RepoOwner != "Acme-Labs" {
		t.Errorf("repository owner not kept on the location: %+v", it.Secret.Locations[0])
	}
}

// The repository owner is kept on the location: a clone deleted since still says whose it is.
func TestRepoOwnerOutlivesTheClone(t *testing.T) {
	tr, out, home := repoAttributionFixture(t)
	if err := os.RemoveAll(filepath.Join(home, "src", "mine")); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Sync(SyncOptions{OutDir: out, IncludeNoise: true, Owned: attribution.Owned{GitHub: []string{"acme-labs"}}}, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a := mustRotate(t, tr, "a1a1").Secret.Attribution; a.Owner != attribution.Mine {
		t.Errorf("after the clone went: %+v", a)
	}
}

// A git worktree is a checkout like any other: its .git is a file pointing to the main repository.
// An untracked .env there is the owner's own, and a tracked file there is committed in the main
// repository's GitHub owner's repository.
func TestWorktreeIsACheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	main, wt := filepath.Join(home, "src", "app"), filepath.Join(home, "src", "app-wt")
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", main, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.MkdirAll(main, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, "app.yml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("init", "-q")
	git("remote", "add", "origin", "git@github.com:Acme-Labs/app.git")
	git("add", "app.yml")
	git("commit", "-q", "-m", "init")
	git("worktree", "add", "-q", wt)
	if st, err := os.Lstat(filepath.Join(wt, ".git")); err != nil || st.IsDir() {
		t.Fatalf("not a worktree: %v %v", st, err)
	}
	out := t.TempDir()
	secret := func(fp string, ev secretrisk.Evidence) finding.Finding {
		ev.Fingerprint, ev.Type, ev.Redacted, ev.Bucket, ev.Source, ev.Kind, ev.Mode = fp, "stripe-live", "sk_live_…"+fp[:4], "b", "scan", "repo", "600"
		f := fnd(secretrisk.ConnectorName, "", "local", "secret", "scan:"+ev.Path+"#"+fp, "Stripe key", finding.SevCritical, "Stripe key in "+ev.Path, t0)
		raw, _ := json.Marshal(ev)
		_ = json.Unmarshal(raw, &f.Evidence)
		return f
	}
	writeRun(t, out, t0, "local-secrets.jsonl",
		secret("e1e1e1e1e1e1e1e1", secretrisk.Evidence{Path: "~/src/app-wt/.env"}),
		secret("e2e2e2e2e2e2e2e2", secretrisk.Evidence{Path: "~/src/app-wt/app.yml", Tracked: true, Remote: true}),
		okStatus(secretrisk.ConnectorName, "local"))
	tr := New(t0)
	if _, err := tr.Sync(SyncOptions{OutDir: out, IncludeNoise: true, Owned: attribution.Owned{GitHub: []string{"acme-labs"}}}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for id, reason := range map[string]string{
		"e1e1": "kept in your own .env file ~/src/app-wt/.env (not tracked by git)",
		"e2e2": "committed in a repository you own (Acme-Labs)",
	} {
		if a := mustRotate(t, tr, id).Secret.Attribution; a.Owner != attribution.Mine || a.Confidence != attribution.Medium || !slices.Contains(a.Reasons, reason) {
			t.Errorf("%s: %+v, want mine with %q", id, a, reason)
		}
	}
}

func TestSetOwnerWinsAndClears(t *testing.T) {
	tr, _, _ := repoAttributionFixture(t)
	it := mustRotate(t, tr, "b2b2")
	extra := attribution.Owned{GitHub: []string{"acme-labs"}}
	if err := tr.setOwner(it, t0.Add(2*time.Hour), attribution.Mine, " ", extra); err == nil {
		t.Error("mine without a reason")
	}
	if err := tr.setOwner(it, t0.Add(2*time.Hour), "theirs", "x", extra); err == nil {
		t.Error("a bad owner")
	}
	if err := tr.setOwner(it, t0.Add(2*time.Hour), attribution.Mine, "my test account's key", extra); err != nil {
		t.Fatal(err)
	}
	a := it.Secret.Attribution
	if it.Owner() != attribution.Mine || a.Confidence != attribution.High || a.Reasons[0] != "set by you: my test account's key" {
		t.Errorf("override: %+v", a)
	}
	if e := it.History[len(it.History)-1]; e.Event != EvOwner || e.Action != actOwner || e.Detail != "mine: my test account's key" {
		t.Errorf("history %+v", e)
	}
	if got := tr.Known(extra).Of(it.Fingerprint, nil); got != attribution.Mine {
		t.Errorf("Known: %s", got)
	}
	// A sync keeps it.
	tr.attribute(tr.ownedAll(extra))
	if it.Owner() != attribution.Mine {
		t.Errorf("a sync dropped the override: %s", it.Owner())
	}
	if err := tr.setOwner(it, t0.Add(3*time.Hour), attribution.Unknown, "", extra); err != nil {
		t.Fatal(err)
	}
	if it.Owner() != attribution.NotMine || it.Secret.Attribution.Facts.Override != nil {
		t.Errorf("cleared: %+v", it.Secret.Attribution)
	}
	if e := it.History[len(it.History)-1]; e.Detail != "back to the automatic attribution: not-mine (medium confidence)" {
		t.Errorf("history %+v", e)
	}
}
