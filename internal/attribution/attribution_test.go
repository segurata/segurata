package attribution

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/testcorpus"
)

func keyID(t *testing.T, prefix string, account uint64, top bool, low7 byte) string {
	t.Helper()
	id := testcorpus.AWSKeyID(prefix, account, top, low7)
	if len(id) != 20 {
		t.Fatalf("built %q", id)
	}
	return id
}

func TestAWSAccountFromKeyID(t *testing.T) {
	// The public example of the aws_account_id_from_key_id crate.
	if got, ok := AWSAccountFromKeyID("AKIASP2TPHJSQH3FJXYZ"); !ok || got != "171436882533" {
		t.Errorf("crate example: %q %v", got, ok)
	}
	for _, c := range []struct {
		prefix  string
		account uint64
		top     bool
		low     byte
		want    string
	}{
		{"AKIA", 123456789012, false, 0, "123456789012"},
		{"ASIA", 12345678901, true, 0x55, "012345678901"}, // leading zero kept; masked top bit and low bits ignored
		{"AKIA", 1, false, 0x7f, "000000000001"},
	} {
		id := keyID(t, c.prefix, c.account, c.top, c.low)
		if got, ok := AWSAccountFromKeyID(id); !ok || got != c.want {
			t.Errorf("%s: %q %v, want %s", id, got, ok, c.want)
		}
	}
	old := "AKIAIOSFODNN7EXAMPLE" // AWS documentation's example: the older format, fifth character I
	for _, bad := range []string{old, "AKIAJ" + old[5:], "AKIA123", "AKIA0000000000000000", "AROAQNZGKIQY56JQ7WML", ""} {
		if got, ok := AWSAccountFromKeyID(bad); ok {
			t.Errorf("%q decoded to %q", bad, got)
		}
	}
}

func TestValueAndContextClaims(t *testing.T) {
	id := keyID(t, "AKIA", 222233334444, false, 3)
	other := keyID(t, "AKIA", 333344445555, false, 3)
	cases := []struct {
		name string
		got  Claims
		want Claims
	}{
		{"access key id", FromValue(id), Claims{AWSAccount: "222233334444"}},
		{"pre-signed url", FromValue("https://b.s3.amazonaws.com/k?X-Amz-Credential=" + id + "%2F20250101%2Fus-east-1"), Claims{AWSAccount: "222233334444"}},
		{"slack webhook", FromValue("https://hooks.slack.com/services/T0ABC1234/B0DEF5678/abcdefghijklmnopqrstuvwx"), Claims{SlackTeam: "T0ABC1234"}},
		{"slack token carries none", FromValue("xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"), Claims{}},
		{"oauth client id", FromValue("123456789012-abc123def456.apps.googleusercontent.com"), Claims{GCPProject: "123456789012"}},
		{"secret key next to its key id", FromContext("aws_access_key_id = " + id + "\naws_secret_access_key = x"), Claims{AWSAccount: "222233334444"}},
		{"two accounts in one file claim none", FromContext(id + "\n" + other), Claims{}},
		{"service account key", FromContext(`{"type": "service_account", "project_id": "acme-prod-1", "client_id": "1"}`), Claims{GCPProject: "acme-prod-1"}},
		{"client_secret.json without project_id", FromContext(`{"installed":{"client_id":"987654321098-x1y2.apps.googleusercontent.com","client_secret":"GOCSPX-…"}}`), Claims{GCPProject: "987654321098"}},
		{"google-services.json", FromContext(`{"project_info":{"project_number":"111122223333","project_id":"my-app-1a2b3"}}`), Claims{GCPProject: "my-app-1a2b3"}},
		{"GoogleService-Info.plist", FromContext("<key>GCM_SENDER_ID</key>\n<string>444455556666</string>"), Claims{GCPProject: "444455556666"}},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, c.got, c.want)
		}
	}
	if got := (Claims{AWSAccount: "1"}).Or(Claims{AWSAccount: "2", GCPProject: "p"}); got != (Claims{AWSAccount: "1", GCPProject: "p"}) {
		t.Errorf("Or: %+v", got)
	}
}

func TestAttribute(t *testing.T) {
	owned := Owned{AWSAccounts: []string{"012345678901"}, GCPProjects: []string{"demo-shop", "123"}, SlackTeams: []string{"T1"},
		GitHub: []string{"octocat", "acme-labs"}, Emails: []string{"me@x.com"}}
	cases := []struct {
		name   string
		facts  Facts
		owned  Owned
		owner  Owner
		conf   string
		reason string
	}{
		{"owner's AWS account", Facts{AWSAccounts: []string{"012345678901"}}, owned, Mine, High, "AWS account 012345678901 is yours"},
		{"someone else's AWS account", Facts{AWSAccounts: []string{"999999999999"}, AuthorEmails: []string{"me@x.com"}}, owned, NotMine, Medium, "is none of your 1 known"},
		{"owner's project by number", Facts{GCPProjects: []string{"123"}}, owned, Mine, High, "GCP project 123 is yours"},
		{"file naming the owner's and another account", Facts{AWSAccounts: []string{"012345678901"}, GCPProjects: []string{"other"}}, owned, Mine, Medium, "GCP project other is none"},
		{"other workspace", Facts{SlackTeams: []string{"T9"}}, owned, NotMine, Medium, "Slack workspace T9"},
		{"no AWS account known", Facts{AWSAccounts: []string{"999999999999"}}, Owned{}, Unknown, Low, "none of yours is known"},
		{"foreign AWS but project kind unknown", Facts{AWSAccounts: []string{"999999999999"}, SlackTeams: []string{"T9"}}, Owned{AWSAccounts: owned.AWSAccounts}, Unknown, Low, "none of yours is known"},
		{"committed by the owner", Facts{AuthorEmails: []string{"ME@x.com"}}, owned, Mine, Medium, "committed by you (ME@x.com)"},
		{"committed by someone else is a hint only", Facts{AuthorEmails: []string{"them@y.com"}}, owned, Unknown, Low, "hint: committed by someone else (them@y.com)"},
		{"repository of the owner", Facts{RepoOwners: []string{"Acme-Labs"}}, owned, Mine, Medium, "committed in a repository you own (Acme-Labs)"},
		{"repository of someone else", Facts{AuthorEmails: []string{"them@y.com"}, RepoOwners: []string{"instructure"}}, owned, NotMine, Medium,
			"committed in a repository of instructure, none of your 2 GitHub accounts or organizations (owned.github)"},
		{"no GitHub account known", Facts{RepoOwners: []string{"instructure"}}, Owned{AWSAccounts: owned.AWSAccounts}, Unknown, Low, "committed in a repository of instructure: none of your GitHub accounts"},
		{"owner's and someone else's repository", Facts{RepoOwners: []string{"instructure", "octocat"}}, owned, Mine, Medium, "committed in a repository you own (octocat)"},
		{"someone else's repository, committed by the owner", Facts{AuthorEmails: []string{"me@x.com"}, RepoOwners: []string{"instructure"}}, owned, Mine, Medium, "committed by you"},
		{"someone else's repository and one without a GitHub remote", Facts{RepoOwners: []string{"instructure"}, UnownedRepos: []string{"~/work/local"}}, owned, Unknown, Low,
			"committed to a git repository with no GitHub remote, so whose it is is unknown (~/work/local)"},
		{"foreign AWS account in the owner's repository", Facts{AWSAccounts: []string{"999999999999"}, RepoOwners: []string{"octocat"}}, owned, NotMine, Medium, "AWS account 999999999999 is none"},
		{"foreign AWS account in the owner's config file", Facts{AWSAccounts: []string{"999999999999"}, OwnConfig: []string{"~/.aws/credentials"}}, owned, NotMine, Medium, "kept in your own config file"},
		{"owner's AWS account in someone else's repository", Facts{AWSAccounts: []string{"012345678901"}, RepoOwners: []string{"instructure"}}, owned, Mine, Medium, "AWS account 012345678901 is yours"},
		{"unknown AWS account kind, own config file", Facts{AWSAccounts: []string{"999999999999"}, OwnConfig: []string{"~/.zshrc"}}, Owned{}, Mine, Medium, "none of yours is known"},
		{"owner's account and owner's repository", Facts{AWSAccounts: []string{"012345678901"}, RepoOwners: []string{"octocat"}}, owned, Mine, High, "committed in a repository you own"},
		{"own config file", Facts{OwnConfig: []string{"~/.zshrc"}}, Owned{}, Mine, Medium, "kept in your own config file ~/.zshrc"},
		{"own user environment", Facts{OwnConfig: []string{`HKCU\Environment\API_KEY`}}, Owned{}, Mine, Medium, `kept in your own user environment HKCU\Environment\API_KEY`},
		{"own config beats a foreign repository", Facts{OwnConfig: []string{"~/.npmrc"}, RepoOwners: []string{"instructure"}}, owned, Mine, Medium, "kept in your own config file ~/.npmrc"},
		{"own .env file", Facts{OwnEnvFiles: []string{"~/src/app/.env.local"}}, Owned{}, Mine, Medium, "kept in your own .env file ~/src/app/.env.local (not tracked by git)"},
		{"own .env file beats a foreign repository", Facts{OwnEnvFiles: []string{"~/src/app/.env"}, RepoOwners: []string{"instructure"}}, owned, Mine, Medium, "kept in your own .env file ~/src/app/.env (not tracked by git)"},
		{"foreign AWS account in the owner's .env file", Facts{AWSAccounts: []string{"999999999999"}, OwnEnvFiles: []string{"~/src/app/.env"}}, owned, NotMine, Medium, "AWS account 999999999999 is none"},
		{"nothing at all: a transcript copy", Facts{}, owned, Unknown, Low, "names no account"},
		{"private key on the owner's GitHub account", Facts{SSHKeys: []string{"github:OctoCat"}}, owned, Mine, High, "the public key of this private key is on your GitHub account OctoCat"},
		{"private key matching the owner's public key file", Facts{SSHKeys: []string{"file:~/.ssh/id_ed25519.pub"}}, Owned{}, Mine, High, "matches ~/.ssh/id_ed25519.pub"},
		{"private key on a GitHub account no longer known", Facts{SSHKeys: []string{"github:mallory"}}, owned, Unknown, Low, "on GitHub account mallory, none of your known ones"},
		{"private key whose public half cannot be read", Facts{SSHKeys: []string{SSHKeyUnreadable}}, owned, Unknown, Low, "hint: the public key of this private key could not be read"},
		{"unmatched private key in someone else's repository", Facts{RepoOwners: []string{"instructure"}}, owned, NotMine, Medium, "committed in a repository of instructure"},
		{"token of the owner's GitHub login", Facts{GitHubLogins: []string{"OctoCat"}}, owned, Mine, High, "GitHub account OctoCat is yours"},
		{"token of another GitHub login", Facts{GitHubLogins: []string{"mallory"}}, owned, NotMine, Medium, "GitHub account mallory is none"},
	}
	for _, c := range cases {
		r := Attribute(c.facts, c.owned)
		if r.Owner != c.owner || r.Confidence != c.conf || !slices.ContainsFunc(r.Reasons, func(s string) bool { return strings.Contains(s, c.reason) }) {
			t.Errorf("%s: %s %s %q, want %s %s with %q", c.name, r.Owner, r.Confidence, r.Reasons, c.owner, c.conf, c.reason)
		}
	}
}

func TestOverride(t *testing.T) {
	owned := Owned{AWSAccounts: []string{"012345678901"}, GitHub: []string{"octocat"}}
	mineFacts := Facts{AWSAccounts: []string{"012345678901"}}
	f := mineFacts.Clone()
	f.Override = &Override{Owner: NotMine, Reason: "a client's account"}
	r := Attribute(f, owned)
	if r.Owner != NotMine || r.Confidence != High || r.Reasons[0] != "set by you: a client's account" ||
		!slices.Contains(r.Reasons, "without it: mine (high confidence)") || !slices.Contains(r.Reasons, "AWS account 012345678901 is yours") {
		t.Errorf("override not-mine: %+v", r)
	}
	f = Facts{Override: &Override{Owner: Mine, Reason: "my old key"}, RepoOwners: []string{"instructure"}}
	if r := Attribute(f, owned); r.Owner != Mine || r.Confidence != High {
		t.Errorf("override mine over a foreign repository: %+v", r)
	}
	k := &Known{Owned: owned, Facts: map[string]Facts{"fp": f}}
	if got := k.Of("fp", []Claims{{AWSAccount: "999999999999"}}); got != Mine {
		t.Errorf("Known.Of ignores the override: %s", got)
	}
	k.Facts["fp"] = Facts{Override: &Override{Owner: NotMine, Reason: "not mine"}}
	if got := k.Of("fp", []Claims{{AWSAccount: "012345678901"}}); got != NotMine {
		t.Errorf("Known.Of: a not-mine override must win over this scan's claims: %s", got)
	}
	cl := f.Clone()
	cl.Override.Reason = "changed"
	if f.Override.Reason != "my old key" {
		t.Error("Clone shares the override")
	}
	if c := (Facts{OwnConfig: []string{"~/.zshrc"}, OwnEnvFiles: []string{"~/src/app/.env"}}).Clone(); !slices.Equal(c.OwnConfig, []string{"~/.zshrc"}) || !slices.Equal(c.OwnEnvFiles, []string{"~/src/app/.env"}) {
		t.Errorf("Clone drops the files: %+v", c)
	}
	acc := Facts{AWSAccounts: []string{"1"}, SSHKeys: []string{"github:x"}, RepoOwners: []string{"r"}, UnownedRepos: []string{"u"}, AuthorEmails: []string{"e"},
		OwnConfig: []string{"~/.zshrc"}, OwnEnvFiles: []string{"~/src/app/.env"}, Override: &Override{Owner: Mine, Reason: "r"}}.Accounts()
	if len(acc.RepoOwners)+len(acc.UnownedRepos)+len(acc.AuthorEmails)+len(acc.OwnConfig)+len(acc.OwnEnvFiles) != 0 || len(acc.AWSAccounts) != 1 || len(acc.SSHKeys) != 1 || acc.Override == nil {
		t.Errorf("Accounts keeps only what names an account, and the override: %+v", acc)
	}
}

func TestParseOwnersAndMerge(t *testing.T) {
	if got, err := ParseOwners("mine, unknown,mine"); err != nil || !slices.Equal(got, []Owner{Mine, Unknown}) {
		t.Errorf("%v %v", got, err)
	}
	for _, bad := range []string{"", "yours", ","} {
		if _, err := ParseOwners(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	m := Owned{GitHub: []string{"Acme"}, Emails: []string{"a@x.com"}}.Merge(Owned{GitHub: []string{"acme", "b"}, Emails: []string{"A@X.com"}, AWSAccounts: []string{"2", "1", "2"}})
	if !slices.Equal(m.GitHub, []string{"Acme", "b"}) || len(m.Emails) != 1 || !slices.Equal(m.AWSAccounts, []string{"1", "2"}) {
		t.Errorf("merge %+v", m)
	}
}

func TestRepoOwner(t *testing.T) {
	root := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	main := filepath.Join(root, "main")
	write(filepath.Join(main, ".git", "config"), "[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = https://github.com/someone/x.git\n[remote \"origin\"]\n\turl = git@github.com:Acme-Labs/x.git\n")
	write(filepath.Join(main, ".git", "worktrees", "wt", "commondir"), "../..\n")
	write(filepath.Join(root, "wt", ".git"), "gitdir: "+filepath.Join(main, ".git", "worktrees", "wt")+"\n")
	write(filepath.Join(root, "gitlab", ".git", "config"), "[remote \"origin\"]\n\turl = https://gitlab.com/a/b.git\n")
	for _, c := range []struct {
		path, want string
		ok         bool
	}{
		{filepath.Join(main, "config", "secrets.yml"), "Acme-Labs", true},
		{filepath.Join(root, "wt", "deep", "f"), "Acme-Labs", true},
		{filepath.Join(root, "gitlab", "f"), "", false},
		{filepath.Join(root, "nowhere", "f"), "", false},
	} {
		if got, ok := RepoOwner(c.path); got != c.want || ok != c.ok {
			t.Errorf("%s: %q %v", c.path, got, ok)
		}
	}
	if !InRepository(filepath.Join(root, "wt", "deep", "f")) || !InRepository(filepath.Join(main, "x")) || InRepository(filepath.Join(root, "nowhere", "f")) {
		t.Error("InRepository")
	}
	for url, want := range map[string]string{"https://github.com/o/r": "o", "ssh://git@github.com:22/o-x/r": "o-x", "https://tok@github.com/O/r.git": "O"} {
		if got, _ := githubOwner(url); got != want {
			t.Errorf("%s: %q", url, got)
		}
	}
}

func TestDiscover(t *testing.T) {
	fs := []finding.Finding{
		{Connector: "aws", Account: "acme-alias", Resource: finding.Resource{Type: AWSAccountType}, Evidence: map[string]any{"account_id": "111111111111"}},
		{Connector: "gcp", Resource: finding.Resource{Type: GCPProjectsType}, Evidence: map[string]any{"projects": []any{map[string]any{"id": "demo-shop", "number": "42"}}}},
		{Connector: "connected-apps", Resource: finding.Resource{Type: SlackWorkspaceType}, Evidence: map[string]any{"team_id": "T0AAA"}},
	}
	sts := []finding.Status{
		{Connector: "aws", Account: "012345678901", State: finding.StateNoScope},
		{Connector: "aws", Account: "profile r2", State: finding.StateReauth},
		{Connector: "gcp", Account: "me@gmail.com", State: finding.StateOK},
		{Connector: "gcp", Account: "bot@p.iam.gserviceaccount.com", State: finding.StateOK},
		{Connector: "google-personal", Account: "colleague@work.com", State: finding.StateReauth},
		{Connector: "google-personal", Account: "me@work.com", State: finding.StateOK},
		{Connector: "github", Account: "github:acme-labs", State: finding.StateOK},
		{Connector: "connected-apps", Account: "github:octocat", State: finding.StateOK},
	}
	o := Discover(fs, sts)
	want := Owned{AWSAccounts: []string{"012345678901", "111111111111"}, GCPProjects: []string{"42", "demo-shop"}, SlackTeams: []string{"T0AAA"},
		GitHub: []string{"acme-labs", "octocat"}, Emails: []string{"me@gmail.com", "me@work.com"}}
	for _, p := range [][2][]string{{o.AWSAccounts, want.AWSAccounts}, {o.GCPProjects, want.GCPProjects}, {o.SlackTeams, want.SlackTeams}, {o.GitHub, want.GitHub}, {o.Emails, want.Emails}} {
		if !slices.Equal(p[0], p[1]) {
			t.Errorf("%v, want %v", p[0], p[1])
		}
	}
}

func TestFromAccount(t *testing.T) {
	cases := map[string]Claims{
		"aws:012345678901":  {AWSAccount: "012345678901"},
		"slack:T0123":       {SlackTeam: "T0123"},
		"github:octocat":    {GitHubLogin: "octocat"},
		"huggingface:alice": {},
		"aws:not-an-id":     {},
		"":                  {},
	}
	for account, want := range cases {
		if got := FromAccount(account); got != want {
			t.Errorf("%q: %+v, want %+v", account, got, want)
		}
	}
	if !(Claims{SSHKey: "github:x"}).NamesAccount() || (Claims{SSHKey: SSHKeyUnreadable}).NamesAccount() {
		t.Error("a private key on a GitHub account names one; an unreadable one does not")
	}
	if got := (Claims{}).Or(Claims{SSHKey: "file:~/.ssh/a.pub"}); got.SSHKey != "file:~/.ssh/a.pub" {
		t.Errorf("Or drops the SSH key: %+v", got)
	}
	f0 := Facts{}
	f0.Add(Claims{SSHKey: "github:x"})
	if !slices.Equal(f0.SSHKeys, []string{"github:x"}) {
		t.Errorf("Add: %+v", f0)
	}
	if !(Claims{GitHubLogin: "x"}).NamesAccount() {
		t.Error("a GitHub login names an account")
	}
	var f Facts
	f.Add(Claims{GitHubLogin: "OctoCat"})
	f.Add(Claims{GitHubLogin: "octocat"})
	if len(f.GitHubLogins) != 1 {
		t.Errorf("logins folded without case: %v", f.GitHubLogins)
	}
}

func TestKnownOf(t *testing.T) {
	owned := Owned{AWSAccounts: []string{"012345678901"}}
	k := &Known{Owned: owned, Facts: map[string]Facts{"fp-old": {AWSAccounts: []string{"012345678901"}}}}
	if got := k.Of("fp-old", nil); got != Mine {
		t.Errorf("facts an earlier sync gathered: %s", got)
	}
	if got := k.Of("fp-new", []Claims{{AWSAccount: "999999999999"}}); got != NotMine {
		t.Errorf("claims of this scan: %s", got)
	}
	if got := k.Of("fp-none", nil); got != Unknown {
		t.Errorf("nothing known: %s", got)
	}
	k.Of("fp-old", []Claims{{AWSAccount: "999999999999"}})
	if len(k.Facts["fp-old"].AWSAccounts) != 1 {
		t.Error("Of changed the facts it was lent")
	}
	var none *Known
	if got := none.Of("fp", []Claims{{AWSAccount: "012345678901"}}); got != Unknown {
		t.Errorf("no Known: %s", got)
	}
}
