package tracker

import (
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

var t0 = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)

func ev(fp, typ, path, source, kind, mode string, tracked, remote bool) secretrisk.Evidence {
	return secretrisk.Evidence{Fingerprint: fp, Type: typ, Path: path, Source: source, Kind: kind, Mode: mode,
		Tracked: tracked, Remote: remote, Redacted: "hint-" + typ, Bucket: "b", Count: 1}
}

func sight(e secretrisk.Evidence) Sighting { return Sighting{Evidence: e} }

func TestSyncGroupsByFingerprintAndPrioritises(t *testing.T) {
	l := &Tracker{NextID: 1}
	rep := l.SyncSecrets([]Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/shop/.env", "scan", "repo", "600", false, false)),
		sight(ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false)),
		sight(ev("aaaaaaaaaaaaaaaa", "generic-api-key", "~/src/shop/app.js", "gitleaks", "repo", "", true, false)),
		sight(ev("bbbbbbbbbbbbbbbb", "anthropic", "~/.zshrc", "scan", "config", "644", false, false)),
		sight(ev("cccccccccccccccc", "assignment", "~/.env", "scan", "config", "600", false, false)),
		sight(ev("dddddddddddddddd", "private-key", "~/k.json", "scan", "config", "600", false, false)),
		sight(ev("dddddddddddddddd", "gcp-service-account", "~/k.json", "scan", "config", "600", false, false)),
	}, t0, false, attribution.Owned{})
	if rep.Secrets != 3 || rep.Created != 3 || rep.Skipped != 1 {
		t.Fatalf("report %+v", rep)
	}
	s, _ := l.FindRotate("aaaaaaaa")
	if s.Secret.Type != "stripe-live" || s.Secret.Service != "stripe" || s.Priority != secretrisk.P0 || len(s.Secret.Locations) != 3 {
		t.Fatalf("stripe item %+v", s)
	}
	if s.Secret.Reasons[0] != "Stripe live secret key; pasted into an agent transcript, so it reached the model provider" {
		t.Errorf("reason %q", s.Secret.Reasons[0])
	}
	if len(s.Secret.Reasons) != 3 || !strings.Contains(s.Secret.Reasons[1], "local git repository") {
		t.Errorf("secondary reasons %q", s.Secret.Reasons)
	}
	if strings.Join(s.Secret.UsedIn, ",") != "~/src/shop/.env" || s.Secret.RotateURL != "https://dashboard.stripe.com/apikeys" {
		t.Errorf("used_in %v rotate %q", s.Secret.UsedIn, s.Secret.RotateURL)
	}
	if s.WorstLabel() != "transcript" || s.Status != Open || len(s.History) != 1 || s.History[0].Action != actFound {
		t.Errorf("stripe item state %+v", s)
	}
	a, _ := l.FindRotate("bbbb")
	if a.Priority != secretrisk.P2 {
		t.Errorf("anthropic in a readable rc file: %s", a.Priority)
	}
	g, _ := l.FindRotate("dddd")
	if g.Secret.Type != "gcp-service-account" || g.Priority != secretrisk.P2 || len(g.Secret.Locations) != 1 {
		t.Errorf("service account key %+v", g)
	}
	if _, err := l.FindRotate("cccc"); err == nil {
		t.Error("noise-only secret tracked by default")
	}

	l.SyncSecrets([]Sighting{sight(ev("cccccccccccccccc", "assignment", "~/.env", "scan", "config", "600", false, false))}, t0, true, attribution.Owned{})
	if c, err := l.FindRotate("cccc"); err != nil || c.Priority != "" {
		t.Errorf("--include-noise item: %+v %v", c, err)
	}
}

func TestDoneButStillPresentReopens(t *testing.T) {
	l := &Tracker{NextID: 1}
	in := []Sighting{sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.netrc", "scan", "config", "600", false, false))}
	l.SyncSecrets(in, t0, false, attribution.Owned{})
	it, _ := l.FindRotate("aaaa")
	it.Done(t0.Add(time.Hour), "new token in the Keychain")
	if it.Status != Done {
		t.Fatal("not rotated")
	}
	rep := l.SyncSecrets(in, t0.Add(24*time.Hour), false, attribution.Owned{})
	if rep.Reopened != 1 || it.Status != Open || it.Secret.Reasons[0] != StillPresent {
		t.Fatalf("report %+v item %+v", rep, it)
	}
	if last := it.History[len(it.History)-1]; last.Action != actAutoReopen {
		t.Errorf("history %+v", it.History)
	}
	it.Done(t0.Add(48*time.Hour), "removed for real")
	if len(it.Secret.Reasons) > 0 && it.Secret.Reasons[0] == StillPresent {
		t.Error("stale reason kept after done")
	}
}

func TestDoneSeenOnlyInHistoryStaysDone(t *testing.T) {
	l := &Tracker{NextID: 1}
	rc := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.zshrc", "scan", "config", "600", false, false))
	transcript := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false))
	gitHistory := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/src/app/config.yml", "gitleaks", "repo", "", true, true))
	l.SyncSecrets([]Sighting{rc, transcript, gitHistory}, t0, false, attribution.Owned{})
	it, _ := l.FindRotate("aaaa")
	it.Done(t0.Add(time.Hour), "")
	if strings.Join(it.Secret.RotatedLocations, ",") != "gitleaks:~/src/app/config.yml,scan:~/.claude/projects/p/s.jsonl,scan:~/.zshrc" {
		t.Fatalf("rotated locations %v", it.Secret.RotatedLocations)
	}

	// The rc file was fixed; the transcript and git history still hold the dead value, and a new
	// log copy appeared.
	log := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/src/app/log/dev.log", "scan", "log", "600", false, false))
	for day := 1; day <= 3; day++ {
		rep := l.SyncSecrets([]Sighting{transcript, gitHistory, log}, t0.Add(time.Duration(day)*24*time.Hour), false, attribution.Owned{})
		if it.Status != Done || rep.Reopened != 0 {
			t.Fatalf("day %d: reopened on history-only copies: %+v %+v", day, rep, it)
		}
		if want := map[bool]int{true: 1, false: 0}[day == 1]; rep.HistoryOnly != want {
			t.Errorf("day %d: history-only count %d, want %d", day, rep.HistoryOnly, want)
		}
	}
	notes := 0
	for _, e := range it.History {
		if e.Action == actHistory {
			notes++
			if e.Detail != historyOnly {
				t.Errorf("note %q", e.Detail)
			}
		}
	}
	if notes != 1 || len(it.Secret.Locations) != 4 {
		t.Errorf("want one note and four locations: %d %+v", notes, it.Secret.Locations)
	}

	// A second rotation gets its own note.
	it.reopen(t0.Add(5*24*time.Hour), "")
	it.Done(t0.Add(5*24*time.Hour), "rotated again")
	if rep := l.SyncSecrets([]Sighting{transcript}, t0.Add(6*24*time.Hour), false, attribution.Owned{}); rep.HistoryOnly != 1 || it.Status != Done {
		t.Errorf("after a new rotation: %+v %s", rep, it.Status)
	}
}

func TestDoneSeenInWorkingFileReopens(t *testing.T) {
	cases := []struct {
		name string
		see  []Sighting
		note string
	}{
		{"known working file", []Sighting{
			sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.zshrc", "scan", "config", "600", false, false)),
		}, "still in ~/.zshrc"},
		{"new working file", []Sighting{
			sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false)),
			sight(ev("aaaaaaaaaaaaaaaa", "github", "~/src/new/.env", "scan", "repo", "600", false, false)),
		}, "new working location ~/src/new/.env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &Tracker{NextID: 1}
			l.SyncSecrets([]Sighting{
				sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.zshrc", "scan", "config", "600", false, false)),
				sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.claude/projects/p/s.jsonl", "scan", "transcript", "600", false, false)),
			}, t0, false, attribution.Owned{})
			it, _ := l.FindRotate("aaaa")
			it.Done(t0.Add(time.Hour), "")
			rep := l.SyncSecrets(tc.see, t0.Add(24*time.Hour), false, attribution.Owned{})
			if rep.Reopened != 1 || rep.HistoryOnly != 0 || it.Status != Open || it.Secret.Reasons[0] != StillPresent {
				t.Fatalf("report %+v item %+v", rep, it)
			}
			last := it.History[len(it.History)-1]
			if last.Action != actAutoReopen || !strings.HasSuffix(last.Detail, tc.note) {
				t.Errorf("history %+v", last)
			}
		})
	}
}

func TestItemsNotSeenKeepLastSeen(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "xai", "~/.zshrc", "scan", "config", "600", false, false))}, t0, false, attribution.Owned{})
	l.SyncSecrets([]Sighting{sight(ev("bbbbbbbbbbbbbbbb", "xai", "~/.zshrc", "scan", "config", "600", false, false))}, t0.Add(72*time.Hour), false, attribution.Owned{})
	a, _ := l.FindRotate("aaaa")
	b, _ := l.FindRotate("bbbb")
	if !a.Secret.LastSeen.Equal(t0) || !b.Secret.LastSeen.Equal(t0.Add(72*time.Hour)) || len(l.Items) != 2 {
		t.Errorf("last seen %v %v", a.Secret.LastSeen, b.Secret.LastSeen)
	}
}

func TestSnoozeExpires(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "notion", "~/.mcp/x.json", "scan", "config", "600", false, false))}, t0, false, attribution.Owned{})
	it, _ := l.FindRotate("aaaa")
	if err := it.snooze(t0, "2026-11-20", ""); err == nil {
		t.Error("snooze into the past accepted")
	}
	if err := it.snooze(t0, "next week", ""); err == nil {
		t.Error("bad date accepted")
	}
	if err := it.snooze(t0, "2026-12-01", "after the release"); err != nil {
		t.Fatal(err)
	}
	if it.Active(t0) || !it.Active(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("snooze window")
	}
	var rep SyncReport
	l.expireAll(time.Date(2026, 12, 2, 0, 0, 0, 0, time.UTC), &rep)
	if rep.Woken != 1 || it.Status != Open {
		t.Errorf("snooze did not expire: %+v %s", rep, it.Status)
	}
	if err := it.ignore(t0, " "); err == nil {
		t.Error("ignore without a reason")
	}
}

// --until is a day in the owner's zone, as accept reads it: west of UTC, an evening snooze until
// tomorrow is in the future, and the item comes back at local midnight, not UTC midnight.
func TestSnoozeUntilIsALocalDate(t *testing.T) {
	la := time.FixedZone("PST", -8*3600)
	evening := time.Date(2026, 11, 24, 20, 0, 0, 0, la) // already 2026-11-25 in UTC
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "notion", "~/.mcp/x.json", "scan", "config", "600", false, false))}, evening, false, attribution.Owned{})
	it, _ := l.FindRotate("aaaa")
	if err := it.snooze(evening, "2026-11-25", ""); err != nil {
		t.Fatalf("snooze until tomorrow refused: %v", err)
	}
	if it.Active(time.Date(2026, 11, 24, 23, 0, 0, 0, la)) {
		t.Error("awake before local midnight")
	}
	if !it.Active(time.Date(2026, 11, 25, 0, 0, 0, 0, la)) {
		t.Error("still asleep at local midnight of --until")
	}
}

func TestIDsGrowOnCollision(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{
		sight(ev("abcdef0123456789", "github", "~/a", "scan", "config", "600", false, false)),
		sight(ev("abcdef0199999999", "github", "~/b", "scan", "config", "600", false, false)),
	}, t0, false, attribution.Owned{})
	if l.Items[0].Secret.ID != "abcdef01" || l.Items[1].Secret.ID != "abcdef019" {
		t.Errorf("ids %s %s", l.Items[0].Secret.ID, l.Items[1].Secret.ID)
	}
	if _, err := l.FindRotate("abcdef"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Errorf("ambiguous prefix: %v", err)
	}
}

func TestSortByPriorityExposureService(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{
		sight(ev("1111111111111111", "anthropic", "~/a", "scan", "transcript", "600", false, false)),      // P1 transcript
		sight(ev("2222222222222222", "github", "~/b", "scan", "config", "644", false, false)),             // P1 readable
		sight(ev("3333333333333333", "aws-secret-key", "~/c", "gitleaks", "repo", "", true, true)),        // P0
		sight(ev("4444444444444444", "openai-project", "~/d", "scan", "transcript", "600", false, false)), // P1 transcript
		sight(ev("5555555555555555", "sentry-dsn", "~/e", "scan", "config", "600", false, false)),         // P3
	}, t0, false, attribution.Owned{})
	items := append([]*Item{}, l.Items...)
	Sort(items)
	var got []string
	for _, it := range items {
		got = append(got, it.Secret.Service)
	}
	if strings.Join(got, ",") != "aws,anthropic,openai,github,sentry" {
		t.Errorf("order %v", got)
	}
}

// A key id signs nothing without its secret key, which is an item of its own when found: pushed,
// the id alone is P2, the secret key P0. Found live in the owner's IAM inventory while leaked, the
// id is P0 again: its secret key may have leaked with it in a form no pattern matched.
func TestAWSKeyIDAloneIsP2(t *testing.T) {
	l := &Tracker{NextID: 1}
	id := ev("aaaaaaaaaaaaaaaa", "aws-access-key-id", "~/src/r/group_vars/all.yml", "gitleaks", "repo", "", true, true)
	id.Redacted = "AKIA…(20)"
	secret := ev("bbbbbbbbbbbbbbbb", "aws-secret-key", "~/src/r/group_vars/all.yml", "gitleaks", "repo", "", true, true)
	l.SyncSecrets([]Sighting{sight(id), sight(secret)}, t0, false, attribution.Owned{})
	a, _ := l.FindRotate("aaaa")
	b, _ := l.FindRotate("bbbb")
	if a.Priority != secretrisk.P2 || b.Priority != secretrisk.P0 {
		t.Fatalf("id %s, secret key %s", a.Priority, b.Priority)
	}
	if !strings.HasPrefix(a.Title, "AWS access key id (signs nothing without its secret key) AKIA…(20)") {
		t.Errorf("title %q", a.Title)
	}
	a.Secret.Liveness = &secretrisk.Liveness{State: secretrisk.Live, Provider: "aws-keys", CheckedAt: t0, Rules: secretrisk.LivenessRules}
	a.derive()
	if a.Priority != secretrisk.P0 {
		t.Errorf("an active key whose id leaked: %s", a.Priority)
	}
}

// A key id paired with its secret access key is one key: its item merges into the secret key's,
// whose title names it. Paired with another secret key later, it follows; with none whose item
// stands (noise), it reopens on its own. An unpaired key id stays on its own.
func TestKeyIDFoldsIntoItsSecretKey(t *testing.T) {
	l := &Tracker{NextID: 1}
	const path = "~/src/r/group_vars/all.yml"
	id := ev("aaaaaaaaaaaaaaaa", "aws-access-key-id", path, "gitleaks", "repo", "", true, true)
	id.Redacted, id.Pair = "AKIA…WXYZ(20)", "bbbbbbbbbbbbbbbb"
	secret := ev("bbbbbbbbbbbbbbbb", "aws-secret-key", path, "gitleaks", "repo", "", true, true)
	secret.Redacted, secret.Pair = "…abcd(40)", "aaaaaaaaaaaaaaaa"
	lone := ev("cccccccccccccccc", "aws-access-key-id", path, "gitleaks", "repo", "", true, true)
	lone.Redacted = "AKIA…LONE(20)"
	rep := l.SyncSecrets([]Sighting{sight(id), sight(secret), sight(lone)}, t0, false, attribution.Owned{})
	a, _ := l.FindRotate("aaaa")
	b, _ := l.FindRotate("bbbb")
	c, _ := l.FindRotate("cccc")
	if rep.Paired != 1 || a.Status != Merged || a.MergedInto != b.ID || b.Status != Open || c.Status != Open {
		t.Fatalf("paired %d; key id %s into %q; secret key %s; lone key id %s", rep.Paired, a.Status, a.MergedInto, b.Status, c.Status)
	}
	if !strings.Contains(b.Title, "AWS secret access key …abcd(40) (key id AKIA…WXYZ(20)) in ") {
		t.Errorf("secret key title %q", b.Title)
	}
	// The same pair again: nothing changes.
	events := len(a.History)
	if rep := l.SyncSecrets([]Sighting{sight(id), sight(secret)}, t0.Add(time.Hour), false, attribution.Owned{}); rep.Paired != 0 || len(a.History) != events {
		t.Errorf("a second sync merged again: paired %d, %d events", rep.Paired, len(a.History)-events)
	}
	// Now paired with another secret key: it follows it.
	other := ev("dddddddddddddddd", "aws-secret-key", path, "gitleaks", "repo", "", true, true)
	other.Redacted, other.Pair = "…efgh(40)", "aaaaaaaaaaaaaaaa"
	id.Pair = "dddddddddddddddd"
	l.SyncSecrets([]Sighting{sight(id), sight(other)}, t0.Add(2*time.Hour), false, attribution.Owned{})
	d, _ := l.FindRotate("dddd")
	if a.Status != Merged || a.MergedInto != d.ID || !strings.Contains(d.Title, "(key id AKIA…WXYZ(20))") || strings.Contains(b.Title, "key id") {
		t.Errorf("key id %s into %q; titles %q and %q", a.Status, a.MergedInto, d.Title, b.Title)
	}
	// Its secret key turns out to be noise: the key id stands on its own again.
	d.Status = Reclassified
	l.SyncSecrets([]Sighting{sight(id)}, t0.Add(3*time.Hour), false, attribution.Owned{})
	if a.Status != Open || a.MergedInto != "" {
		t.Errorf("key id of a noise secret key: %s into %q", a.Status, a.MergedInto)
	}
}

// A rule fix that lowers a secret's impact must reach existing items on the next sync.
func TestSyncLowersImpactWhenTheCurrentSightingIsLess(t *testing.T) {
	l := &Tracker{NextID: 1}
	token := ev("aaaaaaaaaaaaaaaa", "sourcegraph-access-token", "~/src/r/data.json", "gitleaks", "repo", "", true, true)
	token.Redacted = "sgp_…(49)"
	l.SyncSecrets([]Sighting{sight(token)}, t0, false, attribution.Owned{})
	if p := l.Items[0].Priority; p != "P1" {
		t.Fatalf("pushed Sourcegraph token should be P1, got %s", p)
	}
	hex := token
	hex.Redacted = "…(40)" // the rule now knows a bare 40-character hex string is a hash more often
	l.SyncSecrets([]Sighting{sight(hex)}, t0.Add(time.Hour), false, attribution.Owned{})
	if it := l.Items[0]; it.Secret.Impact != "noise" || it.Priority != "" {
		t.Fatalf("the same item seen as a hex lookalike must drop: impact=%s priority=%s", it.Secret.Impact, it.Priority)
	}
}

func TestSecretTitleNamesTheWorstPlaceAndTheCommitDate(t *testing.T) {
	l := &Tracker{NextID: 1}
	hist := ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/acme/shop/config/old.env", "gitleaks", "repo", "", true, true)
	hist.Repo, hist.Date, hist.Redacted = "~/src/acme/shop", "2023-04-09", "sk_live_…a1b2(48)"
	later := hist
	later.Path, later.Date = "~/src/acme/shop/config/new.env", "2024-06-01"
	local := ev("aaaaaaaaaaaaaaaa", "stripe-live", "~/src/acme/shop/.env", "scan", "repo", "600", false, false)
	local.Redacted = hist.Redacted
	pem := ev("bbbbbbbbbbbbbbbb", "private-key", "~/.ssh/deploy.pem", "scan", "config", "600", false, false)
	pem.Redacted = "PEM"
	l.SyncSecrets([]Sighting{sight(hist), sight(later), sight(local), sight(pem)}, t0, false, attribution.Owned{})
	s, _ := l.FindRotate("aaaa")
	if want := "Stripe live secret key sk_live_…a1b2(48) in acme/shop:config/new.env (+2 places), committed 2023-04"; s.Title != want {
		t.Errorf("title %q, want %q", s.Title, want)
	}
	k, _ := l.FindRotate("bbbb")
	if k.Title != "Private key in ~/.ssh/deploy.pem" {
		t.Errorf("title %q", k.Title)
	}
}

func TestSortPrefersOwnedRepositoriesAndRecentCommits(t *testing.T) {
	l := &Tracker{NextID: 1}
	leak := func(fp, date, origin string) Sighting {
		e := ev(fp, "aws-access-key-id", "~/src/r"+fp[:1]+"/k.env", "gitleaks", "repo", "", true, true)
		e.Redacted, e.Date, e.Origin = "AKIA…(20)", date, origin
		return sight(e)
	}
	l.SyncSecrets([]Sighting{
		leak("1111111111111111", "2025-01-01", ""),
		leak("2222222222222222", "2019-01-01", secretrisk.OriginOwned),
		leak("3333333333333333", "2024-01-01", secretrisk.OriginOwned),
	}, t0, false, attribution.Owned{})
	items := append([]*Item{}, l.Items...)
	Sort(items)
	var got []string
	for _, it := range items {
		got = append(got, it.Secret.ID[:1])
	}
	if strings.Join(got, ",") != "3,2,1" {
		t.Errorf("order %v", got)
	}
}

func TestUpstreamLocationsDoNotRaisePriority(t *testing.T) {
	l := &Tracker{NextID: 1}
	mine := ev("aaaaaaaaaaaaaaaa", "github", "~/.config/gh/hosts.yml", "scan", "config", "600", false, false)
	theirs := ev("aaaaaaaaaaaaaaaa", "github", "~/src/lms/config/ci.yml", "gitleaks", "repo", "", true, true)
	theirs.Origin = secretrisk.OriginThirdParty
	l.SyncSecrets([]Sighting{sight(mine), sight(theirs)}, t0, true, attribution.Owned{})
	it := l.Items[0]
	if it.Priority != secretrisk.P2 || it.WorstLabel() != "local" {
		t.Errorf("a third-party copy not tied to the owner raised the item: %s %s", it.Priority, it.WorstLabel())
	}
	theirs.Reused = true
	l.SyncSecrets([]Sighting{sight(mine), sight(theirs)}, t0, true, attribution.Owned{})
	if it.Priority != secretrisk.P0 {
		t.Errorf("the owner's token pushed to a third-party repository: %s", it.Priority)
	}
}

// Spots that tie in rank (both upstream copies) are listed in one order every time, not in map order.
func TestAlsoReasonsHaveAStableOrder(t *testing.T) {
	l := &Tracker{NextID: 1}
	upstream := func(path, origin string) Sighting {
		e := ev("aaaaaaaaaaaaaaaa", "github", path, "gitleaks", "repo", "", true, true)
		e.Origin = origin
		return sight(e)
	}
	l.SyncSecrets([]Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.zshrc", "scan", "config", "644", false, false)),
		upstream("~/src/a/ci.yml", secretrisk.OriginThirdParty),
		upstream("~/src/b/ci.yml", secretrisk.OriginForkUpstream),
	}, t0, true, attribution.Owned{})
	it := l.Items[0]
	want := strings.Join(it.Secret.Reasons, "\n")
	if !strings.Contains(want, "fork inherited") || strings.Index(want, "fork inherited") > strings.Index(want, "third-party") {
		t.Fatalf("reasons %q", it.Secret.Reasons)
	}
	for range 50 {
		if it.derive(); strings.Join(it.Secret.Reasons, "\n") != want {
			t.Fatalf("reasons changed order:\n%s\n---\n%s", want, strings.Join(it.Secret.Reasons, "\n"))
		}
	}
}

// A corrected rule turns a tracked secret into noise: its item is updated, not left behind.
func TestASecretNowNoiseIsReclassified(t *testing.T) {
	l := &Tracker{NextID: 1}
	real := []Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "anthropic", "~/.zshrc", "scan", "config", "644", false, false)),
		sight(ev("bbbbbbbbbbbbbbbb", "anthropic", "~/src/log/development.log", "scan", "log", "644", false, false)),
	}
	l.SyncSecrets(real, t0, false, attribution.Owned{})
	open, _ := l.FindRotate("aaaa")
	ignored, _ := l.FindRotate("bbbb")
	if err := ignored.ignore(t0, "test suite fixtures in a gitignored Rails test log"); err != nil {
		t.Fatal(err)
	}
	noise := []Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "assignment", "~/.zshrc", "scan", "config", "644", false, false)),
		sight(ev("bbbbbbbbbbbbbbbb", "assignment", "~/src/log/development.log", "scan", "log", "644", false, false)),
	}
	rep := l.SyncSecrets(noise, t0.Add(time.Hour), false, attribution.Owned{})
	if rep.Reclassified != 2 || rep.Skipped != 0 || rep.Secrets != 0 {
		t.Fatalf("report %+v", rep)
	}
	for _, it := range []*Item{open, ignored} {
		last := it.History[len(it.History)-1]
		if it.Status != Reclassified || it.Priority != "" || it.Secret.Impact != "noise" || last.Event != EvReclassified ||
			!strings.Contains(last.Detail, "every current sighting is noise (assignment)") {
			t.Errorf("%s: %s %q %s %+v", it.ID, it.Status, it.Priority, it.Secret.Impact, last)
		}
	}
	if d := ignored.History[len(ignored.History)-1].Detail; !strings.HasPrefix(d, "was ignored: test suite fixtures in a gitignored Rails test log; ") {
		t.Errorf("ignore reason lost: %q", d)
	}
	var b strings.Builder
	if err := doc.Render(&b, l.status("tracker.json", t0.Add(time.Hour), View{}), doc.Text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "ignored 0, reclassified as noise 2") {
		t.Errorf("headline:\n%s", b.String())
	}
	// Seen again as noise: nothing changes.
	if rep := l.SyncSecrets(noise, t0.Add(2*time.Hour), false, attribution.Owned{}); rep.Reclassified != 0 || len(open.History) != 2 {
		t.Errorf("second noise sync %+v, history %+v", rep, open.History)
	}
	// The rule changes back: the open one reopens, the ignored one is ignored again with its reason.
	rep = l.SyncSecrets(real, t0.Add(3*time.Hour), false, attribution.Owned{})
	if rep.Reopened != 1 || open.Status != Open || open.Priority == "" {
		t.Errorf("open item back: %+v %s %q", rep, open.Status, open.Priority)
	}
	if ignored.Status != Ignored || ignored.lastDetail(actIgnore) != "test suite fixtures in a gitignored Rails test log" {
		t.Errorf("ignored item back: %s %q", ignored.Status, ignored.lastDetail(actIgnore))
	}
}

// Done and accepted items stay as the owner left them.
func TestReclassifyLeavesSettledItems(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "anthropic", "~/.zshrc", "scan", "config", "644", false, false))}, t0, false, attribution.Owned{})
	it, _ := l.FindRotate("aaaa")
	it.Done(t0, "rotated")
	rep := l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "assignment", "~/.zshrc", "scan", "config", "644", false, false))}, t0.Add(time.Hour), false, attribution.Owned{})
	if rep.Reclassified != 0 || it.Status != Done || it.Secret.Impact != "noise" {
		t.Errorf("%+v %s %s", rep, it.Status, it.Secret.Impact)
	}
}

// The connector emits noise as one summary, not one finding per copy: it still reclassifies.
func TestNoiseSummaryReclassifies(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "aws-access-key-id", "~/src/lms/k.yml", "gitleaks", "repo", "", true, true)),
		sight(ev("bbbbbbbbbbbbbbbb", "anthropic", "~/.zshrc", "scan", "config", "644", false, false)),
	}, t0, false, attribution.Owned{})
	summary := finding.Finding{Connector: secretrisk.ConnectorName, Resource: finding.Resource{Type: secretrisk.NoiseSummaryType},
		Evidence: map[string]any{"noise_fingerprints": map[string]any{"aaaaaaaaaaaaaaaa": "aws-access-key-id", "ffffffffffffffff": "assignment"}}}
	noise := noiseOnly([]finding.Finding{{Connector: secretrisk.ConnectorName, Resource: finding.Resource{Type: "secret"}}, summary})
	if len(noise) != 2 {
		t.Fatalf("NoiseOnly %v", noise)
	}
	rep := l.syncNoise(noise, t0.Add(time.Hour))
	a, _ := l.FindRotate("aaaa")
	b, _ := l.FindRotate("bbbb")
	if rep.Reclassified != 1 || a.Status != Reclassified || a.Priority != "" || b.Status != Open || len(l.Items) != 2 {
		t.Errorf("report %+v, a %s %q, b %s, %d items", rep, a.Status, a.Priority, b.Status, len(l.Items))
	}
	if rep := l.syncNoise(noise, t0.Add(2*time.Hour)); rep.Reclassified != 0 {
		t.Errorf("reclassified twice: %+v", rep)
	}
}

// used_in follows the latest finished local-secrets run: a working file it inspected and no longer
// found the secret in leaves used_in, the priority and path rules; history copies stay, a run that
// skipped the files keeps the location, and a sighting there again brings it back. A run that
// could not read one file keeps the locations there, and only there.
func TestUsedInShrinksWhenAWorkingFileNoLongerHoldsTheSecret(t *testing.T) {
	out := t.TempDir()
	const fp = "c7c7c7c7c7c7c7c7"
	env := secretrisk.Evidence{Fingerprint: fp, Type: "stripe-live", Redacted: "sk_live_…(32)", Path: "~/src/shop/.env", Source: "scan",
		Kind: "repo", Mode: "644", Tracked: true, Remote: true, Bucket: "b", Count: 1}
	old := env
	old.Path, old.Tracked, old.Remote = "~/src/old/.env", false, false
	git := env
	git.Path, git.Repo, git.Source, git.Date, git.Remote = "~/src/old/app.py", "~/src/old", "gitleaks", "2024-01-02", false
	day := func(n int) time.Time { return t0.AddDate(0, 0, n) }
	tr := New(t0)
	sync := func(n int, recs ...any) {
		t.Helper()
		writeRun(t, out, day(n), "local-secrets.jsonl", append(recs, okStatus(secretrisk.ConnectorName, "local"))...)
		syncOrDie(t, tr, out, day(n).Add(time.Hour))
	}
	sync(0, leak(env, day(0)), leak(old, day(0)), leak(git, day(0)))
	it := mustRotate(t, tr, fp[:8])
	if got := strings.Join(it.Secret.UsedIn, " "); got != "~/src/old/.env ~/src/shop/.env" {
		t.Fatalf("day 0 used_in %q", got)
	}
	if it.liesUnder("~/src/old") {
		t.Fatal("under ~/src/old while ~/src/shop/.env holds it")
	}
	if it.worst().Label != "git+remote" {
		t.Fatalf("day 0 worst %q", it.worst().Label)
	}

	// The shop's .env no longer holds it, the scan read the files: only ~/src/old is left.
	sync(1, leak(old, day(1)), leak(git, day(1)))
	if got := strings.Join(it.Secret.UsedIn, " "); got != "~/src/old/.env" {
		t.Errorf("day 1 used_in %q", got)
	}
	if len(it.Secret.Locations) != 3 {
		t.Errorf("locations dropped: %+v", it.Secret.Locations)
	}
	if !it.liesUnder("~/src/old") {
		t.Error("a path rule over ~/src/old does not cover it")
	}
	if it.worst().Label == "git+remote" {
		t.Errorf("exposure still from the gone pushed file: %s %s", it.Priority, it.worst().Label)
	}

	// A run that skipped the files proves nothing: ~/src/old/.env stays in used_in.
	writeRun(t, out, day(2), "local-secrets.jsonl", leak(git, day(2)), finding.Skipped{Scope: "files", Reason: "ripgrep failed"},
		okStatus(secretrisk.ConnectorName, "local"))
	syncOrDie(t, tr, out, day(2).Add(time.Hour))
	if got := strings.Join(it.Secret.UsedIn, " "); got != "~/src/old/.env" {
		t.Errorf("day 2 (files skipped) used_in %q", got)
	}

	// Found in the shop's .env again: back in used_in.
	sync(3, leak(env, day(3)), leak(old, day(3)), leak(git, day(3)))
	if got := strings.Join(it.Secret.UsedIn, " "); got != "~/src/old/.env ~/src/shop/.env" {
		t.Errorf("day 3 used_in %q", got)
	}

	// A run that could not read the shop's .env, or the directory holding it, read the rest of the
	// files: the shop's .env stays in used_in and its finding is not gone.
	for n, unreadable := range []string{"~/src/shop/.env", "~/src/shop"} {
		writeRun(t, out, day(4+n), "local-secrets.jsonl", leak(old, day(4+n)), leak(git, day(4+n)),
			finding.Skipped{Scope: finding.PathScope("files", unreadable), Reason: finding.UnreadableReason}, okStatus(secretrisk.ConnectorName, "local"))
		syncOrDie(t, tr, out, day(4+n).Add(time.Hour))
		if got := strings.Join(it.Secret.UsedIn, " "); got != "~/src/old/.env ~/src/shop/.env" {
			t.Errorf("%s unreadable: used_in %q", unreadable, got)
		}
		for _, r := range it.Findings {
			if r.Path == env.Path && r.Gone {
				t.Errorf("%s unreadable: the shop's .env finding is gone", unreadable)
			}
		}
	}
}

// A credential no provider is known for, such as an internal service's bearer token, is rotated
// where it is accepted; a known provider without a rotation page, in its console.
func TestRotateWhereNamesNoProviderWhereNoneIsKnown(t *testing.T) {
	for _, c := range []struct {
		s    Secret
		want string
	}{
		{Secret{Service: "stripe", RotateURL: "https://dashboard.stripe.com/apikeys"}, "at https://dashboard.stripe.com/apikeys"},
		{Secret{Service: "sendgrid"}, "in the provider's console"},
		{Secret{Service: "unknown"}, "in the service that accepts it (segurata cannot tell which: see what uses it where it was found)"},
		{Secret{}, "in the service that accepts it (segurata cannot tell which: see what uses it where it was found)"},
	} {
		if got := c.s.RotateWhere(); got != c.want {
			t.Errorf("%+v: %q", c.s, got)
		}
	}
	it := &Item{Secret: &Secret{ID: "70d908b3", Service: "unknown", Type: "curl-auth-header", Redacted: "…(12)"}}
	it.secretTitleAndNext()
	if !strings.HasPrefix(it.Next.Action, "Rotate it in the service that accepts it") || strings.Contains(it.Next.Action, "provider") {
		t.Errorf("next %q", it.Next.Action)
	}
}
