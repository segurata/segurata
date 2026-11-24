package tracker

import (
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/doc"
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
	}, t0, false)
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

	l.SyncSecrets([]Sighting{sight(ev("cccccccccccccccc", "assignment", "~/.env", "scan", "config", "600", false, false))}, t0, true)
	if c, err := l.FindRotate("cccc"); err != nil || c.Priority != "" {
		t.Errorf("--include-noise item: %+v %v", c, err)
	}
}

func TestDoneButStillPresentReopens(t *testing.T) {
	l := &Tracker{NextID: 1}
	in := []Sighting{sight(ev("aaaaaaaaaaaaaaaa", "github", "~/.netrc", "scan", "config", "600", false, false))}
	l.SyncSecrets(in, t0, false)
	it, _ := l.FindRotate("aaaa")
	it.Done(t0.Add(time.Hour), "new token in the Keychain")
	if it.Status != Done {
		t.Fatal("not rotated")
	}
	rep := l.SyncSecrets(in, t0.Add(24*time.Hour), false)
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
	l.SyncSecrets([]Sighting{rc, transcript, gitHistory}, t0, false)
	it, _ := l.FindRotate("aaaa")
	it.Done(t0.Add(time.Hour), "")
	if strings.Join(it.Secret.RotatedLocations, ",") != "gitleaks:~/src/app/config.yml,scan:~/.claude/projects/p/s.jsonl,scan:~/.zshrc" {
		t.Fatalf("rotated locations %v", it.Secret.RotatedLocations)
	}

	// The rc file was fixed; the transcript and git history still hold the dead value, and a new
	// log copy appeared.
	log := sight(ev("aaaaaaaaaaaaaaaa", "github", "~/src/app/log/dev.log", "scan", "log", "600", false, false))
	for day := 1; day <= 3; day++ {
		rep := l.SyncSecrets([]Sighting{transcript, gitHistory, log}, t0.Add(time.Duration(day)*24*time.Hour), false)
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
			if e.Detail != HistoryOnly {
				t.Errorf("note %q", e.Detail)
			}
		}
	}
	if notes != 1 || len(it.Secret.Locations) != 4 {
		t.Errorf("want one note and four locations: %d %+v", notes, it.Secret.Locations)
	}

	// A second rotation gets its own note.
	it.Reopen(t0.Add(5*24*time.Hour), "")
	it.Done(t0.Add(5*24*time.Hour), "rotated again")
	if rep := l.SyncSecrets([]Sighting{transcript}, t0.Add(6*24*time.Hour), false); rep.HistoryOnly != 1 || it.Status != Done {
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
			}, t0, false)
			it, _ := l.FindRotate("aaaa")
			it.Done(t0.Add(time.Hour), "")
			rep := l.SyncSecrets(tc.see, t0.Add(24*time.Hour), false)
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
	l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "xai", "~/.zshrc", "scan", "config", "600", false, false))}, t0, false)
	l.SyncSecrets([]Sighting{sight(ev("bbbbbbbbbbbbbbbb", "xai", "~/.zshrc", "scan", "config", "600", false, false))}, t0.Add(72*time.Hour), false)
	a, _ := l.FindRotate("aaaa")
	b, _ := l.FindRotate("bbbb")
	if !a.Secret.LastSeen.Equal(t0) || !b.Secret.LastSeen.Equal(t0.Add(72*time.Hour)) || len(l.Items) != 2 {
		t.Errorf("last seen %v %v", a.Secret.LastSeen, b.Secret.LastSeen)
	}
}

func TestSnoozeExpires(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "notion", "~/.mcp/x.json", "scan", "config", "600", false, false))}, t0, false)
	it, _ := l.FindRotate("aaaa")
	if err := it.Snooze(t0, "2026-11-20", ""); err == nil {
		t.Error("snooze into the past accepted")
	}
	if err := it.Snooze(t0, "next week", ""); err == nil {
		t.Error("bad date accepted")
	}
	if err := it.Snooze(t0, "2026-12-01", "after the release"); err != nil {
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
	if err := it.Ignore(t0, " "); err == nil {
		t.Error("ignore without a reason")
	}
}

func TestIDsGrowOnCollision(t *testing.T) {
	l := &Tracker{NextID: 1}
	l.SyncSecrets([]Sighting{
		sight(ev("abcdef0123456789", "github", "~/a", "scan", "config", "600", false, false)),
		sight(ev("abcdef0199999999", "github", "~/b", "scan", "config", "600", false, false)),
	}, t0, false)
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
		sight(ev("3333333333333333", "aws-access-key-id", "~/c", "gitleaks", "repo", "", true, true)),     // P0
		sight(ev("4444444444444444", "openai-project", "~/d", "scan", "transcript", "600", false, false)), // P1 transcript
		sight(ev("5555555555555555", "sentry-dsn", "~/e", "scan", "config", "600", false, false)),         // P3
	}, t0, false)
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

// A rule fix that lowers a secret's impact must reach existing items on the next sync.
func TestSyncLowersImpactWhenTheCurrentSightingIsLess(t *testing.T) {
	l := &Tracker{NextID: 1}
	high := ev("aaaaaaaaaaaaaaaa", "aws-access-key-id", "~/src/r/data.json", "gitleaks", "repo", "", true, true)
	high.Redacted = "AKIA…(20)"
	l.SyncSecrets([]Sighting{sight(high)}, t0, false)
	if p := l.Items[0].Priority; p != "P0" {
		t.Fatalf("pushed long-lived AWS key should be P0, got %s", p)
	}
	temp := high
	temp.Redacted = "ASIA…(20)"
	l.SyncSecrets([]Sighting{sight(temp)}, t0.Add(time.Hour), false)
	if it := l.Items[0]; it.Secret.Impact != "low" || it.Priority == "P0" {
		t.Fatalf("the same item seen as a temporary credential must drop: impact=%s priority=%s", it.Secret.Impact, it.Priority)
	}
}

// A corrected rule turns a tracked secret into noise: its item is updated, not left behind.
func TestASecretNowNoiseIsReclassified(t *testing.T) {
	l := &Tracker{NextID: 1}
	real := []Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "anthropic", "~/.zshrc", "scan", "config", "644", false, false)),
		sight(ev("bbbbbbbbbbbbbbbb", "anthropic", "~/src/log/test.log", "scan", "log", "644", false, false)),
	}
	l.SyncSecrets(real, t0, false)
	open, _ := l.FindRotate("aaaa")
	ignored, _ := l.FindRotate("bbbb")
	if err := ignored.Ignore(t0, "test suite fixtures in a gitignored Rails test log"); err != nil {
		t.Fatal(err)
	}
	noise := []Sighting{
		sight(ev("aaaaaaaaaaaaaaaa", "assignment", "~/.zshrc", "scan", "config", "644", false, false)),
		sight(ev("bbbbbbbbbbbbbbbb", "assignment", "~/src/log/test.log", "scan", "log", "644", false, false)),
	}
	rep := l.SyncSecrets(noise, t0.Add(time.Hour), false)
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
	if err := doc.Render(&b, l.Status("tracker.json", t0.Add(time.Hour), Filter{}), doc.Text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "ignored 0, reclassified as noise 2") {
		t.Errorf("headline:\n%s", b.String())
	}
	// Seen again as noise: nothing changes.
	if rep := l.SyncSecrets(noise, t0.Add(2*time.Hour), false); rep.Reclassified != 0 || len(open.History) != 2 {
		t.Errorf("second noise sync %+v, history %+v", rep, open.History)
	}
	// The rule changes back: the open one reopens, the ignored one is ignored again with its reason.
	rep = l.SyncSecrets(real, t0.Add(3*time.Hour), false)
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
	l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "anthropic", "~/.zshrc", "scan", "config", "644", false, false))}, t0, false)
	it, _ := l.FindRotate("aaaa")
	it.Done(t0, "rotated")
	rep := l.SyncSecrets([]Sighting{sight(ev("aaaaaaaaaaaaaaaa", "assignment", "~/.zshrc", "scan", "config", "644", false, false))}, t0.Add(time.Hour), false)
	if rep.Reclassified != 0 || it.Status != Done || it.Secret.Impact != "noise" {
		t.Errorf("%+v %s %s", rep, it.Status, it.Secret.Impact)
	}
}
