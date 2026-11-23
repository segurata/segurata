package macos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/remediate"
)

// sharingKey is how fakeRunner spells the share point listing.
var sharingKey = strings.Join(listShares, " ")

// sharesJSON renders share points the way `sharing -l -f json` prints them.
func sharesJSON(sps ...sharePoint) string {
	m := map[string]sharePoint{}
	for _, sp := range sps {
		m[sp.Name] = sp
	}
	raw, _ := json.Marshal(m)
	return string(raw)
}

// The record name the owner's Mac really has: spaces and Unicode quotes in one argument.
const quotedName = "Carpeta pública de “Pablo Macypc”"

func shareFinding(action, name string) finding.Finding {
	return finding.Finding{Connector: "macos", Evidence: map[string]any{"name": name},
		Remediation: finding.Remediation{Action: action}}
}

func TestParseSharePointsReadsTheJSONListing(t *testing.T) {
	raw := `{
  "Carpeta pública de “Pablo Macypc”" : {
    "path" : "\/Users\/repairtech\/Public",
    "smb_guest_access" : 1,
    "smb_name" : "Carpeta pública de “Pablo Macypc”",
    "smb_read_only" : 0,
    "smb_sealed" : 0,
    "smb_shared" : 1
  }
}`
	shares, err := parseSharePoints([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	sp := shares[quotedName]
	if sp.Name != quotedName || sp.Path != "/Users/repairtech/Public" || sp.Guest != 1 || sp.Shared != 1 || sp.SMBName != quotedName {
		t.Fatalf("parsed %+v", shares)
	}
	if shares, err := parseSharePoints([]byte("\n")); err != nil || len(shares) != 0 {
		t.Fatalf("empty listing: %v %v", shares, err)
	}
	if _, err := parseSharePoints([]byte("List of Share Points")); err == nil {
		t.Fatal("text output accepted as JSON")
	}
}

func TestShareChecksGradeEachSharePoint(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		sp     sharePoint
		id     string
		sev    finding.Severity
		action string
		title  string
	}{
		{sharePoint{Name: "Gone", Path: "/nonexistent/gone", Shared: 1}, "smb-share:Gone", finding.SevHigh, ActionShareRemove, "Orphaned"},
		{sharePoint{Name: "Open", Path: dir, Shared: 1, Guest: 1}, "smb-share-guest:Open", finding.SevHigh, ActionShareGuestOff, "allows guests"},
		{sharePoint{Name: "Team", Path: dir, Shared: 1}, "smb-share:Team", finding.SevMedium, ActionShareRemove, "is shared over SMB"},
		{sharePoint{Name: "Idle", Path: dir}, "smb-share:Idle", finding.SevInfo, ActionShareRemove, "not shared"},
	}
	for _, c := range cases {
		ch := shareCheck(c.sp)
		if ch.id != c.id || ch.resource != "share_point" || ch.sev != c.sev || ch.rem.Action != c.action || !strings.Contains(ch.title, c.title) {
			t.Errorf("%s: id %q sev %s action %q title %q", c.sp.Name, ch.id, ch.sev, ch.rem.Action, ch.title)
		}
		for _, k := range []string{"name", "path", "path_exists", "guest", "read_only"} {
			if _, ok := ch.evidence[k]; !ok {
				t.Errorf("%s: evidence lacks %s", c.sp.Name, k)
			}
		}
	}
}

func TestPortStaysManualWhenNoSharePointsRemain(t *testing.T) {
	r := exposed()
	r[sharingKey] = "{}"
	c, _, _ := newTest(t, r)
	rec := inventory(t, c)
	port := rec.ByResource(t, "listening_port", "listen-445")
	if port.Remediation.Action != "" || !strings.Contains(port.Title, "no shared folders") || !strings.Contains(port.Remediation.Summary, "File Sharing") {
		t.Fatalf("port 445 with no shares: %q %+v", port.Title, port.Remediation)
	}
	for _, f := range rec.Findings {
		if f.Resource.Type == "share_point" {
			t.Errorf("share point reported with none listed: %s", f.Resource.ID)
		}
	}
}

func TestShareRemovePlanComesFromAFreshRead(t *testing.T) {
	r := healthy()
	r[sharingKey] = sharesJSON(sharePoint{Name: quotedName, Path: "/nonexistent/repairtech/Public", SMBName: quotedName, Shared: 1, Guest: 1})
	c, _, ex := newTest(t, r)
	f := shareFinding(ActionShareRemove, quotedName)
	p, err := c.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := connector.Step{Argv: []string{sharingBin, "-r", quotedName}, Sudo: true}
	if len(p.Commands) != 1 || !p.Commands[0].Equal(want) {
		t.Fatalf("commands %v", p.Commands)
	}
	if got := p.Commands[0].String(); got != "sudo /usr/sbin/sharing -r 'Carpeta pública de “Pablo Macypc”'" {
		t.Errorf("shown as %s", got)
	}
	if len(p.Undo) != 0 || !strings.Contains(strings.Join(p.SideEffects, "\n"), "Undo: not applicable: the folder /nonexistent/repairtech/Public no longer exists") {
		t.Errorf("orphan undo %v side effects %v", p.Undo, p.SideEffects)
	}
	if err := c.Apply(context.Background(), f, p, termIO()); err != nil {
		t.Fatal(err)
	}
	// The name reaches the executor as one argument, quotes and spaces intact, never via a shell.
	if len(ex.ran) != 1 || len(ex.ran[0].Argv) != 3 || ex.ran[0].Argv[2] != quotedName || !ex.ran[0].Sudo {
		t.Fatalf("ran %#v", ex.ran)
	}
}

func TestShareRemoveUndoRecreatesALiveShare(t *testing.T) {
	dir := t.TempDir()
	r := healthy()
	r[sharingKey] = sharesJSON(sharePoint{Name: "Team files", Path: dir, SMBName: "Team", Shared: 1, ReadOnly: 1})
	c, _, _ := newTest(t, r)
	p, err := c.Plan(context.Background(), shareFinding(ActionShareRemove, "Team files"))
	if err != nil {
		t.Fatal(err)
	}
	want := connector.Step{Argv: []string{sharingBin, "-a", dir, "-n", "Team files", "-S", "Team", "-s", "001", "-g", "000", "-R", "1"}, Sudo: true}
	if len(p.Undo) != 1 || !p.Undo[0].Equal(want) {
		t.Fatalf("undo %v", p.Undo)
	}
}

func TestGuestOffPlanAndUndo(t *testing.T) {
	r := healthy()
	r[sharingKey] = sharesJSON(sharePoint{Name: quotedName, Path: t.TempDir(), SMBName: quotedName, Shared: 1, Guest: 1})
	c, _, ex := newTest(t, r)
	f := shareFinding(ActionShareGuestOff, quotedName)
	p, err := c.Plan(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if got := stepStrings(p.Commands); fmt.Sprint(got) != fmt.Sprint([]string{"sudo /usr/sbin/sharing -e 'Carpeta pública de “Pablo Macypc”' -g 000"}) {
		t.Errorf("commands %q", got)
	}
	if got := stepStrings(p.Undo); fmt.Sprint(got) != fmt.Sprint([]string{"sudo /usr/sbin/sharing -e 'Carpeta pública de “Pablo Macypc”' -g 001"}) {
		t.Errorf("undo %q", got)
	}
	if err := c.Apply(context.Background(), f, p, termIO()); err != nil || len(ex.ran) != 1 {
		t.Fatalf("apply: %v ran %v", err, ex.ran)
	}

	r[sharingKey] = sharesJSON(sharePoint{Name: quotedName, Path: t.TempDir(), Shared: 1})
	if _, err := c.Plan(context.Background(), f); err == nil || !strings.Contains(err.Error(), "already") {
		t.Fatalf("guest-off planned on a share without guest access: %v", err)
	}
}

func TestShareActionsRefuseANameThatNoLongerExists(t *testing.T) {
	r := healthy()
	r[sharingKey] = sharesJSON(sharePoint{Name: "Other", Path: "/nonexistent", Shared: 1})
	c, _, ex := newTest(t, r)
	for _, action := range []string{ActionShareRemove, ActionShareGuestOff} {
		for _, name := range []string{quotedName, "", "other", "Other "} {
			if _, err := c.Plan(context.Background(), shareFinding(action, name)); err == nil || !strings.Contains(err.Error(), "refusing") {
				t.Errorf("%s %q: planned (%v)", action, name, err)
			}
		}
	}
	// A plan built for a share that was there when shown, but is gone at apply time, is refused.
	stale := connector.Plan{Action: ActionShareRemove, Commands: []connector.Step{{Argv: []string{sharingBin, "-r", quotedName}, Sudo: true}}}
	if err := c.Apply(context.Background(), shareFinding(ActionShareRemove, quotedName), stale, termIO()); err == nil || len(ex.ran) != 0 {
		t.Fatalf("applied a stale plan: %v %v", err, ex.ran)
	}
	// The apply-time allowlist only knows the share points that exist now, whatever the plan says.
	allow, err := c.shareAllowlist(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := remediate.Run(context.Background(), stale, allow, ex, termIO()); !errors.Is(err, remediate.ErrRefused) || len(ex.ran) != 0 {
		t.Fatalf("allowlist let a missing share through: %v", err)
	}
	if err := allow.Check(ActionShareRemove, connector.Step{Argv: []string{sharingBin, "-r", "Other"}, Sudo: true}); err != nil {
		t.Fatalf("existing share refused: %v", err)
	}
	if err := allow.Check(ActionShareGuestOff, connector.Step{Argv: []string{sharingBin, "-r", "Other"}, Sudo: true}); err == nil {
		t.Fatal("share-remove command allowed under guest-off")
	}
}
