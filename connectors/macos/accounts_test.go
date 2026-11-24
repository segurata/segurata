package macos

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/finding"
)

// The owner's Mac had a technician account; these are its synthetic traces.
func accountReplies() map[string]string {
	r := healthy()
	r[strings.Join(listUIDs, " ")] = "root 0\nnobody -2\n_sophos 502\nalice 501\nrepairtech 503\ntemp 504\nghost 505\nbad;name 506\n"
	r[strings.Join(listHomes, " ")] = "root /var/root\nalice /Users/alice\nrepairtech /Users/repairtech\ntemp /Users/temp\nghost /Users/ghost dir\n"
	r[strings.Join(adminArgv("repairtech"), " ")] = "yes repairtech is a member of admin"
	r[strings.Join(adminArgv("temp"), " ")] = "no temp is NOT a member of admin"
	r[strings.Join(adminArgv("ghost"), " ")] = "no ghost is NOT a member of admin"
	r[strings.Join(lastArgv("repairtech"), " ")] = "repairtech  console                   mié 12 feb 10:01 - 18:22  (08:21)\n\nwtmp begins lunes, 20 de octubre de 2025, 10:38:56 CEST\n"
	r[strings.Join(lastArgv("temp"), " ")] = "temp  ttys000  192.168.1.9  lun 23 nov 09:00   still logged in\n\nwtmp begins lunes, 20 de octubre de 2025\n"
	r[strings.Join(lastArgv("ghost"), " ")] = "\nwtmp begins lunes, 20 de octubre de 2025, 10:38:56 CEST\n"
	return r
}

func TestAccountChecksReportEveryOtherHumanAccount(t *testing.T) {
	c, fr, _ := newTest(t, accountReplies())
	for _, u := range []string{"repairtech", "temp"} {
		if err := os.MkdirAll(filepath.Join(c.Root, "Users", u), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rec := inventory(t, c)
	want := map[string]struct {
		sev   finding.Severity
		title string
	}{
		"repairtech": {finding.SevHigh, `Administrator account "repairtech" exists besides yours (last login mié 12 feb 10:01 - 18:22 (08:21))`},
		"temp":        {finding.SevMedium, `Local account "temp" exists besides yours (last login 192.168.1.9 lun 23 nov 09:00 still logged in)`},
		"ghost":       {finding.SevLow, `Local account "ghost" exists besides yours (no home folder, no login since lunes, 20 de octubre de 2025, 10:38:56 CEST)`},
	}
	for u, w := range want {
		f := rec.ByResource(t, "local_account", "account:"+u)
		if f.Severity != w.sev || f.Title != w.title || !strings.Contains(f.Remediation.Summary, "standard (not administrator) account") {
			t.Errorf("%s: %s %q", u, f.Severity, f.Title)
		}
	}
	ghost := rec.ByResource(t, "local_account", "account:ghost")
	if ghost.Evidence["home"] != "/Users/ghost dir" || ghost.Evidence["home_exists"] != false || ghost.Evidence["admin"] != false {
		t.Errorf("ghost evidence %v", ghost.Evidence)
	}
	for _, f := range rec.Findings {
		if f.Resource.Type == "local_account" && strings.ContainsAny(f.Resource.ID, ";") || f.Resource.ID == "account:alice" || f.Resource.ID == "account:_sophos" {
			t.Errorf("reported %s", f.Resource.ID)
		}
	}
	for _, call := range fr.calls {
		if strings.Contains(call, "bad;name") || strings.Contains(call, " alice") {
			t.Errorf("ran %q", call)
		}
	}
}

func TestAccountGuardOnlyAllowsListedAccounts(t *testing.T) {
	c, _, _ := newTest(t, accountReplies())
	if _, err := guard(c.Run).Run(context.Background(), adminArgv("repairtech")...); !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("fixed guard allowed a per-account command: %v", err)
	}
	if _, err := guardWith(c.Run, lastArgv("temp")).Run(context.Background(), lastArgv("root")...); !errors.Is(err, cli.ErrRefused) {
		t.Fatalf("guard allowed an account it was not given: %v", err)
	}
}

func TestDsclFailureSkipsAccountChecks(t *testing.T) {
	r := healthy()
	delete(r, strings.Join(listUIDs, " "))
	c, _, _ := newTest(t, r)
	rec := inventory(t, c)
	found := false
	for _, s := range rec.Statuses {
		found = found || strings.HasPrefix(s.Detail, "local-accounts: dscl could not list local users")
	}
	if !found {
		t.Fatalf("statuses %v", rec.Statuses)
	}
}

func TestParseLast(t *testing.T) {
	cases := map[string]string{
		"bob  ttys002   lun 23 nov 22:33 - 22:33  (00:00)\n\nwtmp begins x\n": "last login lun 23 nov 22:33 - 22:33 (00:00)",
		"\nwtmp begins lunes, 20 de octubre\n":                                "no login since lunes, 20 de octubre",
		"":                                                                    "no recorded login",
	}
	for in, want := range cases {
		if got := parseLast(in).String(); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// withOwners makes fileUID answer from a map by base name; other files belong to 501.
func withOwners(t *testing.T, owners map[string]uint32) {
	t.Helper()
	old := fileUID
	fileUID = func(fi fs.FileInfo) (uint32, bool) {
		if uid, ok := owners[fi.Name()]; ok {
			return uid, true
		}
		return 501, true
	}
	t.Cleanup(func() { fileUID = old })
}

func touch(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOrphanedFilesAreReportedPerFolder(t *testing.T) {
	c, _, _ := newTest(t, accountReplies())
	touch(t, c.Root,
		"Users/Shared/notes.txt",              // 503 is repairtech, who still exists here
		"Users/Shared/tech/report.pdf",        // 777: gone
		"Users/Shared/tech/deep/too-deep.pdf", // below depth 2: not read
		"Library/LaunchDaemons/com.tech.helper.plist",
		"Library/LaunchAgents/com.vendor.agent.plist",
		"Library/Application Support/ESET/Security/cache", // 404: a removed service account
		"Library/Application Support/Tech/data.db",
	)
	withOwners(t, map[string]uint32{"notes.txt": 503, "tech": 777, "report.pdf": 777, "too-deep.pdf": 777,
		"com.tech.helper.plist": 404, "Security": 0, "cache": 404, "Tech": 4294967294, "data.db": 888})
	rec := inventory(t, c)

	shared := rec.ByResource(t, "orphaned_files", "unknown-owner:/Users/Shared")
	if shared.Severity != finding.SevLow || fmt.Sprint(shared.Evidence["paths"]) != "[/Users/Shared/tech /Users/Shared/tech/report.pdf]" ||
		fmt.Sprint(shared.Evidence["uids"]) != "[777]" {
		t.Errorf("shared: %s %v", shared.Severity, shared.Evidence)
	}
	daemons := rec.ByResource(t, "orphaned_files", "unknown-owner:/Library/LaunchDaemons")
	if daemons.Severity != finding.SevHigh || !strings.Contains(daemons.Title, "start automatically") ||
		fmt.Sprint(daemons.Evidence["paths"]) != "[/Library/LaunchDaemons/com.tech.helper.plist]" {
		t.Errorf("daemons: %s %q %v", daemons.Severity, daemons.Title, daemons.Evidence)
	}
	support := rec.ByResource(t, "orphaned_files", "unknown-owner:/Library/Application Support")
	if fmt.Sprint(support.Evidence["paths"]) != "[/Library/Application Support/Tech/data.db]" {
		t.Errorf("support: the ESET service UID or nobody leaked in: %v", support.Evidence)
	}
	for _, f := range rec.Findings {
		if f.Resource.ID == "unknown-owner:/Library/LaunchAgents" {
			t.Errorf("reported LaunchAgents owned by known accounts")
		}
	}
}

func TestOrphanListIsCapped(t *testing.T) {
	byUID := map[uint32][]string{}
	for i := range maxListed + 5 {
		byUID[900] = append(byUID[900], fmt.Sprintf("/Users/Shared/f%02d", i))
	}
	ch := orphanCheck(ownerRoots[0], byUID)
	if ch.evidence["count"] != maxListed+5 || len(ch.evidence["paths"].([]string)) != maxListed {
		t.Errorf("%v", ch.evidence)
	}
}

func TestOrphanedShareNamesTheDeletedAccount(t *testing.T) {
	ch := shareCheck(sharePoint{Name: quotedName, Path: "/Users/segurata-test-deleted/Public", Shared: 1, Guest: 1})
	if ch.evidence["deleted_account"] != "segurata-test-deleted" || !strings.Contains(ch.detail, "was deleted") {
		t.Errorf("%q %v", ch.detail, ch.evidence)
	}
	if deletedAccount("/Users/Shared/x") != "" || deletedAccount("/Volumes/x") != "" {
		t.Error("named a deleted account for a path outside a home folder")
	}
}
