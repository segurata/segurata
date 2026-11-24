package macos

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

type tmDest struct{ id, name, kind string }

// tmInfo renders `tmutil destinationinfo -X`.
func tmInfo(ds ...tmDest) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>`)
	if len(ds) > 0 {
		b.WriteString("<key>Destinations</key><array>")
		for _, d := range ds {
			fmt.Fprintf(&b, "<dict><key>ID</key><string>%s</string><key>Kind</key><string>%s</string><key>Name</key><string>%s</string><key>LastDestination</key><integer>1</integer></dict>", d.id, d.kind, d.name)
		}
		b.WriteString("</array>")
	}
	b.WriteString("</dict></plist>\n")
	return b.String()
}

type tmPref struct {
	id, state, keychain string
	snapshots           []string
}

// tmPrefsXML renders /Library/Preferences/com.apple.TimeMachine.plist through plutil -convert xml1.
func tmPrefsXML(ps ...tmPref) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>AutoBackup</key><true/><key>Destinations</key><array>`)
	for _, p := range ps {
		fmt.Fprintf(&b, "<dict><key>DestinationID</key><string>%s</string><key>BackupAlias</key><data>\n\tAAAA\n\t</data>", p.id)
		if p.state != "" {
			fmt.Fprintf(&b, "<key>LastKnownEncryptionState</key><string>%s</string>", p.state)
		}
		if p.keychain != "" {
			fmt.Fprintf(&b, "<key>DiskImageKeychainUUID</key><string>%s</string>", p.keychain)
		}
		if len(p.snapshots) > 0 {
			b.WriteString("<key>SnapshotDates</key><array>")
			for _, s := range p.snapshots {
				fmt.Fprintf(&b, "<date>%s</date>", s)
			}
			b.WriteString("</array>")
		}
		b.WriteString("</dict>")
	}
	b.WriteString("</array><key>PreferencesVersion</key><integer>5</integer></dict></plist>\n")
	return b.String()
}

func TestParsePlistDecodesEveryType(t *testing.T) {
	m, err := plistDict([]byte(`<?xml version="1.0"?><plist version="1.0"><dict>
<key>s</key><string> a b </string><key>i</key><integer>-3</integer><key>r</key><real>1.5</real>
<key>t</key><true/><key>f</key><false/><key>d</key><date>2026-11-20T10:00:00Z</date>
<key>b</key><data>aGk=</data><key>a</key><array><string>x</string><dict/></array><key>e</key><dict></dict>
</dict></plist>`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"s": "a b", "i": "-3", "r": "1.5", "t": "true", "f": "false",
		"d": "2026-11-20 10:00:00 +0000 UTC", "b": "[104 105]", "a": "[x map[]]", "e": "map[]"}
	for k, w := range want {
		if got := fmt.Sprint(m[k]); got != w {
			t.Errorf("%s = %q, want %q", k, got, w)
		}
	}
	if m, err := plistDict([]byte(" \n")); err != nil || len(m) != 0 {
		t.Errorf("empty: %v %v", m, err)
	}
	for _, bad := range []string{`<plist><array/></plist>`, `<plist><dict><key>x</key>`, `<plist><dict><key>i</key><integer>x</integer></dict></plist>`} {
		if _, err := plistDict([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func backupReplies(info, prefs, latest string) map[string]string {
	r := healthy()
	r[strings.Join(tmDestinations, " ")] = info
	r[strings.Join(tmPrefs, " ")] = prefs
	r[strings.Join(tmLatest, " ")] = latest
	return r
}

func TestBackupChecksGradeTimeMachine(t *testing.T) {
	cases := []struct {
		name    string
		replies map[string]string
		want    map[string]finding.Severity // resource id → severity; every other backup id is absent
	}{
		{"healthy", healthy(), nil},
		{"none configured (empty plist)", backupReplies(tmInfo(), tmPrefsXML(), "Failed to mount backup destination, error: Code=17"),
			map[string]finding.Severity{"backup-none": finding.SevHigh}},
		{"none configured (text)", backupReplies("tmutil: No destinations configured.", "", ""),
			map[string]finding.Severity{"backup-none": finding.SevHigh}},
		{"old and unencrypted", backupReplies(tmInfo(tmDest{"D1", "Old Disk", "Local"}), tmPrefsXML(tmPref{id: "D1", state: "NotEncrypted"}),
			"/Volumes/Old Disk/Backups.backupdb/Mac/2026-11-01-080000"),
			map[string]finding.Severity{"backup-unencrypted:D1": finding.SevHigh, "backup-age": finding.SevMedium}},
		{"network backup with keychain is encrypted; date from preferences", backupReplies(tmInfo(tmDest{"N1", "NAS", "Network"}),
			tmPrefsXML(tmPref{id: "N1", keychain: "K-1", snapshots: []string{"2026-11-01T08:00:00Z", "2026-11-23T08:00:00Z"}}),
			"Failed to mount backup destination"), nil},
		{"never completed", backupReplies(tmInfo(tmDest{"D1", "New Disk", "Local"}), tmPrefsXML(tmPref{id: "D1", state: "Encrypted"}), ""),
			map[string]finding.Severity{"backup-age": finding.SevHigh}},
		{"encryption unknown is not a finding", backupReplies(tmInfo(tmDest{"D1", "Disk", "Local"}), "",
			"/Volumes/Disk/2026-11-23-080000.backup"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := newTest(t, tc.replies)
			rec := inventory(t, c)
			got := map[string]finding.Severity{}
			for _, f := range rec.Findings {
				if strings.HasPrefix(f.Resource.ID, "backup-") {
					got[f.Resource.ID] = f.Severity
					if f.Remediation.Summary == "" || !strings.Contains(f.Remediation.Summary, "System Settings") {
						t.Errorf("%s remediation %q", f.Resource.ID, f.Remediation.Summary)
					}
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBackupAgeEvidence(t *testing.T) {
	c, _, _ := newTest(t, backupReplies(tmInfo(tmDest{"D1", "Old Disk", "Local"}), tmPrefsXML(tmPref{id: "D1", state: "Encrypted"}),
		"/Volumes/Old Disk/Backups.backupdb/Mac/2026-11-01-080000"))
	f := inventory(t, c).ByResource(t, "macos_setting", "backup-age")
	if f.Evidence["age_days"] != 23 || !strings.Contains(f.Title, "23 days") || fmt.Sprint(f.Evidence["destinations"]) != "[Old Disk]" {
		t.Errorf("%q %v", f.Title, f.Evidence)
	}
	if _, err := time.Parse(time.RFC3339, f.Evidence["latest_backup"].(string)); err != nil {
		t.Error(err)
	}
}

func TestUnreadableTimeMachineIsSkipped(t *testing.T) {
	c, _, _ := newTest(t, backupReplies("tmutil: destinationinfo: Operation not permitted", "", ""))
	rec := inventory(t, c)
	for _, s := range rec.Statuses {
		if strings.HasPrefix(s.Detail, "backup-none:") {
			if !strings.Contains(s.Detail, "Full Disk Access") {
				t.Errorf("no Full Disk Access hint: %s", s.Detail)
			}
			return
		}
	}
	t.Fatalf("not skipped: %v", rec.Statuses)
}
