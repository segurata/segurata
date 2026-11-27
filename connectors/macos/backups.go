package macos

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

const (
	tmutilBin       = "/usr/bin/tmutil"
	timeMachinePref = "/Library/Preferences/com.apple.TimeMachine.plist"
)

var (
	tmDestinations = []string{tmutilBin, "destinationinfo", "-X"}
	tmLatest       = []string{tmutilBin, "latestbackup"}
	// Only the preferences hold encryption state and snapshot dates; tmutil prints neither.
	tmPrefs = []string{"/usr/bin/plutil", "-convert", "xml1", "-o", "-", timeMachinePref}
)

const maxBackupAge = 7 * 24 * time.Hour

const backupSettings = "System Settings > General > Time Machine"

type tmDestination struct {
	id, name, kind string
	encrypted      *bool     // nil when the preferences do not say
	last           time.Time // latest recorded snapshot; zero when none
}

const fullDiskAccessFix = "grant Full Disk Access to your terminal in System Settings > Privacy & Security > Full Disk Access"

func (c *Connector) destinationInfo(ctx context.Context) (map[string]any, error) {
	raw, err := c.read(ctx, tmDestinations...)
	out := strings.TrimSpace(string(raw))
	switch {
	case strings.Contains(out, "No destinations configured"):
		return map[string]any{}, nil
	case err != nil || !strings.HasPrefix(out, "<"):
		msg := "tmutil destinationinfo could not be read (" + orQ(firstLine(out)) + ")"
		if textfmt.ContainsAny(out, "Full Disk Access", "Operation not permitted") {
			msg += "; " + fullDiskAccessFix
		}
		return nil, errors.New(msg)
	}
	return plistDict(raw)
}

// backupChecks: without the preferences file a destination's encryption is unknown, not reported.
func (c *Connector) backupChecks(ctx context.Context) []check {
	none := check{ID: "backup-none", Sev: finding.SevHigh, Blast: finding.BlastDevice,
		Title: "No Time Machine backup is configured",
		Rem:   posture.Manual("Set up an encrypted backup disk in " + backupSettings + " > Add Backup Disk, with Encrypt Backup on. Keep a second, offsite copy too (3-2-1).")}
	info, err := c.destinationInfo(ctx)
	if err != nil {
		none.Skip = err.Error()
		return []check{none}
	}
	prefs, prefsErr := c.timeMachinePrefs(ctx)
	dests := joinDestinations(info, prefs)
	if len(dests) == 0 {
		none.Detail = "tmutil destinationinfo lists no destination"
		return []check{none}
	}
	none.OK, none.Detail = true, fmt.Sprintf("%d Time Machine destinations", len(dests))
	checks := []check{none}
	for _, d := range dests {
		checks = append(checks, encryptionCheck(d, prefsErr))
	}
	return append(checks, c.backupAgeCheck(ctx, dests))
}

// timeMachinePrefs may need Full Disk Access.
func (c *Connector) timeMachinePrefs(ctx context.Context) (map[string]any, error) {
	raw, err := c.read(ctx, tmPrefs...)
	if err != nil {
		return nil, err
	}
	return plistDict(raw)
}

func dicts(v any) []map[string]any {
	var out []map[string]any
	a, _ := v.([]any)
	for _, x := range a {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

// joinDestinations matches ID to DestinationID. A DiskImageKeychainUUID is an encrypted network
// backup.
func joinDestinations(info, prefs map[string]any) []tmDestination {
	byID := map[string]map[string]any{}
	for _, p := range dicts(prefs["Destinations"]) {
		byID[str(p, "DestinationID")] = p
	}
	var out []tmDestination
	for _, d := range dicts(info["Destinations"]) {
		td := tmDestination{id: str(d, "ID"), name: str(d, "Name"), kind: str(d, "Kind")}
		if td.name == "" {
			td.name = td.id
		}
		if p, ok := byID[td.id]; ok {
			state := str(p, "LastKnownEncryptionState")
			if state != "" || str(p, "DiskImageKeychainUUID") != "" {
				enc := state == "Encrypted" || str(p, "DiskImageKeychainUUID") != ""
				td.encrypted = &enc
			}
			td.last = latestSnapshot(p)
		}
		out = append(out, td)
	}
	return out
}

func latestSnapshot(p map[string]any) time.Time {
	var last time.Time
	dates, _ := p["SnapshotDates"].([]any)
	for _, v := range append(dates, p["ReferenceLocalSnapshotDate"]) {
		if t, ok := v.(time.Time); ok && t.After(last) {
			last = t
		}
	}
	return last
}

func encryptionCheck(d tmDestination, prefsErr error) check {
	ch := check{ID: "backup-unencrypted:" + d.id, Resource: "backup_destination", Name: d.name, Sev: finding.SevHigh,
		Evidence: map[string]any{"destination": d.name, "kind": d.kind},
		Title:    fmt.Sprintf("Time Machine destination %q is not encrypted: anyone holding the disk reads your files despite FileVault", d.name),
		Rem: posture.Manual("Encryption cannot be added to an existing backup since macOS 13: in " + backupSettings +
			", remove the destination, erase the disk, add it again with Set Up Disk > Encrypt Backup on, and keep or wipe the old backups.")}
	switch {
	case d.encrypted == nil:
		ch.OK, ch.Detail = true, fmt.Sprintf("%s (%s): encryption unknown, the Time Machine preferences do not say", d.name, d.kind)
		if prefsErr != nil {
			ch.Detail += fmt.Sprintf(" (%v)", prefsErr)
		}
	case *d.encrypted:
		ch.OK, ch.Detail = true, fmt.Sprintf("%s (%s) is encrypted", d.name, d.kind)
	default:
		ch.Detail = fmt.Sprintf("%s (%s): LastKnownEncryptionState is NotEncrypted", d.name, d.kind)
		ch.Evidence["encrypted"] = false
	}
	return ch
}

var backupStamp = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}-\d{6})`)

// backupAgeCheck dates the latest backup from the path `tmutil latestbackup` prints or, with the
// destination unmounted, from the preferences.
func (c *Connector) backupAgeCheck(ctx context.Context, dests []tmDestination) check {
	now := c.Now()
	ch := check{ID: "backup-age", Sev: finding.SevMedium,
		Rem: posture.Manual("Connect the backup disk and choose Back Up Now in " + backupSettings + "; leave it connected, or on the network, so backups run on their own.")}
	var last time.Time
	out, _ := c.text(ctx, tmLatest...)
	if m := backupStamp.FindStringSubmatch(out); m != nil {
		last, _ = time.ParseInLocation("2006-01-02-150405", m[1], now.Location())
	}
	for _, d := range dests {
		if d.last.After(last) {
			last = d.last
		}
	}
	names := make([]string, 0, len(dests))
	for _, d := range dests {
		names = append(names, d.name)
	}
	slices.Sort(names)
	where := strings.Join(names, ", ")
	if last.IsZero() {
		ch.Sev = finding.SevHigh
		ch.Title = "Time Machine is set up but has never completed a backup"
		ch.Detail = fmt.Sprintf("no backup found on %s (tmutil latestbackup: %s)", where, orQ(firstLine(out)))
		ch.Evidence = map[string]any{"destinations": names}
		return ch
	}
	age := now.Sub(last)
	days := int(age.Hours() / 24)
	ch.Detail = fmt.Sprintf("latest backup %s (%d days ago) on %s", last.Format("2006-01-02 15:04"), days, where)
	ch.Evidence = map[string]any{"latest_backup": last.Format(time.RFC3339), "age_days": days, "destinations": names}
	ch.OK = age <= maxBackupAge
	ch.Title = fmt.Sprintf("The latest Time Machine backup is %d days old", days)
	return ch
}
