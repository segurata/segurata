// Package secretrisk is the shared risk model for leaked secrets: what each type is, how much
// damage it can do (impact), how far a copy travelled (exposure), the resulting rotation priority
// and where the provider rotates it. Finding severity (local-secrets) and item priority (the
// rotation ledger) both come from here, so they always agree.
package secretrisk

import (
	"slices"
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// Impact is how much damage the secret can do in the wrong hands.
type Impact int

const (
	Noise Impact = iota // mostly false positives: excluded from rotation
	Low
	Medium
	High
)

func (i Impact) String() string {
	return [...]string{"noise", "low", "medium", "high"}[i]
}

// Exposure is how far a copy of the secret travelled.
type Exposure int

const (
	Local  Exposure = iota // a file only this user can read, shell history, a log
	Shared                 // readable by other users, or in a local repository's history
	Remote                 // pushed to a remote, or sent to a model provider in a transcript
)

// Priority is the rotation urgency, P0 (now) to P3 (when convenient); "" for noise.
type Priority string

const (
	P0 Priority = "P0"
	P1 Priority = "P1"
	P2 Priority = "P2"
	P3 Priority = "P3"
)

var priorities = map[Impact][3]Priority{
	//      Local Shared Remote
	Low:    {P3, P3, P2},
	Medium: {P3, P2, P1},
	High:   {P2, P1, P0},
}

// PriorityOf returns "" for noise.
func PriorityOf(i Impact, e Exposure) Priority {
	row, ok := priorities[i]
	if !ok {
		return ""
	}
	return row[e]
}

// Rank orders priorities, P0 first, noise last.
func (p Priority) Rank() int {
	if len(p) == 2 && p[0] == 'P' {
		return int(p[1] - '0')
	}
	return 9
}

// Lower is the next priority down; P3 and noise stay as they are.
func (p Priority) Lower() Priority {
	if r := p.Rank(); r < 3 {
		return Priority("P" + string(rune('0'+r+1)))
	}
	return p
}

func SeverityOf(p Priority) finding.Severity {
	switch p {
	case P0:
		return finding.SevCritical
	case P1:
		return finding.SevHigh
	case P2:
		return finding.SevMedium
	case P3:
		return finding.SevLow
	}
	return finding.SevInfo
}

// ImpactOf is the type's impact adjusted by the copy: noise when it is not a usable secret or not
// the owner's, by host for URL credentials, one level lower in test, example, documentation and
// vendored paths.
func ImpactOf(e Evidence) Impact {
	if e.Public || e.Encrypted || dumpNoise(e) || NotOwners(e.Origin, e.Reused) {
		return Noise
	}
	i := TypeFor(e.Type, e.Redacted).Impact
	if urlTypes[e.Type] {
		i = hostImpact(urlHost(e.Note), i)
	}
	if e.Kind != "repo" {
		return i
	}
	switch RoleOf(e.Path) {
	case RoleNone:
		return i
	case RoleGenerated:
		return Noise
	}
	if e.Sample || i == Noise {
		return Noise
	}
	return i - 1
}

// Spot is how far one location exposed the secret: a short label for tables, the plain words
// for reasons.
type Spot struct {
	Level  Exposure
	Label  string
	Phrase string
}

// Where locates one copy of a secret.
func Where(kind, mode string, tracked, remote bool) Spot {
	switch {
	case tracked && remote:
		return Spot{Remote, "git+remote", "committed to a git repository with a remote, so every clone has it"}
	case kind == "transcript":
		return Spot{Remote, "transcript", "pasted into an agent transcript, so it reached the model provider"}
	case tracked:
		return Spot{Shared, "git", "committed to a local git repository (no remote yet)"}
	case groupReadable(mode):
		return Spot{Shared, "readable", "in a file other users of this machine can read"}
	case kind == "history":
		return Spot{Local, "history", "in shell history"}
	case kind == "log":
		return Spot{Local, "log", "in a log file"}
	}
	return Spot{Local, "local", "in a local file only you can read"}
}

// WhereEvidence is Where for one finding, or the upstream's spot for a copy that is not the
// owner's.
func WhereEvidence(e Evidence) Spot {
	if s, ok := UpstreamSpot(e.Origin, e.Reused); ok {
		return s
	}
	return Where(e.Kind, e.Mode, e.Tracked, e.Remote)
}

func groupReadable(mode string) bool {
	m, err := strconv.ParseUint(mode, 8, 32)
	return err == nil && m&0o044 != 0
}

// Reason is the plain-words line behind a priority: what it is and how far it went.
func Reason(t Type, s Spot) string { return t.Label + "; " + s.Phrase }

// ShellRC are the shell start-up files: an `export NAME=value` there reaches every process.
var ShellRC = []string{".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile"}

// IsShellRC reports whether path (~/ or absolute, either separator) names one of ShellRC.
func IsShellRC(path string) bool {
	return slices.Contains(ShellRC, path[strings.LastIndexAny(path, `/\`)+1:])
}

// PowerShellProfiles are the current user's PowerShell profiles below the Documents folder, which
// may be redirected (OneDrive): Windows PowerShell and PowerShell 7, for all hosts and for the
// console host. `$env:NAME = 'value'` there reaches every PowerShell session.
var PowerShellProfiles = []string{
	"WindowsPowerShell/profile.ps1", "WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
	"PowerShell/profile.ps1", "PowerShell/Microsoft.PowerShell_profile.ps1",
}

// UserEnvKey is the registry key of the Windows user's persistent environment variables, which
// setx writes and every new process inherits. A finding there has the path UserEnvKey\NAME.
const UserEnvKey = `HKCU\Environment`

// IsUserEnv reports whether path names a variable under UserEnvKey.
func IsUserEnv(path string) bool { return strings.HasPrefix(path, UserEnvKey+`\`) }

// IsPowerShellProfile reports whether path (~/ or absolute, either separator) ends in one of
// PowerShellProfiles, ignoring case as Windows does.
func IsPowerShellProfile(path string) bool {
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) < 2 {
		return false
	}
	tail := parts[len(parts)-2] + "/" + parts[len(parts)-1]
	return slices.ContainsFunc(PowerShellProfiles, func(p string) bool { return strings.EqualFold(p, tail) })
}
