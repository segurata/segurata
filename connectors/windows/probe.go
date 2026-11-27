package windows

import (
	_ "embed"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// probeScript is what Windows PowerShell runs to read what the registry alone does not hold.
//
//go:embed probe.ps1
var probeScript string

// record is one line of the probe's output: a section and its fields.
type record struct {
	sec    string
	fields map[string]string
}

func (r record) get(k string) string { return r.fields[k] }

func (r record) is(k string) bool { return strings.EqualFold(r.fields[k], "true") }

// probe is the probe's output by section. A section that failed has an err record instead.
type probe struct {
	recs   map[string][]record
	failed map[string]record
	whole  string // why the probe as a whole failed, or ""
}

func parseProbe(out string) probe {
	p := probe{recs: map[string][]record{}, failed: map[string]record{}}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if parts[0] == "" {
			continue
		}
		r := record{sec: parts[0], fields: map[string]string{}}
		for _, kv := range parts[1:] {
			k, v, _ := strings.Cut(kv, "=")
			r.fields[k] = v
		}
		if r.sec == "err" {
			p.failed[r.get("sec")] = r
			continue
		}
		p.recs[r.sec] = append(p.recs[r.sec], r)
	}
	return p
}

func (p probe) all(sec string) []record { return p.recs[sec] }

func (p probe) one(sec string) (record, bool) {
	if rs := p.recs[sec]; len(rs) > 0 {
		return rs[0], true
	}
	return record{}, false
}

// failure is the err record of a section that has no records, and whether it failed.
func (p probe) failure(sec string) (record, bool) {
	if p.whole != "" {
		return record{sec: "err", fields: map[string]string{"sec": sec, "msg": p.whole}}, true
	}
	r, ok := p.failed[sec]
	return r, ok
}

// unread is why a check whose source is section sec cannot run, and whether it cannot. A section
// refused to a user who is not elevated needs an administrator: the skip names elevated, the
// command that shows the same from an elevated PowerShell, and is unsupported, since segurata
// never elevates. Any other failure is an error.
func (p probe) unread(sec, elevated string) (string, finding.State, bool) {
	r, failed := p.failure(sec)
	if !failed {
		return "", "", false
	}
	if r.is("denied") && !p.elevated() && elevated != "" {
		return needsAdmin(elevated), finding.StateUnsupported, true
	}
	msg := r.get("msg")
	if c := r.get("code"); c != "" {
		msg += " (" + c + ")"
	}
	return "could not read " + sec + ": " + msg, finding.StateError, true
}

// needsAdmin is the skip of a check a standard user cannot run.
func needsAdmin(cmd string) string {
	return "needs admin: run `" + cmd + "` in an elevated PowerShell to see it"
}

func (p probe) elevated() bool {
	r, _ := p.one("self")
	return r.is("elevated")
}

// WMI's codes for a namespace or class this edition of Windows does not have.
func absent(r record) bool {
	c := r.get("code")
	return c == "InvalidNamespace" || c == "InvalidClass" || c == "NotFound"
}
