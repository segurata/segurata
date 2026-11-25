// Package browserext triages the extensions installed in every Brave and Chrome profile: what each
// one can do, where it came from, how fresh it is, and a verdict (remove, review, keep) with the
// reasons. It reads the browsers' profile files and never changes them: editing them while the
// browser runs is unsafe, so every fix is a link to the extension's page in the browser.
package browserext

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

type browser struct {
	name   string
	dirs   map[string]string // GOOS -> data directory under the home folder
	scheme string            // for the extensions page URL
}

var browsers = []browser{
	{"Brave", map[string]string{"darwin": "Library/Application Support/BraveSoftware/Brave-Browser", "linux": ".config/BraveSoftware/Brave-Browser"}, "brave"},
	{"Chrome", map[string]string{"darwin": "Library/Application Support/Google/Chrome", "linux": ".config/google-chrome"}, "chrome"},
}

type Connector struct {
	Home func() (string, error)
	Now  func() time.Time
	OS   string
}

func New() *Connector { return &Connector{Home: os.UserHomeDir, Now: time.Now, OS: runtime.GOOS} }

func init() { connector.Register(New()) }

func (c *Connector) Describe() connector.Description {
	return connector.Description{
		Name:     "browser-extensions",
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Brave and Chrome extensions in every profile: capabilities, source, age and a remove/review/keep verdict",
		Needs:    []string{"os:darwin|linux"},
		Theme:    finding.ThemeBrowserExtensions,
	}
}

// Track makes one review item of each extension: keep it or remove it.
func (c *Connector) Track(finding.Finding) *finding.Track {
	return &finding.Track{Group: finding.GroupFinding, Kind: finding.TrackReview}
}

// primaries reads config "primary": extension ids that win a duplicate check in their category
// (for example the password manager you use, when another one is still installed).
func primaries(cfg map[string]any) []string {
	var ids []string
	list, _ := cfg["primary"].([]any)
	for _, v := range list {
		if s, ok := v.(string); ok {
			ids = append(ids, s)
		}
	}
	return ids
}

func (c *Connector) Inventory(_ context.Context, req connector.Request, emit connector.Emitter) error {
	home, err := c.Home()
	if err != nil {
		emit.Status(finding.Status{Account: "this machine", State: finding.StateError, Detail: err.Error()})
		return nil
	}
	now := c.Now()
	found := false
	for _, b := range browsers {
		rel, ok := b.dirs[c.OS]
		if !ok {
			continue
		}
		dir := filepath.Join(home, rel)
		ins, err := readBrowser(dir, now)
		if err != nil {
			emit.Log(fmt.Sprintf("%s: no profiles in %s", b.name, dir))
			continue
		}
		found = true
		for _, f := range findings(b, assess(ins, now, primaries(req.Config))) {
			emit.Finding(f)
		}
		emit.Status(finding.Status{Account: b.name, State: finding.StateOK})
	}
	if !found {
		emit.Status(finding.Status{Account: "this machine", State: finding.StateUnsupported, Detail: "no Brave or Chrome profile found"})
	}
	return nil
}

// findings groups assessments by extension: one finding per extension and browser, with every
// profile it is installed in. The verdict and severity are the worst across profiles.
func findings(b browser, as []assessment) []finding.Finding {
	byID := map[string][]assessment{}
	for _, a := range as {
		byID[a.id] = append(byID[a.id], a)
	}
	var out []finding.Finding
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		out = append(out, extensionFinding(b, byID[id]))
	}
	return out
}

func extensionFinding(b browser, as []assessment) finding.Finding {
	worst := slices.MaxFunc(as, func(x, y assessment) int {
		return cmp.Or(cmp.Compare(x.verdict, y.verdict), cmp.Compare(x.sev.Rank(), y.sev.Rank()))
	})
	var reasons, profiles []string
	caps := []string{}
	var where []map[string]any
	for _, a := range as {
		profiles = append(profiles, a.profile)
		for _, c := range a.caps {
			if !slices.Contains(caps, c) {
				caps = append(caps, c)
			}
		}
		if a.verdict == worst.verdict {
			for _, r := range a.reasons {
				reasons = append(reasons, "["+a.profile+"] "+r)
			}
		}
		where = append(where, map[string]any{"profile": a.profile, "version": a.version, "enabled": a.enabled,
			"source": a.source(), "installed": day(a.installed), "updated": day(a.updated), "verdict": a.verdict.String()})
	}
	url := b.scheme + "://extensions/?id=" + worst.id
	in := "profile " + strings.Join(profiles, ", ")
	if len(profiles) > 1 {
		in = "profiles " + strings.Join(profiles, ", ")
	}
	var summary string
	switch worst.verdict {
	case remove:
		summary = fmt.Sprintf("Remove it: open %s in %s and click Remove.", url, in)
	case review:
		summary = fmt.Sprintf("Review it at %s (%s): remove it if you do not use it, or set Site access to \"On click\".", url, in)
	default:
		summary = fmt.Sprintf("Nothing to do. It is at %s (%s).", url, in)
	}
	title := fmt.Sprintf("%s extension %s: %s (%s)", b.name, worst.name, worst.verdict, strings.TrimPrefix(reasons[0], "["+worst.profile+"] "))
	if len(profiles) > 1 {
		title = fmt.Sprintf("%s extension %s: %s (%s)", b.name, worst.name, worst.verdict, reasons[0])
	}
	return finding.Finding{
		Account:  b.name,
		Resource: finding.Resource{Type: "browser_extension", ID: worst.id, Name: worst.name},
		Kind:     finding.KindGrant,
		Severity: worst.sev,
		Title:    title,
		Evidence: map[string]any{"browser": b.name, "extension_id": worst.id, "name": worst.name, "verdict": worst.verdict.String(),
			"reasons": reasons, "category": worst.category, "capabilities": caps, "profiles": where, "url": url},
		Remediation: finding.Remediation{Summary: summary, URL: url},
	}
}
