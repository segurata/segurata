package rotation

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

// maxLeaks is how many locations `next` lists; `show` lists them all.
const maxLeaks = 8

// next prints the most urgent active item with everything needed to rotate it; only --log writes.
func (c CLI) next(t *tracker.Tracker, path string, args []string, now time.Time) int {
	fs := cliflag.New("rotations next", c.Err)
	prio := fs.String("priority", "", "comma-separated priorities, e.g. P0 or P0,P1")
	service := fs.String("service", "", "comma-separated services, e.g. stripe,aws")
	logIt := fs.Bool("log", false, "record in the item's history that it was shown")
	if pos, err := cliflag.Parse(fs, args); err != nil || len(pos) > 0 {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	items := selectItems(t, now, false, splitList(*prio), splitList(*service))
	if len(items) == 0 {
		fmt.Fprintln(c.Out, "Nothing open matches. `segurata rotations list --all` shows rotated, snoozed and ignored items.")
		return 0
	}
	it := items[0]
	printNext(c.Out, it, items)
	if !*logIt {
		return 0
	}
	if n := len(it.History); n == 0 || it.History[n-1].Action != tracker.ActNext {
		it.Log(now, tracker.EvNote, tracker.ActNext, "")
		if err := t.Save(path); err != nil {
			return c.fail(err)
		}
	}
	return 0
}

// selectItems returns the rotate items that match the priority and service filters (empty matches
// all), most urgent first: active ones, or every item when all is true.
func selectItems(t *tracker.Tracker, now time.Time, all bool, prios, services map[string]bool) []*tracker.Item {
	var out []*tracker.Item
	for _, it := range t.Items {
		switch {
		case it.Kind != tracker.KindRotate:
		case !all && !it.Active(now):
		case len(prios) > 0 && !prios[strings.ToLower(string(it.EffectivePriority()))]:
		case len(services) > 0 && !services[strings.ToLower(it.Secret.Service)]:
		default:
			out = append(out, it)
		}
	}
	tracker.Sort(out)
	return out
}

func printNext(w io.Writer, it *tracker.Item, queue []*tracker.Item) {
	counts := map[secretrisk.Priority]int{}
	for _, q := range queue {
		counts[q.EffectivePriority()]++
	}
	var parts []string
	for _, p := range []secretrisk.Priority{secretrisk.P0, secretrisk.P1, secretrisk.P2, secretrisk.P3} {
		if counts[p] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", p, counts[p]))
		}
	}
	s := it.Secret
	label := secretrisk.TypeFor(s.Type, s.Redacted).Label
	fmt.Fprintf(w, "Next of %d open (%s)\n\n", len(queue), strings.Join(parts, ", "))
	fmt.Fprintf(w, "%s  %s  %s  %s  (%s/%s)\n", s.ID, textfmt.OrDash(string(it.EffectivePriority())), label, textfmt.OrDash(s.Redacted), s.Service, s.Type)

	fmt.Fprintln(w, "\nWhy")
	for _, r := range s.Reasons {
		fmt.Fprintf(w, "  %s\n", r)
	}

	fmt.Fprintf(w, "\nLeaked in (%d)\n", len(s.Locations))
	locs := append([]tracker.Location(nil), s.Locations...)
	sort.SliceStable(locs, func(i, j int) bool { return tracker.SpotRank(locs[i]) > tracker.SpotRank(locs[j]) })
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for i, loc := range locs {
		if i == maxLeaks {
			fmt.Fprintf(tw, "  … and %d more: segurata rotations show %s\n", len(locs)-maxLeaks, s.ID)
			break
		}
		fmt.Fprintf(tw, "  %s\t%s\n", loc.Where(), loc.Spot().Label)
	}
	tw.Flush()

	fmt.Fprintln(w, "\nRotate it")
	if where := s.RotateWhere(); s.RotateURL == "" && where == "in the provider's console" {
		fmt.Fprintln(w, "  "+where+" (no account-independent page is known for this type)")
	} else {
		fmt.Fprintln(w, "  "+where)
	}
	if g, ok := secretrisk.GuideFor(s.Type); ok {
		for i, step := range g.Steps {
			fmt.Fprintf(w, "  %d. %s\n", i+1, step)
		}
		fmt.Fprintf(w, "  Source: %s\n", g.Doc)
	}

	fmt.Fprintln(w, "\nThe new value goes in (used_in)")
	rc := false
	if len(s.UsedIn) == 0 {
		fmt.Fprintln(w, "  no working file: only history, transcripts or logs hold it")
	}
	for _, p := range s.UsedIn {
		line := p
		for _, loc := range s.Locations {
			if loc.Path == p && loc.Line > 0 && loc.Source != "gitleaks" {
				line = loc.Where()
				break
			}
		}
		if toKeychain != nil && toKeychain.is(p) {
			rc = true
			line += "  (" + toKeychain.kind + ": --to-keychain keeps the new value out of it)"
		}
		fmt.Fprintf(w, "  %s\n", line)
	}

	fmt.Fprintln(w, "\nNext commands")
	fmt.Fprintln(w, "  1. Rotate it at the provider as above and copy the new value.")
	_, single := secretrisk.ParseHint(s.Redacted)
	switch {
	case len(s.UsedIn) == 0:
		fmt.Fprintf(w, "  2. segurata rotations done %s --note \"rotated at the provider\"\n", s.ID)
	case !single:
		fmt.Fprintf(w, "  2. Put the new value in the files above by hand (not a one-line value).\n")
		fmt.Fprintf(w, "  3. segurata rotations done %s --note \"rotated at the provider\"\n", s.ID)
	default:
		fmt.Fprintf(w, "  2. segurata rotations replace %s            # dry run: plan from the clipboard\n", s.ID)
		keychain := ""
		if rc {
			keychain = " [--to-keychain <VAR_NAME>]"
		}
		fmt.Fprintf(w, "  3. segurata rotations replace %s --apply%s\n", s.ID, keychain)
	}
	fmt.Fprintf(w, "  Then: segurata rotations next   (not now: snooze %s --until YYYY-MM-DD; false positive: ignore %s --reason …)\n", s.ID, s.ID)
}
