package report

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/segurata/segurata/internal/config"
	"io"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/tracker"
)

const usage = "usage: segurata report [--format text|md|html] [--out file] [--dir out] [--min-severity low] [--top 10]"

// CLI is `segurata report`.
type CLI struct {
	Out, Err io.Writer
	Paths    tracker.Paths // zero means tracker.DefaultPaths
	Config   string        // config file whose expected rules apply to statuses; "" means none
	Now      func() time.Time
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, "report:", err)
	return 1
}

// Run builds the report and prints it, or writes it to --out with mode 0600: it names accounts,
// services and file paths.
func (c CLI) Run(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	format := fs.String("format", string(Text), "text, md or html")
	out := fs.String("out", "", "write the report to this file (mode 0600) instead of stdout")
	dir := fs.String("dir", config.DefaultOutDir(), "inventory output directory")
	minSev := fs.String("min-severity", string(finding.SevLow), "leave findings below this severity out of the lists")
	top := fs.Int("top", 10, "findings listed per connector and per kind of change")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) > 0 || *top < 1 || !validSeverity(finding.Severity(*minSev)) {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	f := Format(*format)
	if !f.Valid() {
		fmt.Fprintln(c.Err, usage)
		return 2
	}
	paths, err := c.Paths.Resolve()
	if err != nil {
		return c.fail(err)
	}
	now := c.Now()
	t, err := tracker.LoadOrNew(paths, now)
	if err != nil {
		return c.fail(err)
	}
	expect, err := tracker.Expectations(c.Config)
	if err != nil {
		return c.fail(err)
	}
	r, err := Build(Inputs{OutDir: *dir, Now: now, Tracker: t, TrackerPath: paths.Tracker, Expect: expect,
		MinSev: finding.Severity(*minSev), Top: *top})
	if err != nil {
		return c.fail(err)
	}
	if *out == "" {
		if err := r.Render(c.Out, f); err != nil {
			return c.fail(err)
		}
		return 0
	}
	var buf bytes.Buffer
	if err := r.Render(&buf, f); err != nil {
		return c.fail(err)
	}
	if err := statefile.Write(*out, buf.Bytes()); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "Report written to %s (mode 0600).\n", *out)
	return 0
}

func validSeverity(s finding.Severity) bool {
	for _, x := range severities {
		if x == s {
			return true
		}
	}
	return false
}
