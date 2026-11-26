package report

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/doc"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

const usage = "usage: segurata report [--format text|md|html] [--out file] [--dir out] [--min-severity low] [--top 10]"

type CLI struct {
	Out, Err io.Writer
	Paths    tracker.Paths // zero means tracker.DefaultPaths
	Config   string        // config file whose expected rules apply to statuses; "" means none
	Now      func() time.Time
}

func (c CLI) fail(err error) int { return textfmt.Fail(c.Err, "report", err) }

// Run prints the report, or writes it to --out with mode 0600: it names accounts and paths.
func (c CLI) Run(args []string) int {
	fs := cliflag.New("report", c.Err)
	format := fs.String("format", string(doc.Text), "text, md or html")
	out := fs.String("out", "", "write the report to this file (mode 0600) instead of stdout")
	dir := fs.String("dir", config.DefaultOutDir(), "inventory output directory")
	minSev := fs.String("min-severity", string(finding.SevLow), "leave findings below this severity out of the lists")
	top := fs.Int("top", 10, "findings listed per connector")
	pos, err := cliflag.Parse(fs, args)
	f := doc.Format(*format)
	if err != nil || len(pos) > 0 || *top < 1 || !finding.Severity(*minSev).Valid() || !f.Valid() {
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
	opt, err := tracker.ConfiguredSync(c.Config, tracker.SyncOptions{})
	if err != nil {
		return c.fail(err)
	}
	r, err := build(inputs{OutDir: *dir, Now: now, Tracker: t, TrackerPath: paths.Tracker, Sync: opt,
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
