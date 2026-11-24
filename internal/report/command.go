package report

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/segurata/segurata/internal/accept"
	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/rotation"
	"github.com/segurata/segurata/internal/statefile"
)

const usage = "usage: securizame report [--format text|md|html] [--out file] [--dir out] [--min-severity low] [--top 10]"

// CLI is `securizame report`.
type CLI struct {
	Out, Err     io.Writer
	AcceptedPath string // "" means accept.DefaultPath
	LedgerPath   string // "" means rotation.DefaultPath
	Now          func() time.Time
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
	dir := fs.String("dir", "out", "inventory output directory")
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
	accPath, ledPath := c.AcceptedPath, c.LedgerPath
	if accPath == "" {
		if accPath, err = accept.DefaultPath(); err != nil {
			return c.fail(err)
		}
	}
	if ledPath == "" {
		if ledPath, err = rotation.DefaultPath(); err != nil {
			return c.fail(err)
		}
	}
	acc, err := accept.Load(accPath)
	if err != nil {
		return c.fail(err)
	}
	led, err := rotation.Load(ledPath)
	if err != nil {
		return c.fail(err)
	}
	r, err := Build(Inputs{OutDir: *dir, Now: c.Now(), Accepted: acc, Ledger: led, LedgerPath: ledPath,
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
