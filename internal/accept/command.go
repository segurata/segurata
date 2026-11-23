package accept

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/remediate"
)

const (
	acceptUsage   = "usage: securizame accept <finding-id> --reason text [--until YYYY-MM-DD] | securizame accept --list"
	unacceptUsage = "usage: securizame unaccept <finding-id>"
)

// CLI is `securizame accept` and `securizame unaccept`.
type CLI struct {
	Out, Err io.Writer
	Path     string // "" means DefaultPath
	Now      func() time.Time
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, err)
	return 1
}

func (c CLI) load() (*Store, string, error) {
	path := c.Path
	if path == "" {
		p, err := DefaultPath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	s, err := Load(path)
	return s, path, err
}

// Accept records a finding of the latest run as an accepted risk, or lists the accepted ones.
func (c CLI) Accept(args []string) int {
	fs := flag.NewFlagSet("accept", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	list := fs.Bool("list", false, "list accepted findings")
	reason := fs.String("reason", "", "why the risk is kept on purpose")
	until := fs.String("until", "", "last day the acceptance applies, YYYY-MM-DD (default: no end)")
	out := fs.String("out", "out", "inventory output directory")
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) > 1 || (len(pos) == 1) == *list {
		fmt.Fprintln(c.Err, acceptUsage)
		return 2
	}
	s, path, err := c.load()
	if err != nil {
		return c.fail(err)
	}
	now := c.Now()
	if *list {
		c.list(s, now)
		return 0
	}
	files, err := remediate.LatestFiles(*out)
	if err != nil {
		return c.fail(err)
	}
	all, err := remediate.Load(files)
	if err != nil {
		return c.fail(err)
	}
	f, err := remediate.Find(all, pos[0])
	if err != nil {
		return c.fail(err)
	}
	e, err := s.Accept(f, *reason, *until, now)
	if err != nil {
		return c.fail(err)
	}
	if err := s.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "Accepted %s [%s] %s · %s (%s).\n", e.ID, f.Severity, e.Connector, e.Title, untilText(e))
	return 0
}

// Unaccept removes an acceptance, so the finding shows again.
func (c CLI) Unaccept(args []string) int {
	fs := flag.NewFlagSet("unaccept", flag.ContinueOnError)
	fs.SetOutput(c.Err)
	pos, err := cliflag.Parse(fs, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprintln(c.Err, unacceptUsage)
		return 2
	}
	s, path, err := c.load()
	if err != nil {
		return c.fail(err)
	}
	e, err := s.Unaccept(pos[0])
	if err != nil {
		return c.fail(err)
	}
	if err := s.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "No longer accepted: %s %s · %s.\n", e.ID, e.Connector, e.Title)
	return 0
}

func (c CLI) list(s *Store, now time.Time) {
	for _, e := range s.Entries {
		state := "accepted"
		if e.Expired(now) {
			state = "acceptance expired"
		}
		fmt.Fprintf(c.Out, "%s  %-18s %-22s %-16s %s\n", e.ID, state, untilText(e), e.Connector, e.Title)
		fmt.Fprintf(c.Out, "%18s reason: %s (accepted %s)\n", "", e.Reason, e.AcceptedAt.In(now.Location()).Format(time.DateOnly))
	}
	fmt.Fprintf(c.Out, "\n%d accepted findings. Show them again with: securizame unaccept <id>\n", len(s.Entries))
}

func untilText(e *Entry) string {
	if e.Until == "" {
		return "no end date"
	}
	return "until " + e.Until
}
