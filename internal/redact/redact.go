// Package redact is `segurata redact`: it rewrites local trail files (agent transcripts, shell
// histories, logs) so the secrets local-secrets finds in them are replaced by
// [REDACTED:<type>:<fingerprint8>]. Those copies already went wherever they went (a transcript
// reached the model provider), so rotation is still needed; redaction removes the copy that
// stays on disk, in backups and in sync tools. See docs/architecture.md, "Redaction".
package redact

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/segurata/segurata/connectors/localsecrets"
	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/remediate"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

// DefaultMinAge keeps files an agent or a shell may still be writing out of reach.
const DefaultMinAge = 2 * time.Hour

const usage = `usage: segurata redact (--trails | --path <prefix> | --item <rotation id>) [options]
  --trails            every trail local-secrets scans: agent transcripts, shell histories, logs
  --path <prefix>     only trail files under this path
  --item <id>         only this rotation item's secret, everywhere it appears in trails
  --min-priority P1   only secrets whose rotation priority is P1 or more urgent
  --include-noise     also generic matches, public, expired and encrypted values
  --min-age 2h        leave files modified more recently alone (default 2h)
  --apply [--yes]     rewrite the files after confirmation; without it, a dry run
  --backup            with --apply, keep a 0600 copy of each file as it was (plaintext secrets!)`

// Runner runs a program and returns its stdout. Tests inject a fake.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// CLI is the `segurata redact` command.
type CLI struct {
	Out, Err io.Writer
	In       io.Reader
	TTY      bool // In is a terminal
	// Trails opens local-secrets' trail scan with the user's config.
	Trails func(ctx context.Context) (*localsecrets.Trails, error)
	Lsof   Runner        // lists the files claude and codex processes have open
	Paths  tracker.Paths // the tracker whose rotate items are noted; zero means tracker.DefaultPaths
	Now    func() time.Time
}

type options struct {
	trails, noise, apply, yes, backup bool
	path, item                        string
	minPriority                       secretrisk.Priority
	minAge                            time.Duration
}

func (c CLI) fail(err error) int {
	fmt.Fprintln(c.Err, "redact:", err)
	return 1
}

// Run executes the command and returns the exit code.
func (c CLI) Run(ctx context.Context, args []string) int {
	o, ok := c.parse(args)
	if !ok {
		return 2
	}
	now := c.Now()
	t, err := c.Trails(ctx)
	if err != nil {
		return c.fail(err)
	}
	paths, err := c.Paths.Resolve()
	if err != nil {
		return c.fail(err)
	}
	ledger, err := tracker.LoadOrNew(paths, now)
	if err != nil {
		return c.fail(err)
	}
	s := &selection{opt: o, items: map[string]*tracker.Item{}}
	for _, it := range ledger.Items {
		if it.Kind == tracker.KindRotate {
			s.items[it.Fingerprint] = it
		}
	}
	if o.item != "" {
		it, err := ledger.FindRotate(o.item)
		if err != nil {
			return c.fail(err)
		}
		s.only = it
	}
	if o.path != "" {
		s.prefix = filepath.Clean(expandHome(o.path, t.Home()))
	}

	lines, err := t.Lines(nil)
	if err != nil {
		return c.fail(err)
	}
	open, err := c.openFiles(ctx)
	if err != nil {
		return c.fail(err)
	}
	p := c.plan(t, s, lines, open, now)
	p.print(c.Out, t, o, s)
	if !o.apply {
		fmt.Fprintln(c.Out, "\nDry run: nothing was changed. Run again with --apply to rewrite these files.")
		return 0
	}
	if len(p.files) == 0 {
		return 0
	}
	if o.backup {
		fmt.Fprintln(c.Out, "\nWARNING: --backup keeps a copy of every file as it was, next to it (mode 0600). Each copy holds the secrets in plaintext: delete them once you have checked the result.")
	}
	yes, err := remediate.Confirm(c.In, c.Out, o.yes, c.TTY)
	if err != nil {
		return c.fail(err)
	}
	if !yes {
		fmt.Fprintln(c.Out, "Not applied.")
		return 0
	}
	return c.apply(ctx, t, s, p, ledger, paths.Tracker, now)
}

func (c CLI) parse(args []string) (options, bool) {
	fs := cliflag.New("redact", c.Err)
	fs.Usage = func() { fmt.Fprintln(c.Err, usage) }
	var o options
	var prio string
	fs.BoolVar(&o.trails, "trails", false, "")
	fs.StringVar(&o.path, "path", "", "")
	fs.StringVar(&o.item, "item", "", "")
	fs.StringVar(&prio, "min-priority", "", "")
	fs.BoolVar(&o.noise, "include-noise", false, "")
	fs.DurationVar(&o.minAge, "min-age", DefaultMinAge, "")
	fs.BoolVar(&o.apply, "apply", false, "")
	fs.BoolVar(&o.yes, "yes", false, "")
	fs.BoolVar(&o.backup, "backup", false, "")
	pos, err := cliflag.Parse(fs, args)
	if err != nil {
		return o, false
	}
	bad := func(msg string) (options, bool) {
		fmt.Fprintln(c.Err, "redact: "+msg)
		fmt.Fprintln(c.Err, usage)
		return o, false
	}
	switch {
	case len(pos) > 0:
		return bad("unexpected argument " + pos[0])
	case !o.trails && o.path == "" && o.item == "":
		return bad("choose what to redact: --trails, --path or --item")
	case o.minAge < 0:
		return bad("--min-age must not be negative")
	case o.backup && !o.apply:
		return bad("--backup only makes sense with --apply")
	case o.yes && !o.apply:
		return bad("--yes only makes sense with --apply")
	}
	if prio != "" {
		o.minPriority = secretrisk.Priority(strings.ToUpper(prio))
		if o.minPriority.Rank() > 3 {
			return bad("--min-priority must be P0, P1, P2 or P3")
		}
	}
	return o, true
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// selection decides which files and which secrets are in scope.
type selection struct {
	opt    options
	prefix string                   // --path, absolute
	only   *tracker.Item            // --item
	items  map[string]*tracker.Item // rotate items by fingerprint
}

func (s *selection) file(abs string) bool {
	return s.prefix == "" || abs == s.prefix || strings.HasPrefix(abs, s.prefix+string(filepath.Separator))
}

// keep reports whether a hit is in scope. The priority is the rotation item's when the ledger
// knows the secret (its worst location), otherwise this copy's.
func (s *selection) keep(h localsecrets.Hit) bool {
	if s.only != nil {
		return h.Fingerprint == s.only.Fingerprint
	}
	if h.Impact == secretrisk.Noise && !s.opt.noise {
		return false
	}
	if s.opt.minPriority != "" {
		p := h.Priority
		if it := s.items[h.Fingerprint]; it != nil && it.EffectivePriority() != "" {
			p = it.EffectivePriority()
		}
		if p == "" || p.Rank() > s.opt.minPriority.Rank() {
			return false
		}
	}
	return true
}

func (s *selection) finder(t *localsecrets.Trails, abs, mode string) finder {
	return func(text string) []localsecrets.Hit {
		var out []localsecrets.Hit
		for _, h := range t.Find(abs, mode, text) {
			if s.keep(h) {
				out = append(out, h)
			}
		}
		return out
	}
}

// filePlan is one file to rewrite, with what was found in it and the state it was in.
type filePlan struct {
	abs, path string
	lines     []int
	mode      string // effective mode, for exposure
	perm      fs.FileMode
	size      int64
	mtime     time.Time
	matches   int
	residue   int
	bytes     int
	byType    map[string]int
	fps       map[string]string // fingerprint -> type
}

type plan struct {
	files   []*filePlan
	skipped map[string][]string // reason -> paths
}

func (p *plan) skip(reason, path string) {
	p.skipped[reason] = append(p.skipped[reason], path)
}

// Skip reasons, also used at apply time.
const (
	skipRecent  = "modified within --min-age"
	skipOpen    = "open by a running claude or codex process"
	skipIrreg   = "not a regular file (symlink or other)"
	skipOwner   = "owned by another account"
	skipRead    = "unreadable"
	skipJSON    = "a replacement would break its JSON"
	skipChanged = "changed since the plan"
)

// guard returns the file's info, or why it must not be touched.
func guard(abs string, minAge time.Duration, now time.Time, open map[string]bool) (fs.FileInfo, string) {
	st, err := os.Lstat(abs)
	if err != nil {
		return nil, skipRead
	}
	if !st.Mode().IsRegular() {
		return nil, skipIrreg
	}
	if !ownedByMe(st) {
		return nil, skipOwner
	}
	if now.Sub(st.ModTime()) < minAge {
		return nil, skipRecent
	}
	if isOpen(abs, open) {
		return nil, skipOpen
	}
	return st, ""
}

func isOpen(abs string, open map[string]bool) bool {
	if open[abs] {
		return true
	}
	real, err := filepath.EvalSymlinks(abs)
	return err == nil && open[real]
}

// plan works out every file's rewrite, several files at a time: matching is CPU-bound.
func (c CLI) plan(t *localsecrets.Trails, s *selection, lines map[string][]int, open map[string]bool, now time.Time) *plan {
	p := &plan{skipped: map[string][]string{}}
	paths := make([]string, 0, len(lines))
	for abs := range lines {
		if s.file(abs) {
			paths = append(paths, abs)
		}
	}
	slices.Sort(paths)
	type planned struct {
		fp     *filePlan
		reason string
	}
	out := make([]planned, len(paths))
	work := make(chan int)
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), len(paths)) {
		wg.Go(func() {
			for i := range work {
				out[i].fp, out[i].reason = c.planFile(t, s, paths[i], lines[paths[i]], open, now)
			}
		})
	}
	for i := range paths {
		work <- i
	}
	close(work)
	wg.Wait()
	for i, r := range out {
		switch {
		case r.reason != "":
			p.skip(r.reason, t.Tilde(paths[i]))
		case r.fp != nil:
			p.files = append(p.files, r.fp)
		}
	}
	return p
}

// planFile reads one file and works out its rewrite. It returns nil when nothing in scope is in
// it, or the reason it is left alone.
func (c CLI) planFile(t *localsecrets.Trails, s *selection, abs string, lines []int, open map[string]bool, now time.Time) (*filePlan, string) {
	st, reason := guard(abs, s.opt.minAge, now, open)
	if reason != "" {
		// A file with nothing in scope is not worth reporting as skipped.
		if !c.anyInScope(t, s, abs, lines) {
			return nil, ""
		}
		return nil, reason
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, skipRead
	}
	f := &filePlan{abs: abs, path: t.Tilde(abs), lines: lines, mode: t.Mode(abs), perm: st.Mode().Perm(),
		size: st.Size(), mtime: st.ModTime(), byType: map[string]int{}, fps: map[string]string{}}
	res, err := rewrite(raw, lines, s.finder(t, abs, f.mode))
	if err != nil {
		return nil, skipJSON
	}
	if len(res.applied) == 0 && res.residue == 0 {
		return nil, ""
	}
	f.matches, f.residue, f.bytes = len(res.applied), res.residue, res.bytes
	for _, h := range res.applied {
		f.byType[h.Type]++
		f.fps[h.Fingerprint] = h.Type
	}
	return f, ""
}

// anyInScope reports whether a file left alone holds anything in scope, so the skip is worth
// reporting.
func (c CLI) anyInScope(t *localsecrets.Trails, s *selection, abs string, lines []int) bool {
	raw, err := os.ReadFile(abs)
	if err != nil {
		return true
	}
	res, err := rewrite(raw, lines, s.finder(t, abs, t.Mode(abs)))
	return err != nil || len(res.applied) > 0 || res.residue > 0
}

func (p *plan) print(w io.Writer, t *localsecrets.Trails, o options, s *selection) {
	scope := []string{}
	if o.trails {
		scope = append(scope, "every trail (agent transcripts, shell histories, logs)")
	}
	if s.prefix != "" {
		scope = append(scope, "trail files under "+t.Tilde(s.prefix))
	}
	if s.only != nil {
		scope = append(scope, fmt.Sprintf("only item %s (%s %s)", s.only.Secret.ID, s.only.Secret.Type, s.only.Secret.Redacted))
	}
	if o.minPriority != "" {
		scope = append(scope, "priority "+string(o.minPriority)+" or more urgent")
	}
	if o.noise {
		scope = append(scope, "noise included")
	} else if s.only == nil {
		scope = append(scope, "noise left out")
	}
	fmt.Fprintf(w, "Redact: %s; files modified in the last %s are left alone.\n", strings.Join(scope, "; "), o.minAge)
	fmt.Fprintln(w, "Each secret becomes [REDACTED:<type>:<fingerprint8>].")

	total := map[string]int{}
	distinct := map[string]map[string]bool{} // type -> fingerprints
	all := map[string]bool{}
	matches, bytes, residue := 0, 0, 0
	if len(p.files) > 0 {
		fmt.Fprintln(w)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range p.files {
			fmt.Fprintf(tw, "%s\t%d\t%s\n", f.path, f.matches, typeCounts(f.byType))
			matches, bytes, residue = matches+f.matches, bytes+f.bytes, residue+f.residue
			for typ, n := range f.byType {
				total[typ] += n
			}
			for fp, typ := range f.fps {
				if distinct[typ] == nil {
					distinct[typ] = map[string]bool{}
				}
				distinct[typ][fp], all[fp] = true, true
			}
		}
		tw.Flush()
	}
	reasons := slices.Sorted(maps.Keys(p.skipped))
	if len(reasons) > 0 {
		fmt.Fprintln(w, "\nLeft alone, although they hold secrets in scope:")
		for _, r := range reasons {
			n := len(p.skipped[r])
			fmt.Fprintf(w, "  %d %s %s\n", n, textfmt.Plural(n, "file", "files"), r)
			if r != skipRecent {
				for _, path := range p.skipped[r] {
					fmt.Fprintf(w, "    %s\n", path)
				}
			}
		}
	}
	fmt.Fprintf(w, "\nTotal: %d %s, %d %s of %d distinct %s, %d bytes of secret text replaced.\n",
		len(p.files), textfmt.Plural(len(p.files), "file", "files"), matches, textfmt.Plural(matches, "match", "matches"),
		len(all), textfmt.Plural(len(all), "secret", "secrets"), bytes)
	if residue > 0 {
		fmt.Fprintf(w, "%d %s cannot be replaced without breaking JSON and will stay.\n", residue, textfmt.Plural(residue, "match", "matches"))
	}
	if len(total) == 0 {
		return
	}
	fmt.Fprintln(w, "By type (matches, distinct secrets):")
	types := slices.Collect(maps.Keys(total))
	slices.SortFunc(types, func(a, b string) int {
		return cmp.Or(cmp.Compare(total[b], total[a]), cmp.Compare(a, b))
	})
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, typ := range types {
		fmt.Fprintf(tw, "  %s\t%d\t%d\n", typ, total[typ], len(distinct[typ]))
	}
	tw.Flush()
}

func typeCounts(m map[string]int) string {
	types := slices.Sorted(maps.Keys(m))
	parts := make([]string, len(types))
	for i, t := range types {
		parts[i] = fmt.Sprintf("%s %d", t, m[t])
	}
	return strings.Join(parts, ", ")
}

// apply rewrites every planned file that is still as planned, verifies the result by scanning
// the rewritten files again, and notes the redaction on the rotation items.
func (c CLI) apply(ctx context.Context, t *localsecrets.Trails, s *selection, p *plan, ledger *tracker.Tracker, statePath string, now time.Time) int {
	open, err := c.openFiles(ctx)
	if err != nil {
		return c.fail(err)
	}
	var written []*filePlan
	failed := 0
	for _, f := range p.files {
		reason, err := c.applyFile(t, s, f, open, now)
		switch {
		case err != nil:
			failed++
			fmt.Fprintf(c.Err, "redact: %s: %v\n", f.path, err)
		case reason != "":
			fmt.Fprintf(c.Out, "Left alone: %s (%s)\n", f.path, reason)
		default:
			written = append(written, f)
		}
	}
	matches := 0
	for _, f := range written {
		matches += f.matches
	}
	fmt.Fprintf(c.Out, "Rewrote %d %s (%d %s). Scanning them again...\n", len(written), textfmt.Plural(len(written), "file", "files"),
		matches, textfmt.Plural(matches, "match", "matches"))
	if err := c.verify(t, s, written); err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.Out, "Verified: no secret in scope is left in the rewritten files; modes and modification times are as they were.")

	files := map[string]int{}
	for _, f := range written {
		for fp := range f.fps {
			files[fp]++
		}
	}
	noted := 0
	for _, it := range ledger.Items {
		if n := files[it.Fingerprint]; n > 0 {
			it.NoteRedaction(now, n)
			noted++
		}
	}
	if noted > 0 {
		if err := ledger.Save(statePath); err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.Out, "Noted the redaction on %d rotation %s. Rotation is still needed: these copies reached the model provider or wherever the trail was sent.\n",
			noted, textfmt.Plural(noted, "item", "items"))
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// unchanged reports whether st still has the size and modification time the plan saw.
func (f *filePlan) unchanged(st fs.FileInfo) bool {
	return st.Size() == f.size && st.ModTime().Equal(f.mtime)
}

// applyFile rewrites one file if it is still exactly as planned: same guards, size, modification
// time and matches. The new content replaces the file atomically with its mode, and the
// modification time is put back so tools that sort by date are not confused.
func (c CLI) applyFile(t *localsecrets.Trails, s *selection, f *filePlan, open map[string]bool, now time.Time) (string, error) {
	st, reason := guard(f.abs, s.opt.minAge, now, open)
	if reason != "" {
		return reason, nil
	}
	if !f.unchanged(st) {
		return skipChanged, nil
	}
	raw, err := os.ReadFile(f.abs)
	if err != nil {
		return "", err
	}
	res, err := rewrite(raw, f.lines, s.finder(t, f.abs, f.mode))
	if err != nil || len(res.applied) != f.matches {
		return skipChanged, nil
	}
	if s.opt.backup {
		name, err := statefile.Backup(f.abs, raw, now)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(c.Out, "Backup (plaintext secrets): %s\n", t.Tilde(name))
	}
	// Last look before replacing: an append since the read would be lost.
	if st, err := os.Lstat(f.abs); err != nil || !f.unchanged(st) {
		return skipChanged, nil
	}
	if err := statefile.Replace(f.abs, res.out, f.perm); err != nil {
		return "", err
	}
	if err := os.Chtimes(f.abs, time.Time{}, f.mtime); err != nil {
		return "", fmt.Errorf("rewritten, but the modification time could not be restored: %w", err)
	}
	return "", nil
}

// verify scans the rewritten files again with ripgrep and the same patterns: none may hold a
// secret in scope beyond what the plan said would stay, and each keeps its mode and modification
// time.
func (c CLI) verify(t *localsecrets.Trails, s *selection, written []*filePlan) error {
	if len(written) == 0 {
		return nil
	}
	abs := make([]string, len(written))
	for i, f := range written {
		abs[i] = f.abs
	}
	lines, err := t.Lines(abs)
	if err != nil {
		return fmt.Errorf("the check could not run: %w", err)
	}
	var problems []string
	for _, f := range written {
		problem := func(format string, a ...any) {
			problems = append(problems, f.path+": "+fmt.Sprintf(format, a...))
		}
		st, err := os.Lstat(f.abs)
		if err != nil {
			problem("%v", err)
			continue
		}
		if st.Mode().Perm() != f.perm {
			problem("mode is %o, was %o", st.Mode().Perm(), f.perm)
		}
		if !st.ModTime().Equal(f.mtime) {
			problem("modification time changed")
		}
		raw, err := os.ReadFile(f.abs)
		if err != nil {
			problem("%v", err)
			continue
		}
		res, err := rewrite(raw, lines[f.abs], s.finder(t, f.abs, f.mode))
		if err != nil {
			problem("%v", err)
			continue
		}
		if left := len(res.applied) + res.residue; left > f.residue {
			problem("%d %s in scope still there", left, textfmt.Plural(left, "secret", "secrets"))
		}
	}
	if len(problems) > 0 {
		return errors.New("verification failed:\n  " + strings.Join(problems, "\n  "))
	}
	return nil
}

// openFiles lists the files that running claude and codex processes have open, with
// `lsof -Fn -c claude -c codex` (read-only). lsof exits 1 when a name matches no process, which
// is not a failure; anything else is, because without the list an active session could be
// rewritten under its writer.
func (c CLI) openFiles(ctx context.Context) (map[string]bool, error) {
	out, err := c.Lsof(ctx, "lsof", "-Fn", "-c", "claude", "-c", "codex")
	var exit interface{ ExitCode() int }
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1) {
		return nil, fmt.Errorf("cannot list the files agents have open (lsof): %w", err)
	}
	open := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "n/") {
			open[l[1:]] = true
		}
	}
	return open, nil
}
