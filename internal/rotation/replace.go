package rotation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/gitlocal"
	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/prompt"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/textfmt"
	"github.com/segurata/segurata/internal/tracker"
)

const replaceUsage = `usage: segurata rotations replace <id> [--stdin] [--to-keychain <service>] [--apply [--yes] [--backup]]

After you rotated the secret at the provider, copy the new value and run this. It reads the new
value from the clipboard (pbpaste), or from stdin with --stdin (piped, never typed: a terminal
would echo it). Never pass it as an argument or an environment variable: both show up in process
listings and shell history.

It checks, by HMAC fingerprint, that the new value differs from the old one and that the old value
is still on the line where the scan found it in every used_in file, then plans to replace it there
(and on any other line of the same file that holds it). Without --apply it only prints the plan,
with redacted values. With --apply it asks for confirmation (stdin must be a terminal, or pass
--yes), writes each file atomically keeping its mode, re-reads it to check that the old value is
gone and the new one is in place, marks the item rotated and clears the clipboard.
Plaintext replacements require an untracked file whose POSIX permissions keep it private.

  --to-keychain <service>  for shell rc files (~/.zshrc, ~/.zprofile, ~/.bashrc…), store the new
                           value in the login Keychain under <service> (fed to security -i on
                           stdin) and rewrite the line to read it from there:
                             export NAME="$(security find-generic-password -a "$USER" -s <service> -w)"
                           Other used_in files still get the plaintext value.
  --backup                 keep a 0600 copy of each file as it was, next to it. Off by default: a
                           backup holds the OLD value in plaintext, one more copy to delete.`

// A new value must survive being pasted unquoted into a shell line, a .env file or a JSON string.
// Provider keys, base64, base64url and webhook URLs fit; anything else is edited by hand.
var (
	safeValue   = regexp.MustCompile(`^[A-Za-z0-9._~+/=:@%-]+$`)
	safeService = regexp.MustCompile(`^[A-Za-z0-9._/@:-]+$`)
	safeAccount = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	aclDeny     = regexp.MustCompile(`^\s+[0-9]+: \S+( inherited)? deny [a-z_,]+$`)
	// assignLine is `[export ]NAME=value`, the only shape --to-keychain rewrites.
	assignLine = regexp.MustCompile(`^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*?)\s*$`)
)

const minValueLen = 8

// lineEdit is one line that holds the old value.
type lineEdit struct {
	n        int    // 1-based
	keychain bool   // rewritten to a Keychain lookup instead of the new value
	head     string // keychain: the line up to and including "=", which holds no secret
}

// fileEdit is one file to change, which may stand under several used_in names.
type fileEdit struct {
	path    string   // as the ledger records it (~/…)
	also    []string // other used_in names of the same file (a symlink and its target)
	abs     string   // the file written: path with ~ expanded and symlinks resolved
	paths   []string // absolute paths before resolving symlinks
	link    bool     // a symlink the used_in name spells out leads elsewhere: the plan names abs
	info    fs.FileInfo
	tracked bool // tracked when the ledger last saw any of its names
	mode    fs.FileMode
	orig    []byte
	lines   []lineEdit
	next    []byte // the content to write
}

// replacement is a whole replace run: the item, the old value located in its files, and the edits.
type replacement struct {
	item    *tracker.Item
	hint    secretrisk.Hint
	key     fingerprint.Key
	old     string // located in the files, kept in memory only
	newFP   string
	files   []*fileEdit
	service string
	account string // Keychain account, with service
	warn    []string
}

// locate finds the old value in every used_in file: on the line the scan recorded, and on any
// other line of the same file. It refuses when the recorded line no longer holds it. used_in names
// that resolve to one file (a symlink and its target) make one edit.
func locate(it *tracker.Item, key fingerprint.Key, home string) (*replacement, error) {
	if it.Closed() {
		return nil, fmt.Errorf("%s is %s; `segurata rotations reopen %s` first if it still needs replacing", it.Secret.ID, it.RotationStatus(), it.Secret.ID)
	}
	hint, ok := secretrisk.ParseHint(it.Secret.Redacted)
	if !ok {
		return nil, fmt.Errorf("%s (%s) is not a single value on one line; replace it by hand, then `segurata rotations done %s`", it.Secret.ID, it.Secret.Type, it.Secret.ID)
	}
	if len(it.Secret.UsedIn) == 0 {
		return nil, fmt.Errorf("no working file holds %s, so there is nothing to replace; once rotated: `segurata rotations done %s`", it.Secret.ID, it.Secret.ID)
	}
	r := &replacement{item: it, hint: hint, key: key}
	byAbs := map[string]*fileEdit{}
	for _, p := range it.Secret.UsedIn {
		f, err := r.locateIn(p, home)
		if err != nil {
			return nil, err
		}
		if same := byAbs[f.abs]; same != nil {
			same.also = append(same.also, p)
			same.paths = append(same.paths, f.paths...)
			same.tracked = same.tracked || f.tracked
			same.link = same.link || f.link
			continue
		}
		byAbs[f.abs] = f
		r.files = append(r.files, f)
	}
	return r, nil
}

// names are the used_in names of the file.
func (f *fileEdit) names() []string { return append([]string{f.path}, f.also...) }

func (r *replacement) locateIn(p, home string) (*fileEdit, error) {
	var recorded []int
	var tracked bool
	for _, loc := range r.item.Secret.Locations {
		if loc.Path == p && loc.Line > 0 && loc.Source != "gitleaks" && !loc.Gone {
			recorded = append(recorded, loc.Line)
			tracked = tracked || loc.Tracked
		}
	}
	if len(recorded) == 0 {
		return nil, fmt.Errorf("%s: the ledger records no line for it; edit it by hand", p)
	}
	base, rest := filepath.Dir(p), filepath.Base(p)
	if r, ok := strings.CutPrefix(p, "~/"); ok {
		base, rest = home, r
	}
	if !filepath.IsAbs(base) {
		return nil, fmt.Errorf("%q is not an absolute file path", p)
	}
	original := filepath.Join(base, rest)
	abs, err := filepath.EvalSymlinks(original)
	if err != nil {
		return nil, err
	}
	// Only links in the part the name spells out (below ~, or the file itself) are worth showing:
	// the directories above it, like macOS /var -> /private/var, say nothing about this file.
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	f := &fileEdit{path: p, abs: abs, paths: []string{original}, link: filepath.Join(resolvedBase, rest) != abs, info: st, tracked: tracked,
		mode: st.Mode().Perm(), orig: raw}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if v := r.find(line); v != "" {
			if r.old == "" {
				r.old = v
			}
			f.lines = append(f.lines, lineEdit{n: i + 1})
		}
	}
	for _, n := range recorded {
		if !f.has(n) {
			return nil, fmt.Errorf("%s: the old value is no longer on line %d (the file changed since the scan); run `segurata inventory local-secrets` and `segurata rotations sync`, then try again", p, n)
		}
	}
	return f, nil
}

func (f *fileEdit) has(n int) bool {
	for _, l := range f.lines {
		if l.n == n {
			return true
		}
	}
	return false
}

// find returns the substring of line whose fingerprint is the item's, or "". The hint gives the
// value's length, prefix and last characters, so only windows that fit it are fingerprinted.
func (r *replacement) find(line string) string {
	return r.key.Find(line, r.hint.Len, r.item.Fingerprint, r.hint.Fits)
}

// checkNew validates the new value and fixes the edits. The value is never part of an error.
func (r *replacement) checkNew(raw []byte, service string) (string, error) {
	v := strings.TrimSpace(string(raw))
	switch {
	case v == "":
		return "", errors.New("the new value is empty: copy it from the provider first")
	case strings.ContainsAny(v, "\r\n"):
		return "", errors.New("the new value spans several lines; replace it by hand")
	case len(v) < minValueLen:
		return "", fmt.Errorf("the new value is %d characters long, too short for a key: is the right thing copied?", len(v))
	case !safeValue.MatchString(v):
		return "", errors.New("the new value has characters other than letters, digits and . _ ~ + / = : @ % - (quotes, spaces, $, # would need escaping in a shell or .env line); replace it by hand")
	}
	r.newFP = r.key.Of(v)
	if r.newFP == r.item.Fingerprint {
		return "", errors.New("the new value is the old one (same fingerprint): rotate it at the provider and copy the new value")
	}
	if p := r.hint.Prefix; p != "" && !strings.HasPrefix(v, p) {
		r.warn = append(r.warn, fmt.Sprintf("the new value does not start with %q like the old one: check that the clipboard holds the right key", p))
	}
	r.service = service
	if service != "" {
		if !safeService.MatchString(service) {
			return "", fmt.Errorf("--to-keychain %q: use letters, digits and . _ / @ : -", service)
		}
		if !safeAccount.MatchString(r.account) {
			return "", fmt.Errorf("user name %q cannot be a Keychain account", r.account)
		}
		if err := r.planKeychain(); err != nil {
			return "", err
		}
	}
	for _, f := range r.files {
		f.next = []byte(r.rewrite(f, v))
	}
	return v, nil
}

// planKeychain marks the lines of shell rc files that become Keychain lookups. Each must be a
// plain `[export ]NAME=old` (quoted or not), so rewriting the whole line loses nothing.
func (r *replacement) planKeychain() error {
	rc := false
	for _, f := range r.files {
		if !slices.ContainsFunc(f.names(), secretrisk.IsShellRC) {
			continue
		}
		rc = true
		lines := strings.Split(string(f.orig), "\n")
		for i := range f.lines {
			le := &f.lines[i]
			m := assignLine.FindStringSubmatch(lines[le.n-1])
			if m == nil || unquote(m[4]) != r.old {
				return fmt.Errorf("%s:%d is not a plain `export NAME=value` line; drop --to-keychain or edit it by hand", f.path, le.n)
			}
			le.keychain, le.head = true, m[1]+m[2]+m[3]+"="
		}
	}
	if !rc {
		return fmt.Errorf("--to-keychain applies to shell rc files (%s), and no used_in file is one", strings.Join(secretrisk.ShellRC, ", "))
	}
	return nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// rewrite returns the file with every planned line edited.
func (r *replacement) rewrite(f *fileEdit, v string) string {
	lines := strings.Split(string(f.orig), "\n")
	for _, le := range f.lines {
		if le.keychain {
			lines[le.n-1] = le.head + lookupLine(r.service)
		} else {
			lines[le.n-1] = strings.ReplaceAll(lines[le.n-1], r.old, v)
		}
	}
	return strings.Join(lines, "\n")
}

// print shows the plan. It never prints a line of a file: the rest of the line may hold another
// secret. Values appear only as redacted hints.
func (r *replacement) print(w io.Writer, v string, backup bool) {
	it := r.item
	before, after := it.Secret.Redacted, secretrisk.Redact(it.Secret.Type, r.hint.Prefix, v)
	fmt.Fprintln(w, textfmt.Terminal(fmt.Sprintf("Replace %s  %s/%s  %s → %s", it.Secret.ID, it.Secret.Service, it.Secret.Type, before, after)))
	for _, f := range r.files {
		where := f.path
		if f.link {
			where += " (→ " + f.abs + ")"
		}
		if len(f.also) > 0 {
			where += ", also " + strings.Join(f.also, ", ")
		}
		fmt.Fprintf(w, "\n%s  mode %o\n", textfmt.Terminal(where), f.mode)
		for _, le := range f.lines {
			if le.keychain {
				fmt.Fprintf(w, "  line %d: %s%s → %s%s\n", le.n, textfmt.Terminal(le.head), textfmt.Terminal(before), textfmt.Terminal(le.head), lookupLine(r.service))
			} else {
				fmt.Fprintf(w, "  line %d: %s → %s\n", le.n, textfmt.Terminal(before), textfmt.Terminal(after))
			}
		}
	}
	if r.service != "" {
		fmt.Fprintf(w, "\nKeychain: store the new value as service %q, account %q (security -i, value on stdin), then read it back to check.\n", r.service, r.account)
	}
	fmt.Fprintln(w, "\nThen: re-read every file (old fingerprint gone, new value in place), mark the item rotated, clear the clipboard.")
	if backup {
		fmt.Fprintln(w, "Backup: a 0600 copy of each file as it was, next to it. It holds the old value in plaintext: delete it once the new key works.")
	} else {
		fmt.Fprintln(w, "No backup (a backup would be one more plaintext copy of the old value); --backup keeps one.")
	}
	for _, x := range r.warn {
		fmt.Fprintln(w, "Warning: "+textfmt.Terminal(x))
	}
}

func (r *replacement) preflight(ctx context.Context) error {
	for _, f := range r.files {
		if err := f.validate(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (f *fileEdit) validate(ctx context.Context) error {
	changed := fmt.Errorf("%q changed since the plan; run the preview again", f.path)
	for _, path := range f.paths {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != f.abs {
			return changed
		}
	}
	st, err := os.Lstat(f.abs)
	if err != nil || !os.SameFile(f.info, st) || st.Mode() != f.info.Mode() {
		return changed
	}
	if uid, ok := statefile.OwnerID(st); !ok || uid != os.Getuid() {
		return fmt.Errorf("%q: file ownership could not be verified; edit it by hand", f.path)
	}
	dirs, private, err := parentPrivacy(f.abs)
	if err != nil {
		return fmt.Errorf("%q: %w", f.path, err)
	}
	raw, err := os.ReadFile(f.abs)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, f.orig) {
		return changed
	}
	if !slices.ContainsFunc(f.lines, func(line lineEdit) bool { return !line.keychain }) {
		return nil
	}
	if f.tracked {
		return fmt.Errorf("%q was tracked by Git at the last scan; replace the secret by hand outside the index", f.path)
	}
	paths := f.paths
	if !slices.Contains(paths, f.abs) {
		paths = append(slices.Clone(paths), f.abs)
	}
	for _, path := range paths {
		tracked, err := gitlocal.Tracked(ctx, path)
		if err != nil {
			return fmt.Errorf("%q: could not check the Git index: %w", f.path, err)
		}
		if tracked {
			return fmt.Errorf("%q is tracked by Git; replace the secret by hand outside the index", f.path)
		}
	}
	if st.Mode().Perm()&0o077 != 0 && !private {
		return fmt.Errorf("%q can be accessed by other users; restrict its permissions before replacing the secret", f.path)
	}
	if runtime.GOOS == "darwin" {
		paths := append(dirs, f.abs)
		// macOS ACLs can grant access beyond the mode bits or propagate to the temporary file.
		// ls -e emits an extra line per entry. -bn keeps filenames on one line and IDs numeric.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := proc.Command(ctx, "/bin/ls", append([]string{"-ldenb", "--"}, paths...)...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.Output()
		if err != nil || !safeACLReport(out, len(paths)) {
			return fmt.Errorf("%q: unexpected access control entries or unreadable ACLs; edit it by hand", f.path)
		}
	}
	return nil
}

func safeACLReport(report []byte, paths int) bool {
	listed := 0
	for line := range bytes.SplitSeq(bytes.TrimSuffix(report, []byte{'\n'}), []byte{'\n'}) {
		if len(line) > 0 && (line[0] == '-' || line[0] == 'd') {
			listed++
		} else if !aclDeny.Match(line) {
			return false
		}
	}
	return listed == paths
}

// Untrusted accounts must not be able to change the path between validation and the rename.
// A sticky directory owned by root or by the caller protects entries with trusted owners.
// A private parent owned by the caller also keeps group and other users from reading the file.
func parentPrivacy(path string) (dirs []string, private bool, err error) {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		st, err := os.Stat(dir)
		if err != nil {
			return nil, false, err
		}
		uid, ok := statefile.OwnerID(st)
		if !ok || uid != 0 && uid != os.Getuid() ||
			st.Mode().Perm()&0o022 != 0 && st.Mode()&fs.ModeSticky == 0 {
			return nil, false, fmt.Errorf("directory %q can be changed by another account; edit it by hand", dir)
		}
		dirs = append(dirs, dir)
		private = private || uid == os.Getuid() && st.Mode().Perm()&0o011 == 0
		if filepath.Dir(dir) == dir {
			return dirs, private, nil
		}
	}
}

// write applies the edits: every file must still be as planned, checked before any is written,
// then each is replaced atomically with its mode kept, after an optional backup. It returns the
// names of the files written so far.
func (r *replacement) write(ctx context.Context, backup bool, now time.Time) ([]string, error) {
	if err := r.preflight(ctx); err != nil {
		return nil, err
	}
	var done []string
	for _, f := range r.files {
		if err := f.validate(ctx); err != nil {
			return done, err
		}
		if backup {
			if _, err := statefile.Backup(f.abs, f.orig, now); err != nil {
				return done, err
			}
		}
		if err := statefile.Replace(f.abs, f.next, f.mode); err != nil {
			return done, fmt.Errorf("%s: %w", f.path, err)
		}
		done = append(done, f.names()...)
	}
	return done, nil
}

// verify re-reads every file: the old fingerprint must be gone from all of it, each edited line
// must hold the new value (or the Keychain lookup) and the mode must be unchanged.
func (r *replacement) verify(v string) error {
	for _, f := range r.files {
		st, err := os.Stat(f.abs)
		if err != nil {
			return err
		}
		if st.Mode().Perm() != f.mode {
			return fmt.Errorf("%s: mode is %o, was %o", f.path, st.Mode().Perm(), f.mode)
		}
		raw, err := os.ReadFile(f.abs)
		if err != nil {
			return err
		}
		lines := strings.Split(string(raw), "\n")
		for i, line := range lines {
			if r.find(line) != "" {
				return fmt.Errorf("%s:%d still holds the old value", f.path, i+1)
			}
		}
		for _, le := range f.lines {
			if le.n > len(lines) {
				return fmt.Errorf("%s lost line %d", f.path, le.n)
			}
			line := lines[le.n-1]
			ok := strings.Contains(line, v)
			if le.keychain {
				ok = line == le.head+lookupLine(r.service)
			}
			if !ok {
				return fmt.Errorf("%s:%d does not hold the new value", f.path, le.n)
			}
		}
	}
	return nil
}

// note is the history entry of a successful replace.
func (r *replacement) note(written []string) string {
	n := "replaced in " + strings.Join(written, ", ")
	if r.service != "" {
		n += "; new value in the Keychain as " + r.service
	}
	return n
}

func (c CLI) replace(t *tracker.Tracker, path string, args []string, now time.Time) int {
	fs := cliflag.New("rotations replace", c.Err)
	fs.Usage = func() { fmt.Fprintln(c.Err, replaceUsage) }
	apply := fs.Bool("apply", false, "apply the plan after confirmation (default: dry run)")
	yes := fs.Bool("yes", false, "with --apply, do not ask for confirmation")
	fromStdin := fs.Bool("stdin", false, "read the new value from stdin (piped) instead of the clipboard")
	backup := fs.Bool("backup", false, "keep a 0600 copy of each file as it was (holds the old value)")
	service := fs.String("to-keychain", "", "store the value in the Keychain under this service and make shell rc lines read it")
	pos, err := cliflag.Parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(c.Err, replaceUsage)
		return 2
	}
	it, err := t.FindRotate(pos[0])
	if err != nil {
		return c.fail(err)
	}
	home, err := c.Home()
	if err != nil {
		return c.fail(err)
	}
	keyPath := c.KeyPath
	if keyPath == "" {
		keyPath = fingerprint.DefaultPath(home)
	}
	key, err := fingerprint.Open(keyPath)
	if err != nil {
		return c.fail(fmt.Errorf("fingerprint key (the one the scan used): %w", err))
	}
	r, err := locate(it, key, home)
	if err != nil {
		return c.fail(err)
	}
	r.account = c.User

	ctx := context.Background()
	clip := clipboard{run: c.Exec}
	var raw []byte
	if *fromStdin {
		if c.TTY {
			return c.fail(errors.New("--stdin reads a piped value; typed on a terminal it would be echoed. Copy it and drop --stdin to read the clipboard"))
		}
		raw, err = io.ReadAll(io.LimitReader(c.In, 64<<10))
	} else {
		raw, err = clip.paste(ctx)
	}
	if err != nil {
		return c.fail(fmt.Errorf("reading the new value: %w", err))
	}
	v, err := r.checkNew(raw, *service)
	if err != nil {
		return c.fail(err)
	}
	if err := r.preflight(ctx); err != nil {
		return c.fail(err)
	}
	r.print(c.Out, v, *backup)

	// The copy loaded at the start is stale by now (the clipboard, the confirmation, the writes):
	// each outcome is recorded into the tracker as it is when recording.
	record := func(change func(*tracker.Item)) error {
		return tracker.Update(path, now, func(fresh *tracker.Tracker) error {
			cur, err := fresh.FindRotate(it.Fingerprint)
			if err == nil {
				change(cur)
			}
			return err
		})
	}
	if !*apply {
		plan := fmt.Sprintf("planned for %s", textfmt.Count(len(r.files), "file", "files"))
		if err := record(func(it *tracker.Item) { it.Log(now, tracker.EvNote, tracker.ActReplacePlan, plan) }); err != nil {
			return c.fail(err)
		}
		fmt.Fprintln(c.Out, "\nDry run recorded in the tracker. Run again with --apply to read the new value and replace the credential.")
		return 0
	}
	// Confirmation needs a terminal on stdin; a value piped in with --stdin leaves --yes as the only way.
	ok, err := prompt.Confirm(c.In, c.Out, *yes, c.TTY && !*fromStdin)
	if err != nil {
		return c.fail(err)
	}
	if !ok {
		fmt.Fprintln(c.Out, "Not applied.")
		return 0
	}
	failed := func(err error, written []string) int {
		note := err.Error()
		if len(written) > 0 {
			note += "; already written: " + strings.Join(written, ", ")
		}
		if rerr := record(func(it *tracker.Item) { it.Log(now, tracker.EvNote, tracker.ActReplaceFailed, textfmt.Terminal(note)) }); rerr != nil {
			fmt.Fprintln(c.Err, "rotations:", rerr)
		}
		return c.fail(errors.New(note))
	}
	if r.service != "" {
		if err := r.preflight(ctx); err != nil {
			return failed(err, nil)
		}
		kc := keychain.Keychain{Run: c.Exec, Account: r.account}
		if err := kc.Store(ctx, r.service, v); err != nil {
			return failed(err, nil)
		}
		got, err := kc.Read(ctx, r.service)
		if err != nil {
			return failed(err, nil)
		}
		if key.Of(got) != r.newFP {
			return failed(fmt.Errorf("the Keychain item %s does not hold the new value after storing it; no file was changed", r.service), nil)
		}
	}
	written, err := r.write(ctx, *backup, now)
	if err != nil {
		if r.service != "" {
			err = fmt.Errorf("the Keychain item was updated: %w", err)
		}
		return failed(err, written)
	}
	if err := r.verify(v); err != nil {
		return failed(fmt.Errorf("written, but the check failed: %w", err), written)
	}
	if err := record(func(it *tracker.Item) { it.Done(now, textfmt.Terminal(r.note(written))) }); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "\nReplaced in %s and checked. %s is now rotated.\n", textfmt.Count(len(r.files), "file", "files"), it.Secret.ID)
	if !*fromStdin {
		if err := clip.clear(ctx); err != nil {
			fmt.Fprintln(c.Err, "rotations: could not clear the clipboard, clear it yourself:", err)
		} else {
			fmt.Fprintln(c.Out, "Clipboard cleared.")
		}
	}
	fmt.Fprintf(c.Out, "Restart whatever reads these files (open a new shell for rc files). Copies in history, transcripts and logs still hold the old value: `segurata rotations show %s`.\nNext: segurata rotations next\n", it.Secret.ID)
	return 0
}
