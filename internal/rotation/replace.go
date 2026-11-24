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
	"strings"
	"time"

	"github.com/segurata/segurata/internal/cliflag"
	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/remediate"
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

// fileEdit is one used_in file to change.
type fileEdit struct {
	path  string // as the ledger records it (~/…)
	abs   string // the file written: path with ~ expanded and symlinks resolved
	link  bool   // path itself is a symlink to abs
	mode  fs.FileMode
	orig  []byte
	lines []lineEdit
	next  []byte // the content to write
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
// other line of the same file. It refuses when the recorded line no longer holds it.
func locate(it *tracker.Item, key fingerprint.Key, home string) (*replacement, error) {
	switch it.Status {
	case tracker.Done, tracker.Ignored, tracker.Accepted:
		return nil, fmt.Errorf("%s is %s; `segurata rotations reopen %s` first if it still needs replacing", it.Secret.ID, stateOf(it), it.Secret.ID)
	}
	hint, ok := secretrisk.ParseHint(it.Secret.Redacted)
	if !ok {
		return nil, fmt.Errorf("%s (%s) is not a single value on one line; replace it by hand, then `segurata rotations done %s`", it.Secret.ID, it.Secret.Type, it.Secret.ID)
	}
	if len(it.Secret.UsedIn) == 0 {
		return nil, fmt.Errorf("no working file holds %s, so there is nothing to replace; once rotated: `segurata rotations done %s`", it.Secret.ID, it.Secret.ID)
	}
	r := &replacement{item: it, hint: hint, key: key}
	for _, p := range it.Secret.UsedIn {
		f, err := r.locateIn(p, home)
		if err != nil {
			return nil, err
		}
		r.files = append(r.files, f)
	}
	return r, nil
}

func (r *replacement) locateIn(p, home string) (*fileEdit, error) {
	var recorded []int
	for _, loc := range r.item.Secret.Locations {
		if loc.Path == p && loc.Line > 0 && loc.Source != "gitleaks" {
			recorded = append(recorded, loc.Line)
		}
	}
	if len(recorded) == 0 {
		return nil, fmt.Errorf("%s: the ledger records no line for it; edit it by hand", p)
	}
	abs := p
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		abs = filepath.Join(home, rest)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	link := fi.Mode()&fs.ModeSymlink != 0
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
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
	f := &fileEdit{path: p, abs: abs, link: link, mode: st.Mode().Perm(), orig: raw}
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
	return findFP(line, r.hint.Len, r.item.Fingerprint, r.key, r.hint.Fits)
}

func findFP(line string, n int, fp string, key fingerprint.Key, fits func(string) bool) string {
	for i := 0; i+n <= len(line); i++ {
		w := line[i : i+n]
		if fits(w) && key.Of(w) == fp {
			return w
		}
	}
	return ""
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
		if !secretrisk.IsShellRC(f.path) {
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
	fmt.Fprintf(w, "Replace %s  %s/%s  %s → %s\n", it.Secret.ID, it.Secret.Service, it.Secret.Type, before, after)
	for _, f := range r.files {
		where := f.path
		if f.link {
			where += " (→ " + f.abs + ")"
		}
		fmt.Fprintf(w, "\n%s  mode %o\n", where, f.mode)
		for _, le := range f.lines {
			if le.keychain {
				fmt.Fprintf(w, "  line %d: %s%s → %s%s\n", le.n, le.head, before, le.head, lookupLine(r.service))
			} else {
				fmt.Fprintf(w, "  line %d: %s → %s\n", le.n, before, after)
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
		fmt.Fprintln(w, "Warning: "+x)
	}
}

// write applies the edits: each file must still be as planned, then it is replaced atomically with
// its mode kept, after an optional backup. It returns the files written so far.
func (r *replacement) write(backup bool, now time.Time) ([]string, error) {
	var done []string
	for _, f := range r.files {
		cur, err := os.ReadFile(f.abs)
		if err != nil {
			return done, err
		}
		if !bytes.Equal(cur, f.orig) {
			return done, fmt.Errorf("%s changed since the plan; nothing more written", f.path)
		}
		if backup {
			if _, err := statefile.Backup(f.abs, f.orig, now); err != nil {
				return done, err
			}
		}
		if err := statefile.Replace(f.abs, f.next, f.mode); err != nil {
			return done, fmt.Errorf("%s: %w", f.path, err)
		}
		done = append(done, f.path)
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
			ok := strings.Contains(line, v) && r.key.Of(v) == r.newFP
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
	fs := newFlags("replace", c.Err)
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
	r.print(c.Out, v, *backup)

	if !*apply {
		it.Log(now, tracker.EvNote, tracker.ActReplacePlan, fmt.Sprintf("planned for %d %s", len(r.files), textfmt.Plural(len(r.files), "file", "files")))
		if err := t.Save(path); err != nil {
			return c.fail(err)
		}
		fmt.Fprintf(c.Out, "\nDry run: nothing was changed. Run again with --apply to apply this plan (the new value is read again).\n")
		return 0
	}
	// Confirmation needs a terminal on stdin; a value piped in with --stdin leaves --yes as the only way.
	ok, err := remediate.Confirm(c.In, c.Out, *yes, c.TTY && !*fromStdin)
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
		it.Log(now, tracker.EvNote, tracker.ActReplaceFailed, note)
		if serr := t.Save(path); serr != nil {
			fmt.Fprintln(c.Err, "rotations:", serr)
		}
		return c.fail(errors.New(note))
	}
	if r.service != "" {
		kc := keychain{run: c.Exec, account: r.account}
		if err := kc.store(ctx, r.service, v); err != nil {
			return failed(err, nil)
		}
		got, err := kc.read(ctx, r.service)
		if err != nil {
			return failed(err, nil)
		}
		if key.Of(got) != r.newFP {
			return failed(fmt.Errorf("the Keychain item %s does not hold the new value after storing it; no file was changed", r.service), nil)
		}
	}
	written, err := r.write(*backup, now)
	if err != nil {
		return failed(err, written)
	}
	if err := r.verify(v); err != nil {
		return failed(fmt.Errorf("written, but the check failed: %w", err), written)
	}
	it.Done(now, r.note(written))
	if err := t.Save(path); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.Out, "\nReplaced in %d %s and checked. %s is now rotated.\n", len(written), textfmt.Plural(len(written), "file", "files"), it.Secret.ID)
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
