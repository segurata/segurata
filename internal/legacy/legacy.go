// Package legacy moves a machine set up under segurata's former name, securizame, to the current
// layout. Migrate runs once at startup, before config or state is read: it renames the old
// directories when the new ones do not exist yet, never overwriting anything, and says what it
// moved on one line each. KeychainMigrate is `segurata keychain-migrate`, which moves the Keychain
// items the config names under the old prefix. See README.md, "Upgrading from securizame".
package legacy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/segurata/segurata/internal/keychain"
	"github.com/segurata/segurata/internal/statefile"
	"github.com/segurata/segurata/internal/tracker"
)

const (
	oldName = "securizame"
	newName = "segurata"
	// oldAgent is the launchd label the former name installed its scheduled agent under.
	oldAgent = "com." + oldName + ".inventory"
)

// Env is the machine to migrate. Keychain only answers whether an item exists: Migrate never
// reads a value.
type Env struct {
	Home     string
	UID      int
	Keychain keychain.Keychain
	Out      io.Writer // one line per move, warnings and hints (stderr)
}

// move is one directory that changes name.
type move struct{ from, to string }

func (e Env) moves() (home, config move, rest []move) {
	j := func(p ...string) string { return filepath.Join(append([]string{e.Home}, p...)...) }
	home = move{j("." + oldName), j("." + newName)}
	config = move{j(".config", oldName), j(".config", newName)}
	rest = []move{
		{j(".cache", oldName), j(".cache", newName)},
		{j("Library", "Logs", oldName), j("Library", "Logs", newName)},
	}
	return home, config, rest
}

// Migrate moves ~/.securizame, ~/.config/securizame, ~/.cache/securizame and
// ~/Library/Logs/securizame to their segurata names, and the files of ~/.local/state/securizame
// into ~/.segurata. A rename keeps every mode and byte, so the fingerprint key and with it every
// fingerprint stay the same. When both names exist it warns and leaves both: the new one is used.
// After moving the tracker it renames the commands its items suggest; after moving the config it
// renames each keychain:securizame-* reference whose segurata-* item already exists.
func Migrate(ctx context.Context, e Env) error {
	home, config, rest := e.moves()
	var errs []error
	movedHome, err := e.rename(home)
	errs = append(errs, err)
	errs = append(errs, e.moveState(home.to))
	if movedHome {
		errs = append(errs, e.renameTracker(filepath.Join(home.to, "tracker.json")))
	}
	movedConfig, err := e.rename(config)
	errs = append(errs, err)
	if movedConfig {
		errs = append(errs, e.renameReferences(ctx, filepath.Join(config.to, "config.json")))
	}
	for _, m := range rest {
		_, err := e.rename(m)
		errs = append(errs, err)
	}
	plist := filepath.Join(e.Home, "Library", "LaunchAgents", oldAgent+".plist")
	if _, err := os.Lstat(plist); err == nil {
		fmt.Fprintf(e.Out, "%s: the scheduled agent of the old name is still installed and runs the old binary; remove it with\n"+
			"  launchctl bootout gui/%d/%s; rm %s\nthen install the new one: segurata schedule install --apply\n", newName, e.UID, oldAgent, plist)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("moving %s's files to %s: %w", oldName, newName, err)
	}
	return nil
}

func exists(p string) (bool, error) {
	_, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// rename moves m.from to m.to when only m.from exists, and reports whether it did.
func (e Env) rename(m move) (bool, error) {
	from, err := exists(m.from)
	if err != nil || !from {
		return false, err
	}
	to, err := exists(m.to)
	if err != nil {
		return false, err
	}
	if to {
		fmt.Fprintf(e.Out, "%s: both %s and %s exist; using %s (remove %s once nothing in it is needed)\n", newName, m.from, m.to, m.to, m.from)
		return false, nil
	}
	if err := os.Rename(m.from, m.to); err != nil {
		return false, err
	}
	fmt.Fprintf(e.Out, "%s: moved %s to %s\n", newName, m.from, m.to)
	return true, nil
}

// moveState moves each entry of ~/.local/state/securizame (the old rotation ledger, scheduled
// runs' output and reports) into dir, then removes the old directory once it is empty.
func (e Env) moveState(dir string) error {
	old := filepath.Join(e.Home, ".local", "state", oldName)
	entries, err := os.ReadDir(old)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	left := 0
	for _, en := range entries {
		moved, err := e.rename(move{filepath.Join(old, en.Name()), filepath.Join(dir, en.Name())})
		if err != nil {
			return err
		}
		if !moved {
			left++
		}
	}
	if left == 0 {
		return os.Remove(old)
	}
	return nil
}

// textRename renames the old command in text the tool generated: the word itself, its Keychain
// prefix and its home paths, but not a path that only contains it (a checkout called securizame).
var textRename = strings.NewReplacer("~/."+oldName, "~/."+newName, "~/.config/"+oldName, "~/.config/"+newName)

var oldWord = regexp.MustCompile(`(^|[^\w./~-])` + oldName + `\b`)

func renameText(s string) string {
	return oldWord.ReplaceAllString(textRename.Replace(s), "${1}"+newName)
}

// renameTracker rewrites what the tracker stored from the old binary's own words: who takes the
// next step, its action and command, decision questions and options, and theme descriptions.
// Finding titles refresh on the next sync; notes and reasons are the owner's and stay as written.
func (e Env) renameTracker(path string) error {
	t, err := tracker.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	changed := false
	set := func(s *string) {
		if r := renameText(*s); r != *s {
			*s, changed = r, true
		}
	}
	for i := range t.Themes {
		set(&t.Themes[i].Description)
	}
	for _, it := range t.Items {
		if n := it.Next; n != nil {
			if n.Who == oldName {
				n.Who, changed = tracker.Segurata, true
			}
			set(&n.Action)
			set(&n.Command)
		}
		if d := it.Decision; d != nil {
			set(&d.Question)
			for i := range d.Options {
				set(&d.Options[i])
			}
		}
	}
	if !changed {
		return nil
	}
	if err := t.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(e.Out, "%s: renamed the commands the tracker suggests in %s\n", newName, path)
	return nil
}

// refPattern finds the Keychain references the config holds under the old prefix.
var refPattern = regexp.MustCompile(`"keychain:(` + oldName + `-[A-Za-z0-9._@/:-]+)"`)

// oldServices returns the distinct old Keychain services raw names, in the order they appear.
func oldServices(raw []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range refPattern.FindAllSubmatch(raw, -1) {
		if s := string(m[1]); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func newService(old string) string { return newName + strings.TrimPrefix(old, oldName) }

// rewriteReference replaces one quoted reference, leaving the rest of the file as the owner wrote it.
func rewriteReference(path, old string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	q := func(s string) string { return `"keychain:` + s + `"` }
	return statefile.Write(path, []byte(strings.ReplaceAll(string(raw), q(old), q(newService(old)))))
}

// renameReferences renames each old reference whose new Keychain item already exists, and says how
// to move the rest.
func (e Env) renameReferences(ctx context.Context, path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var pending []string
	for _, old := range oldServices(raw) {
		if _, err := e.Keychain.Find(ctx, newService(old)); err != nil {
			pending = append(pending, old)
			continue
		}
		if err := rewriteReference(path, old); err != nil {
			return err
		}
		fmt.Fprintf(e.Out, "%s: %s now references keychain:%s\n", newName, path, newService(old))
	}
	if len(pending) > 0 {
		fmt.Fprintf(e.Out, "%s: %s still references Keychain items under the old name (%s); they keep working. "+
			"To move them to %s-* names: segurata keychain-migrate (a dry run; then --apply)\n",
			newName, path, strings.Join(pending, ", "), newName)
	}
	return nil
}
