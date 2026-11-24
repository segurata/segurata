package macos

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

const (
	dsclBin        = "/usr/bin/dscl"
	dseditgroupBin = "/usr/sbin/dseditgroup"
	lastBin        = "/usr/bin/last"
)

// The account listings inventory reads; both cover every local record, service accounts included.
var (
	listUIDs  = []string{dsclBin, ".", "list", "/Users", "UniqueID"}
	listHomes = []string{dsclBin, ".", "list", "/Users", "NFSHomeDirectory"}
)

// firstHumanUID is where macOS starts numbering the accounts people create (the first is 501).
const firstHumanUID = 500

type localUser struct {
	name string
	uid  int
	home string
}

// human reports whether the record is an account a person signs in to: not a service account
// (UID below 500, or a name starting with "_", like _sophos at 502).
func (u localUser) human() bool { return u.uid >= firstHumanUID && !strings.HasPrefix(u.name, "_") }

// localUsers reads every local user record with its UID and home folder.
func (c *Connector) localUsers(ctx context.Context) ([]localUser, error) {
	out, err := guard(c.Run).Run(ctx, listUIDs...)
	if err != nil {
		return nil, err
	}
	homes, _ := c.text(ctx, listHomes...)
	return parseUsers(string(out), homes), nil
}

// parseUsers reads `dscl . list /Users UniqueID` ("name   501") and the NFSHomeDirectory listing
// ("name   /Users/name", where the path may hold spaces).
func parseUsers(uids, homes string) []localUser {
	home := map[string]string{}
	for _, l := range strings.Split(homes, "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			home[f[0]] = strings.Join(f[1:], " ")
		}
	}
	var users []localUser
	for _, l := range strings.Split(uids, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 {
			continue
		}
		uid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		users = append(users, localUser{name: f[0], uid: uid, home: home[f[0]]})
	}
	return users
}

// safeName is an account name that can go on a command line as one plain argument.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func adminArgv(u string) []string {
	return []string{dseditgroupBin, "-o", "checkmember", "-m", u, "admin"}
}
func lastArgv(u string) []string { return []string{lastBin, "-1", u} }

// accountChecks reports every human account other than the one running segurata. The guest
// account is the guest-account check; a deleted account's File Sharing record is the share point
// check (shareCheck names the deleted account).
func (c *Connector) accountChecks(ctx context.Context, users []localUser) []check {
	me := c.UID()
	var others []localUser
	var extra [][]string
	for _, u := range users {
		if u.human() && u.uid != me && safeName.MatchString(u.name) {
			others = append(others, u)
			extra = append(extra, adminArgv(u.name), lastArgv(u.name))
		}
	}
	if len(others) == 0 {
		return []check{{id: "local-accounts", ok: true, detail: "no human account besides yours"}}
	}
	run := guardWith(c.Run, extra...)
	var out []check
	for _, u := range others {
		res, err := run.Run(ctx, adminArgv(u.name)...)
		admin := err == nil && strings.HasPrefix(strings.TrimSpace(string(res)), "yes ")
		res, _ = run.Run(ctx, lastArgv(u.name)...)
		out = append(out, accountCheck(u, admin, pathExists(c.path(u.home)), parseLast(string(res))))
	}
	return out
}

// lastLogin is what `last -1 <user>` says: the session line, or that there is none since wtmp
// begins.
type lastLogin struct {
	when  string // "lun 23 nov 22:33 - 22:33 (00:00)", or "" for never
	since string // "wtmp begins ..." line, which bounds "never"
}

func parseLast(out string) lastLogin {
	var ll lastLogin
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, "wtmp begins"):
			ll.since = strings.TrimSpace(strings.TrimPrefix(l, "wtmp begins"))
		case ll.when == "":
			if f := strings.Fields(l); len(f) > 2 {
				ll.when = strings.Join(f[2:], " ")
			}
		}
	}
	return ll
}

func (ll lastLogin) String() string {
	switch {
	case ll.when != "":
		return "last login " + ll.when
	case ll.since != "":
		return "no login since " + ll.since
	}
	return "no recorded login"
}

func accountCheck(u localUser, admin, homeExists bool, ll lastLogin) check {
	ch := check{id: "account:" + u.name, resource: "local_account", name: u.name,
		evidence: map[string]any{"user": u.name, "uid": u.uid, "admin": admin, "home": u.home,
			"home_exists": homeExists, "last_login": ll.when, "logins_recorded_since": ll.since},
		rem: manual("If this account was for a repair technician or another temporary use, delete it in System Settings > Users & Groups (and its home folder with it). " +
			"For the next repair, create a standard (not administrator) account and delete it afterwards, or let the technician use the Guest User with File Sharing off.")}
	kind := "Local account"
	if admin {
		kind = "Administrator account"
	}
	var notes []string
	if !homeExists {
		notes = append(notes, "no home folder")
	}
	if ll.when == "" {
		notes = append(notes, ll.String())
	}
	switch {
	case admin:
		ch.sev = finding.SevHigh
	case len(notes) > 0:
		ch.sev = finding.SevLow
	default:
		ch.sev = finding.SevMedium
	}
	if len(notes) == 0 {
		notes = append(notes, ll.String())
	}
	ch.title = fmt.Sprintf("%s %q exists besides yours (%s)", kind, u.name, strings.Join(notes, ", "))
	ch.detail = fmt.Sprintf("%s (UID %d, home %s): %s; admin=%t", u.name, u.uid, orQ(u.home), strings.Join(notes, ", "), admin)
	return ch
}

// ownerRoot is a shared folder searched for items no account owns. depth 1 is the folder's
// entries; depth 2 adds their children.
type ownerRoot struct {
	dir       string
	depth     int
	autostart bool // launchd loads what is here at boot or login
}

var ownerRoots = []ownerRoot{
	{"/Users/Shared", 2, false},
	{"/Library/LaunchAgents", 1, true},
	{"/Library/LaunchDaemons", 1, true},
	{"/Library/Application Support", 2, false},
}

// maxListed caps the paths a finding lists; the count is always complete.
const maxListed = 20

// fileUID returns the owner of a file; it is a variable so tests can give files any owner.
var fileUID = ownerUID

// orphanedFiles reports, per shared folder, items owned by a UID that no local account has: what a
// deleted account leaves behind. Outside the launchd folders only UIDs in the range of accounts
// people create count, because uninstalled security agents (ESET, for one) leave folders owned by
// their removed service accounts below 500. In LaunchAgents and LaunchDaemons any unknown owner
// counts: those files start a program automatically.
func (c *Connector) orphanedFiles(users []localUser) []check {
	known := map[uint32]bool{}
	for _, u := range users {
		known[uint32(int32(u.uid))] = true // nobody is -2, which a file reports as 4294967294
	}
	var out []check
	for _, root := range ownerRoots {
		byUID := map[uint32][]string{}
		walkDepth(c.path(root.dir), root.depth, func(p string, fi fs.FileInfo) {
			uid, ok := fileUID(fi)
			if !ok || known[uid] || (!root.autostart && uid < firstHumanUID) {
				return
			}
			byUID[uid] = append(byUID[uid], c.shown(p))
		})
		out = append(out, orphanCheck(root, byUID))
	}
	return out
}

func orphanCheck(root ownerRoot, byUID map[uint32][]string) check {
	ch := check{id: "unknown-owner:" + root.dir, resource: "orphaned_files", name: root.dir}
	if len(byUID) == 0 {
		ch.ok, ch.detail = true, root.dir+": every item belongs to an existing account"
		return ch
	}
	var uids []string
	var paths []string
	for _, uid := range slices.Sorted(maps.Keys(byUID)) {
		uids = append(uids, strconv.FormatUint(uint64(uid), 10))
		paths = append(paths, byUID[uid]...)
	}
	slices.Sort(paths)
	n := len(paths)
	listed := paths[:min(n, maxListed)]
	ch.evidence = map[string]any{"folder": root.dir, "uids": uids, "count": n, "paths": listed}
	owners := "UID " + strings.Join(uids, ", ")
	ch.detail = fmt.Sprintf("%d items in %s belong to %s, which no account on this Mac has: %s", n, root.dir, owners, strings.Join(listed, ", "))
	if root.autostart {
		ch.sev = finding.SevHigh
		ch.title = fmt.Sprintf("%d launch items in %s belong to %s, which no account on this Mac has, and start automatically", n, root.dir, owners)
		ch.rem = manual("Check what each one runs (`plutil -p <path>`). If you do not recognise it, unload it with `sudo launchctl bootout system <path>` and delete the file.")
		return ch
	}
	ch.sev = finding.SevLow
	ch.title = fmt.Sprintf("%d items in %s belong to %s, which no account on this Mac has (left by a deleted account)", n, root.dir, owners)
	ch.rem = manual("Review them: delete what you do not need, or take ownership of what you keep with `sudo chown -R <you> <path>`. Other accounts may have been able to read them.")
	return ch
}

// walkDepth calls fn for every entry under dir down to depth levels, without following symbolic
// links. Folders it cannot read are skipped.
func walkDepth(dir string, depth int, fn func(string, fs.FileInfo)) {
	if depth == 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			continue
		}
		fn(p, fi)
		if fi.IsDir() {
			walkDepth(p, depth-1, fn)
		}
	}
}
