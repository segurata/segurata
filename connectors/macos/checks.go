package macos

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/finding"
)

func (c *Connector) systemChecks(ctx context.Context) []check {
	var out []check

	s, _ := c.text(ctx, "/usr/bin/fdesetup", "status")
	s = firstLine(s)
	out = append(out, check{ID: "filevault", OK: strings.Contains(s, "is On"), Detail: s, Sev: finding.SevHigh,
		Title: "FileVault disk encryption is off",
		Rem:   posture.Manual("Turn on FileVault in System Settings > Privacy & Security > FileVault, and keep the recovery key somewhere safe.")})

	s, _ = c.text(ctx, "/usr/bin/csrutil", "status")
	out = append(out, check{ID: "sip", OK: strings.Contains(s, "enabled"), Detail: s, Sev: finding.SevHigh,
		Title: "System Integrity Protection is disabled",
		Rem:   posture.Manual("Start up in macOS Recovery, open Terminal and run `csrutil enable`, then restart.")})

	s, _ = c.text(ctx, "/usr/sbin/spctl", "--status")
	out = append(out, check{ID: "gatekeeper", OK: strings.Contains(s, "assessments enabled"), Detail: s, Sev: finding.SevHigh,
		Title: "Gatekeeper is disabled: apps from anywhere run without a check",
		Rem:   posture.Manual("In System Settings > Privacy & Security > Security, allow applications from the App Store and identified developers.")})

	s, _ = c.text(ctx, socketfilterfw, "--getglobalstate")
	out = append(out, check{ID: "firewall", OK: strings.Contains(s, "enabled"), Detail: s, Sev: finding.SevMedium,
		Title: "The macOS application firewall is off",
		Rem: finding.Remediation{Action: actionFirewallEnable,
			Summary: "Turn on the firewall (System Settings > Network > Firewall), or run `segurata remediate <id> --apply`."}})

	s, _ = c.text(ctx, socketfilterfw, "--getstealthmode")
	out = append(out, check{ID: "firewall-stealth", OK: strings.Contains(s, " on") || strings.Contains(s, "enabled"), Detail: s, Sev: finding.SevLow,
		Title: "Firewall stealth mode is off: the Mac answers probes and pings",
		Rem: finding.Remediation{Action: actionFirewallStealth,
			Summary: "Turn on stealth mode (System Settings > Network > Firewall > Options), or run `segurata remediate <id> --apply`."}})

	updates := posture.Manual("Turn on every automatic update option in System Settings > General > Software Update > Automatic Updates.")
	for _, k := range updateKeys {
		v := c.pref(ctx, defaultsBin, "read", softwareUpdatePrefs, k)
		out = append(out, check{ID: "update-" + k, OK: v != "0", Detail: orUnset(v), Sev: finding.SevMedium,
			Title: fmt.Sprintf("Automatic update setting %s is off", k), Rem: updates})
	}
	v := c.pref(ctx, defaultsBin, "read", commercePrefs, "AutoUpdate")
	out = append(out, check{ID: "update-appstore-apps", OK: v != "0", Detail: orUnset(v), Sev: finding.SevLow,
		Title: "App Store apps do not update automatically",
		Rem:   posture.Manual("Turn on App Store > Settings > Automatic Updates.")})

	s, _ = c.text(ctx, "/usr/sbin/sysadminctl", "-screenLock", "status")
	s = screenLockText(s)
	out = append(out, check{ID: "screen-lock", OK: screenLockOK(s), Detail: s, Sev: finding.SevMedium,
		Title: "The screen does not lock right away when it sleeps",
		Rem:   posture.Manual("In System Settings > Lock Screen, set \"Require password after screen saver begins or display is turned off\" to Immediately.")})

	saver := c.readSetting(ctx, defaultsBin, "-currentHost", "read", "com.apple.screensaver", "idleTime")
	if !saver.set && saver.err == "" {
		saver = c.readSetting(ctx, defaultsBin, "read", "com.apple.screensaver", "idleTime")
	}
	pm, pmOK := c.text(ctx, "/usr/bin/pmset", "-g")
	display := setting{err: pm}
	if pmOK {
		display = setting{}
		if v := displaySleep(pm); v != "" {
			display.value, display.set = v, true
		}
	}
	out = append(out, screenIdleCheck(saver, display))

	user := c.pref(ctx, defaultsBin, "read", loginWindowPrefs, "autoLoginUser")
	out = append(out, check{ID: "auto-login", OK: user == "", Detail: "automatic login as " + user, Sev: finding.SevHigh,
		Title: "The Mac logs in automatically, without a password",
		Rem:   posture.Manual("Set System Settings > Users & Groups > Automatically log in as: Off.")})
	if user == "" {
		out[len(out)-1].Detail = "off"
	}

	g := c.pref(ctx, defaultsBin, "read", loginWindowPrefs, "GuestEnabled")
	if g == "" {
		g = "0"
	}
	out = append(out, check{ID: "guest-account", OK: g == "0", Detail: "GuestEnabled=" + g, Sev: finding.SevMedium,
		Title: "The guest account is enabled",
		Rem:   posture.Manual("Turn off System Settings > Users & Groups > Guest User > Allow guests to log in to this computer.")})

	s, _ = c.text(ctx, "/usr/sbin/systemsetup", "-getremotelogin")
	rl := check{ID: "remote-login", OK: strings.Contains(s, "Off"), Detail: s, Sev: finding.SevMedium,
		Title: "Remote Login (SSH) is on",
		Rem:   posture.Manual("Turn off System Settings > General > Sharing > Remote Login unless you use SSH into this Mac.")}
	if strings.Contains(s, "administrator") {
		rl.Skip = "systemsetup needs admin; the listening ports check covers SSH"
	}
	return append(out, rl)
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }

func orUnset(v string) string {
	if v == "" {
		return "unset (default)"
	}
	return v
}

func orQ(v string) string {
	if v == "" {
		return "?"
	}
	return v
}

// setting tells an unset defaults key (neither set nor err) from a failed read.
type setting struct {
	value string
	set   bool
	err   string
}

func (c *Connector) readSetting(ctx context.Context, args ...string) setting {
	s, ok := c.text(ctx, args...)
	switch {
	case ok:
		return setting{value: s, set: true}
	case strings.Contains(s, "does not exist"):
		return setting{}
	}
	return setting{err: s}
}

// maxIdleLock is in seconds. The screen locks when the saver starts or the display sleeps.
const maxIdleLock = 10 * 60

// screenIdleCheck: saver idleTime is in seconds, displaysleep in minutes; 0 is never for both.
func screenIdleCheck(saver, display setting) check {
	ch := check{ID: "screensaver", Sev: finding.SevLow,
		Rem: posture.Manual("In System Settings > Lock Screen, set \"Start Screen Saver when inactive\" or \"Turn display off when inactive\" to 10 minutes or less.")}
	saverSecs, saverOK := seconds(saver, 1)
	displaySecs, displayOK := seconds(display, 60)
	ch.Detail = fmt.Sprintf("screen saver %s, display off %s", describeIdle(saver, saverSecs, "idleTime"), describeIdle(display, displaySecs, "displaysleep"))
	if !saverOK && !displayOK {
		ch.Skip, ch.SkipState = "could not read the idle timing: "+ch.Detail, finding.StateError
		return ch
	}
	effective := 0
	for _, v := range []int{saverSecs, displaySecs} {
		if v > 0 && (effective == 0 || v < effective) {
			effective = v
		}
	}
	ch.Evidence = map[string]any{"effective_seconds": effective, "max_seconds": maxIdleLock}
	switch {
	case effective == 0 && saverOK && displayOK:
		ch.Sev = finding.SevMedium
		ch.Title = "The screen never locks on its own: screen saver and display sleep are both off"
	case effective == 0:
		ch.Skip, ch.SkipState = "could not judge the idle timing: "+ch.Detail, finding.StateError
	case effective > maxIdleLock:
		ch.Title = fmt.Sprintf("The screen locks only after %d minutes idle (more than %d)", effective/60, maxIdleLock/60)
	default:
		ch.OK = true
	}
	return ch
}

func seconds(s setting, unit int) (int, bool) {
	if !s.set {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(s.value))
	if err != nil {
		return 0, false
	}
	return n * unit, true
}

func describeIdle(s setting, secs int, key string) string {
	switch {
	case s.err != "":
		return fmt.Sprintf("unreadable (%s: %s)", key, firstLine(s.err))
	case !s.set:
		return "not set (macOS default)"
	case secs == 0:
		return "never"
	}
	return fmt.Sprintf("after %d s", secs)
}

// screenLockText drops sysadminctl's log prefix ("2026-11-23 ... sysadminctl[1:2] ").
func screenLockText(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	last := lines[len(lines)-1]
	if _, after, ok := strings.Cut(last, "] "); ok {
		return after
	}
	return last
}

var lockDelay = regexp.MustCompile(`delay is (\d+) seconds`)

func screenLockOK(s string) bool {
	if strings.Contains(s, "immediate") {
		return true
	}
	m := lockDelay.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	n, _ := strconv.Atoi(m[1])
	return n <= 5
}

func displaySleep(pmset string) string {
	for _, l := range strings.Split(pmset, "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "displaysleep" {
			return f[1]
		}
	}
	return ""
}

var updateLabel = regexp.MustCompile(`(?m)^\s*\* Label: (.+)$`)

func (c *Connector) pendingUpdates(ctx context.Context) check {
	ver, _ := c.text(ctx, "/usr/bin/sw_vers", "-productVersion")
	out, err := c.read(ctx, softwareUpdate, "-l")
	ch := check{ID: "updates-pending", Sev: finding.SevMedium, Title: "macOS has updates waiting to be installed",
		Rem: posture.Manual("Install them in System Settings > General > Software Update.")}
	if errors.Is(err, context.DeadlineExceeded) {
		ch.Skip = "softwareupdate -l did not answer within 120 s"
		return ch
	}
	var labels []string
	for _, m := range updateLabel.FindAllStringSubmatch(string(out), -1) {
		labels = append(labels, strings.TrimSpace(m[1]))
	}
	if len(labels) == 0 {
		ch.OK, ch.Detail = true, ver+", no pending updates"
		return ch
	}
	ch.Detail = ver + ", pending: " + strings.Join(labels, ",")
	ch.Evidence = map[string]any{"macos_version": ver, "pending": labels}
	return ch
}

var knownPorts = map[string]struct{ label, fix string }{
	"22":   {"SSH (Remote Login)", "Turn off System Settings > General > Sharing > Remote Login."},
	"445":  {"SMB (File Sharing)", "Turn off System Settings > General > Sharing > File Sharing if you do not share folders with other devices. Each shared folder is its own finding."},
	"548":  {"AFP (File Sharing)", "Turn off System Settings > General > Sharing > File Sharing."},
	"3283": {"Apple Remote Desktop", "Turn off System Settings > General > Sharing > Remote Management."},
	"5900": {"Screen Sharing/VNC", "Turn off System Settings > General > Sharing > Screen Sharing and Remote Management."},
	"5000": {"AirPlay Receiver", ""},
	"7000": {"AirPlay Receiver", ""},
	"3689": {"Music Sharing", "Turn off Music > Settings > Sharing > Share my library on my local network."},
}

type listener struct {
	port  string
	addrs []string
	proc  string
	path  string // "" when ps did not list the pid
}

// listeningPorts reports every TCP port listening outside loopback. An app's info-level port is
// folded into the background item that runs its process, when there is one.
func (c *Connector) listeningPorts(ctx context.Context, r *reporter, items *bgItems) {
	ns, _ := c.text(ctx, netstatBin, "-anv", "-p", "tcp")
	ps, _ := c.text(ctx, psBin, "-axo", "pid=,comm=")
	ls := parseListeners(ns, parseProcs(ps))
	if len(ls) == 0 {
		r.Report(check{ID: "listen", OK: true, Detail: "no TCP port listening outside loopback"})
		return
	}
	for _, l := range ls {
		ch := listenerCheck(l)
		if ch.Sev == finding.SevInfo && items.absorb(l) {
			continue
		}
		if l.port == "445" {
			c.smbChecks(ctx, r, &ch)
		}
		r.Report(ch)
	}
}

// smbChecks reports each share point behind port 445. With none left, File Sharing still listens.
func (c *Connector) smbChecks(ctx context.Context, r *reporter, port *check) {
	shares, err := c.sharePoints(ctx)
	if err != nil {
		r.Report(check{ID: "smb-shares", Area: "smb-shares", Skip: err.Error()})
		return
	}
	if len(shares) == 0 {
		port.Title += ", with no shared folders"
		port.Detail += "; no share points"
		port.Rem = posture.Manual("File Sharing is on but shares nothing: turn it off in System Settings > General > Sharing > File Sharing.")
		return
	}
	port.Evidence["share_points"] = slices.Sorted(maps.Keys(shares))
	r.ReportAll(posture.InArea("smb-shares", shareChecks(shares)))
}

func listenerCheck(l listener) check {
	where := fmt.Sprintf("%s (%s)", strings.Join(l.addrs, ", "), l.proc)
	ch := check{ID: "listen-" + l.port, Resource: "listening_port", Name: "TCP " + l.port,
		Evidence: map[string]any{"port": l.port, "addresses": l.addrs, "process": l.proc}}
	known, isKnown := knownPorts[l.port]
	switch {
	case isKnown && known.label == "AirPlay Receiver":
		ch.Sev, ch.Detail = finding.SevMedium, where+" AirPlay Receiver, reachable from the network"
		ch.Title = fmt.Sprintf("AirPlay Receiver listens on port %s for any device on the network", l.port)
		// Not automatable: on macOS 15.6 writing com.apple.controlcenter AirplayRecieverEnabled and
		// restarting ControlCenter leaves ports 5000 and 7000 open (tried 2026-11-23).
		ch.Rem = posture.Manual("Turn off System Settings > General > AirDrop & Handoff > AirPlay Receiver.")
	case isKnown:
		ch.Sev, ch.Detail = finding.SevMedium, where+" "+known.label+", reachable from the network"
		ch.Title = fmt.Sprintf("%s listens on port %s for any device on the network", known.label, l.port)
		ch.Rem = posture.Manual(known.fix)
	case l.proc == "sshd" || l.proc == "launchd":
		ch.Sev, ch.Detail = finding.SevMedium, where+" system service, reachable from the network"
		ch.Title = fmt.Sprintf("A system service (%s) listens on port %s for any device on the network", l.proc, l.port)
		ch.Rem = posture.Manual("Find the sharing service behind it in System Settings > General > Sharing and turn it off if you do not use it.")
	default:
		ch.Sev, ch.Detail = finding.SevInfo, where+" reachable from the local network"
		ch.Title = fmt.Sprintf("%s listens on port %s for other devices on the network", l.proc, l.port)
		ch.Rem = posture.Manual("If you do not need " + l.proc + " reachable from other devices, turn off its network feature; with the firewall on, macOS asks before it accepts connections.")
	}
	return ch
}

func parseProcs(ps string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(ps, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		m[f[0]] = strings.Join(f[1:], " ")
	}
	return m
}

// parseListeners reads `netstat -anv -p tcp`; the pid column moves between macOS versions.
func parseListeners(ns string, procs map[string]string) []listener {
	pidCol := 10
	byPort := map[string]*listener{}
	var order []string
	for _, line := range strings.Split(ns, "\n") {
		if strings.HasPrefix(line, "Proto") {
			h := strings.NewReplacer("Local Address", "Local", "Foreign Address", "Foreign").Replace(line)
			for i, col := range strings.Fields(h) {
				if col == "pid" {
					pidCol = i
				}
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) <= pidCol || f[5] != "LISTEN" {
			continue
		}
		addr := f[3]
		if strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "::1") || strings.Contains(addr, "%lo0") {
			continue
		}
		port := addr[strings.LastIndex(addr, ".")+1:]
		path := procs[f[pidCol]]
		proc := path[strings.LastIndex(path, "/")+1:]
		if proc == "" {
			proc = "pid " + f[pidCol]
		}
		l, ok := byPort[port]
		if !ok {
			l = &listener{port: port, proc: proc, path: path}
			byPort[port] = l
			order = append(order, port)
		}
		if !slices.Contains(l.addrs, addr) {
			l.addrs = append(l.addrs, addr)
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, _ := strconv.Atoi(order[i])
		b, _ := strconv.Atoi(order[j])
		return a < b
	})
	out := make([]listener, 0, len(order))
	for _, p := range order {
		out = append(out, *byPort[p])
	}
	return out
}

type btmItem struct{ name, typ, ident, exe, team, url string }

// label strips the item type BTM prefixes to a launchd label ("16.com.example.helper").
func (it btmItem) label() string {
	if n, rest, ok := strings.Cut(it.ident, "."); ok && strings.Trim(n, "0123456789") == "" {
		return rest
	}
	return it.ident
}

// paths are where the item's process runs from; BTM can give the executable relative to its bundle.
func (it btmItem) paths() []string {
	u := strings.TrimSuffix(strings.TrimPrefix(it.url, "file://"), "/")
	exe := it.exe
	if exe != "" && !strings.HasPrefix(exe, "/") && strings.HasSuffix(u, ".app") {
		exe = u + "/" + exe
	}
	if strings.HasSuffix(u, ".app") {
		return []string{exe, u}
	}
	return []string{exe}
}

// backgroundItems collects leftover launch items, then the enabled items of `sfltool dumpbtm` (no
// sudo on macOS 13 and later), or else the launchd plists and non-Apple launchctl jobs.
func (c *Connector) backgroundItems(ctx context.Context, r *reporter) *bgItems {
	items := &bgItems{}
	jobs := c.launchJobs(ctx)
	var ids []string
	bundleIDs := func() []string {
		if ids == nil {
			ids = append(c.installedBundleIDs(ctx), "")
		}
		return ids
	}
	leftover := map[string]bool{}
	for _, j := range jobs {
		if ch, ok := leftoverCheck(j, bundleIDs); ok {
			leftover[j.label] = true
			items.add(ch, j.program)
		}
	}

	out, err := c.read(ctx, sfltoolBin, "dumpbtm")
	btm := parseBTM(string(out))
	if err != nil || len(btm) == 0 {
		skip := check{ID: "btm", Area: "btm", Skip: "sfltool dumpbtm returned nothing (it may need sudo here); listed launchd plists and launchctl jobs instead"}
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			skip.Skip, skip.SkipState = fmt.Sprintf("sfltool dumpbtm timed out after %s; listed launchd plists and launchctl jobs instead", slowTimeout), finding.StateError
		case err != nil:
			skip.Skip, skip.SkipState = fmt.Sprintf("sfltool dumpbtm failed (%v); listed launchd plists and launchctl jobs instead", err), finding.StateError
		}
		r.Report(skip)
		c.launchItems(ctx, items, jobs, leftover)
		return items
	}
	for _, it := range btm {
		if leftover[it.label()] {
			continue
		}
		ch := check{ID: "btm:" + it.ident, Area: "btm", Resource: "background_item", Name: it.name,
			Detail:   fmt.Sprintf("%s [%s] %s %s (Team %s)", it.name, it.typ, it.ident, it.exe, it.team),
			Evidence: map[string]any{"type": it.typ, "identifier": it.ident, "executable": it.exe, "team_id": it.team},
			Rem:      posture.Manual("Check you recognise it. Turn it off in System Settings > General > Login Items & Extensions, or uninstall the app that installed it."),
			Sev:      finding.SevInfo, Title: fmt.Sprintf("Background item %s (%s) runs at login", it.name, it.typ)}
		if it.team == "" && !strings.HasPrefix(it.exe, "/opt/homebrew/") {
			ch.Sev = finding.SevLow
			ch.Detail = fmt.Sprintf("%s [%s] %s %s (no developer signature: check you recognise it)", it.name, it.typ, it.ident, it.exe)
			ch.Title = fmt.Sprintf("Background item %s (%s) runs at login without a developer signature", it.name, it.typ)
		}
		items.add(ch, it.paths()...)
	}
	return items
}

var (
	btmItemStart = regexp.MustCompile(`^ #\d+:`)
	btmField     = regexp.MustCompile(`^ +(Name|Type|Disposition|Identifier|URL|Executable Path|Team Identifier): ?(.*)$`)
	btmKind      = regexp.MustCompile(`agent|daemon|login item`)
)

func parseBTM(out string) []btmItem {
	var items []btmItem
	seen := map[string]bool{}
	var cur btmItem
	var disp string
	flush := func() {
		if strings.HasPrefix(disp, "[enabled") && btmKind.MatchString(cur.typ) && !seen[cur.ident] {
			seen[cur.ident] = true
			items = append(items, cur)
		}
		cur, disp = btmItem{}, ""
	}
	for _, line := range strings.Split(out, "\n") {
		if btmItemStart.MatchString(line) {
			flush()
			continue
		}
		m := btmField.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch m[1] {
		case "Name":
			cur.name = m[2]
		case "Type":
			cur.typ, _, _ = strings.Cut(m[2], " (0x")
		case "Disposition":
			disp = m[2]
		case "Identifier":
			cur.ident = m[2]
		case "URL":
			cur.url = m[2]
		case "Executable Path":
			cur.exe = m[2]
		case "Team Identifier":
			cur.team = m[2]
		}
	}
	flush()
	return items
}

// launchItems is the fallback without sfltool: one item per launchd label, plists first. Apple's
// jobs and the application.* jobs launchd makes per running app are left out.
func (c *Connector) launchItems(ctx context.Context, items *bgItems, jobs []launchJob, leftover map[string]bool) {
	seen := maps.Clone(leftover)
	for _, j := range jobs {
		if seen[j.label] {
			continue
		}
		seen[j.label] = true
		detail := j.plist
		if j.program != "" {
			detail += " starts " + j.program
		}
		items.add(check{ID: "launch-item:" + j.label, Area: "btm", Resource: "background_item", Name: j.label, Sev: finding.SevInfo,
			Detail: detail, Evidence: map[string]any{"label": j.label, "plist": j.plist, "program": j.program},
			Title: "Launch item " + j.label, Rem: posture.Manual("Check you recognise it.")}, j.program)
	}
	out, _ := c.text(ctx, "/bin/launchctl", "list")
	for i, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 3 {
			continue
		}
		label := f[2]
		if seen[label] || strings.HasPrefix(label, "com.apple.") || strings.HasPrefix(label, "application.") {
			continue
		}
		seen[label] = true
		items.add(check{ID: "launchctl:" + label, Area: "btm", Resource: "background_item", Name: label, Sev: finding.SevInfo, Detail: label,
			Title: "launchd job " + label, Rem: posture.Manual("Check you recognise it.")})
	}
}
