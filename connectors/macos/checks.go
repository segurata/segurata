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

	"github.com/segurata/segurata/internal/finding"
)

func manual(summary string) finding.Remediation { return finding.Remediation{Summary: summary} }

// systemChecks covers disk and boot, firewall, update settings, screen and session, and Remote Login.
func (c *Connector) systemChecks(ctx context.Context) []check {
	var out []check

	s, _ := c.text(ctx, "/usr/bin/fdesetup", "status")
	s = firstLine(s)
	out = append(out, check{id: "filevault", ok: strings.Contains(s, "is On"), detail: s, sev: finding.SevHigh,
		title: "FileVault disk encryption is off",
		rem:   manual("Turn on FileVault in System Settings > Privacy & Security > FileVault, and keep the recovery key somewhere safe.")})

	s, _ = c.text(ctx, "/usr/bin/csrutil", "status")
	out = append(out, check{id: "sip", ok: strings.Contains(s, "enabled"), detail: s, sev: finding.SevHigh,
		title: "System Integrity Protection is disabled",
		rem:   manual("Start up in macOS Recovery, open Terminal and run `csrutil enable`, then restart.")})

	s, _ = c.text(ctx, "/usr/sbin/spctl", "--status")
	out = append(out, check{id: "gatekeeper", ok: strings.Contains(s, "assessments enabled"), detail: s, sev: finding.SevHigh,
		title: "Gatekeeper is disabled: apps from anywhere run without a check",
		rem:   manual("In System Settings > Privacy & Security > Security, allow applications from the App Store and identified developers.")})

	s, _ = c.text(ctx, socketfilterfw, "--getglobalstate")
	out = append(out, check{id: "firewall", ok: strings.Contains(s, "enabled"), detail: s, sev: finding.SevMedium,
		title: "The macOS application firewall is off",
		rem: finding.Remediation{Action: ActionFirewallEnable,
			Summary: "Turn on the firewall (System Settings > Network > Firewall), or run `securizame remediate <id> --apply`."}})

	s, _ = c.text(ctx, socketfilterfw, "--getstealthmode")
	out = append(out, check{id: "firewall-stealth", ok: strings.Contains(s, " on") || strings.Contains(s, "enabled"), detail: s, sev: finding.SevLow,
		title: "Firewall stealth mode is off: the Mac answers probes and pings",
		rem: finding.Remediation{Action: ActionFirewallStealth,
			Summary: "Turn on stealth mode (System Settings > Network > Firewall > Options), or run `securizame remediate <id> --apply`."}})

	updates := manual("Turn on every automatic update option in System Settings > General > Software Update > Automatic Updates.")
	for _, k := range updateKeys {
		v := c.pref(ctx, defaultsBin, "read", softwareUpdatePrefs, k)
		out = append(out, check{id: "update-" + k, ok: v != "0", detail: orUnset(v), sev: finding.SevMedium,
			title: fmt.Sprintf("Automatic update setting %s is off", k), rem: updates})
	}
	v := c.pref(ctx, defaultsBin, "read", commercePrefs, "AutoUpdate")
	out = append(out, check{id: "update-appstore-apps", ok: v != "0", detail: orUnset(v), sev: finding.SevLow,
		title: "App Store apps do not update automatically",
		rem:   manual("Turn on App Store > Settings > Automatic Updates.")})

	s, _ = c.text(ctx, "/usr/sbin/sysadminctl", "-screenLock", "status")
	s = screenLockText(s)
	out = append(out, check{id: "screen-lock", ok: screenLockOK(s), detail: s, sev: finding.SevMedium,
		title: "The screen does not lock right away when it sleeps",
		rem:   manual("In System Settings > Lock Screen, set \"Require password after screen saver begins or display is turned off\" to Immediately.")})

	idle := c.pref(ctx, defaultsBin, "-currentHost", "read", "com.apple.screensaver", "idleTime")
	pm, _ := c.text(ctx, "/usr/bin/pmset", "-g")
	out = append(out, check{id: "screensaver", sev: finding.SevInfo,
		detail: fmt.Sprintf("screensaver after %s s, display off after %s min", orQ(idle), orQ(displaySleep(pm))),
		title:  "Screen saver and display sleep timing",
		rem:    manual("Shorter is safer: System Settings > Lock Screen.")})

	user := c.pref(ctx, defaultsBin, "read", loginWindowPrefs, "autoLoginUser")
	out = append(out, check{id: "auto-login", ok: user == "", detail: "automatic login as " + user, sev: finding.SevHigh,
		title: "The Mac logs in automatically, without a password",
		rem:   manual("Set System Settings > Users & Groups > Automatically log in as: Off.")})
	if user == "" {
		out[len(out)-1].detail = "off"
	}

	g := c.pref(ctx, defaultsBin, "read", loginWindowPrefs, "GuestEnabled")
	if g == "" {
		g = "0"
	}
	out = append(out, check{id: "guest-account", ok: g == "0", detail: "GuestEnabled=" + g, sev: finding.SevMedium,
		title: "The guest account is enabled",
		rem:   manual("Turn off System Settings > Users & Groups > Guest User > Allow guests to log in to this computer.")})

	s, _ = c.text(ctx, "/usr/sbin/systemsetup", "-getremotelogin")
	rl := check{id: "remote-login", ok: strings.Contains(s, "Off"), detail: s, sev: finding.SevMedium,
		title: "Remote Login (SSH) is on",
		rem:   manual("Turn off System Settings > General > Sharing > Remote Login unless you use SSH into this Mac.")}
	if strings.Contains(s, "administrator") {
		rl.skip = "systemsetup needs admin; the listening ports check covers SSH"
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
	out, err := guard(c.Run).Run(ctx, softwareUpdate, "-l")
	ch := check{id: "updates-pending", sev: finding.SevMedium, title: "macOS has updates waiting to be installed",
		rem: manual("Install them in System Settings > General > Software Update.")}
	if errors.Is(err, context.DeadlineExceeded) {
		ch.skip = "softwareupdate -l did not answer within 120 s"
		return ch
	}
	var labels []string
	for _, m := range updateLabel.FindAllStringSubmatch(string(out), -1) {
		labels = append(labels, strings.TrimSpace(m[1]))
	}
	if len(labels) == 0 {
		ch.ok, ch.detail = true, ver+", no pending updates"
		return ch
	}
	ch.detail = ver + ", pending: " + strings.Join(labels, ",")
	ch.evidence = map[string]any{"macos_version": ver, "pending": labels}
	return ch
}

// Ports of sharing services and what turns each off.
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
}

// listeningPorts reports every TCP port listening outside loopback, one finding per port.
func (c *Connector) listeningPorts(ctx context.Context, r *reporter) {
	ns, _ := c.text(ctx, netstatBin, "-anv", "-p", "tcp")
	ps, _ := c.text(ctx, psBin, "-axo", "pid=,comm=")
	ls := parseListeners(ns, parseProcs(ps))
	if len(ls) == 0 {
		r.report(check{id: "listen", ok: true, detail: "no TCP port listening outside loopback"})
		return
	}
	for _, l := range ls {
		ch := listenerCheck(l)
		if l.port == "445" {
			c.smbChecks(ctx, r, &ch)
		}
		r.report(ch)
	}
}

// smbChecks reports one finding per share point behind port 445 and names them on the port's
// finding. With no share points left, File Sharing still listens until it is turned off.
func (c *Connector) smbChecks(ctx context.Context, r *reporter, port *check) {
	shares, err := c.sharePoints(ctx)
	if err != nil {
		r.report(check{id: "smb-shares", skip: err.Error()})
		return
	}
	if len(shares) == 0 {
		port.title += ", with no shared folders"
		port.detail += "; no share points"
		port.rem = manual("File Sharing is on but shares nothing: turn it off in System Settings > General > Sharing > File Sharing.")
		return
	}
	port.evidence["share_points"] = slices.Sorted(maps.Keys(shares))
	for _, ch := range shareChecks(shares) {
		r.report(ch)
	}
}

func listenerCheck(l listener) check {
	where := fmt.Sprintf("%s (%s)", strings.Join(l.addrs, ", "), l.proc)
	ch := check{id: "listen-" + l.port, resource: "listening_port", name: "TCP " + l.port,
		evidence: map[string]any{"port": l.port, "addresses": l.addrs, "process": l.proc}}
	known, isKnown := knownPorts[l.port]
	switch {
	case isKnown && known.label == "AirPlay Receiver":
		ch.sev, ch.detail = finding.SevMedium, where+" AirPlay Receiver, reachable from the network"
		ch.title = fmt.Sprintf("AirPlay Receiver listens on port %s for any device on the network", l.port)
		// Not automatable: on macOS 15.6 writing com.apple.controlcenter AirplayRecieverEnabled and
		// restarting ControlCenter leaves ports 5000 and 7000 open (tried 2026-11-23).
		ch.rem = manual("Turn off System Settings > General > AirDrop & Handoff > AirPlay Receiver.")
	case isKnown:
		ch.sev, ch.detail = finding.SevMedium, where+" "+known.label+", reachable from the network"
		ch.title = fmt.Sprintf("%s listens on port %s for any device on the network", known.label, l.port)
		ch.rem = manual(known.fix)
	case l.proc == "sshd" || l.proc == "launchd":
		ch.sev, ch.detail = finding.SevMedium, where+" system service, reachable from the network"
		ch.title = fmt.Sprintf("A system service (%s) listens on port %s for any device on the network", l.proc, l.port)
		ch.rem = manual("Find the sharing service behind it in System Settings > General > Sharing and turn it off if you do not use it.")
	default:
		ch.sev, ch.detail = finding.SevInfo, where+" reachable from the local network"
		ch.title = fmt.Sprintf("%s listens on port %s for other devices on the network", l.proc, l.port)
		ch.rem = manual("If you do not need " + l.proc + " reachable from other devices, turn off its network feature; with the firewall on, macOS asks before it accepts connections.")
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
		path := strings.Join(f[1:], " ")
		m[f[0]] = path[strings.LastIndex(path, "/")+1:]
	}
	return m
}

// parseListeners reads `netstat -anv -p tcp`, locating the pid column from the header because
// its position changes between macOS versions.
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
		proc := procs[f[pidCol]]
		if proc == "" {
			proc = "pid " + f[pidCol]
		}
		l, ok := byPort[port]
		if !ok {
			l = &listener{port: port, proc: proc}
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

type btmItem struct{ name, typ, ident, exe, team string }

// backgroundItems reports enabled login items, agents and daemons from `sfltool dumpbtm`, which
// needs no sudo on macOS 13 and later. Without it, it lists LaunchAgents and LaunchDaemons.
func (c *Connector) backgroundItems(ctx context.Context, r *reporter) {
	out, _ := c.text(ctx, "/usr/bin/sfltool", "dumpbtm")
	items := parseBTM(out)
	if len(items) == 0 {
		r.report(check{id: "btm", skip: "sfltool dumpbtm returned nothing (it may need sudo here); falling back to launchctl and launchd plists"})
		c.launchItems(ctx, r)
		return
	}
	for _, it := range items {
		ch := check{id: "btm:" + it.ident, resource: "background_item", name: it.name,
			detail:   fmt.Sprintf("%s [%s] %s %s (Team %s)", it.name, it.typ, it.ident, it.exe, it.team),
			evidence: map[string]any{"type": it.typ, "identifier": it.ident, "executable": it.exe, "team_id": it.team},
			rem:      manual("Check you recognise it. Turn it off in System Settings > General > Login Items & Extensions, or uninstall the app that installed it."),
			sev:      finding.SevInfo, title: fmt.Sprintf("Background item %s (%s) runs at login", it.name, it.typ)}
		if it.team == "" && !strings.HasPrefix(it.exe, "/opt/homebrew/") {
			ch.sev = finding.SevLow
			ch.detail = fmt.Sprintf("%s [%s] %s %s (no developer signature: check you recognise it)", it.name, it.typ, it.ident, it.exe)
			ch.title = fmt.Sprintf("Background item %s (%s) runs at login without a developer signature", it.name, it.typ)
		}
		r.report(ch)
	}
}

var (
	btmItemStart = regexp.MustCompile(`^ #\d+:`)
	btmField     = regexp.MustCompile(`^ +(Name|Type|Disposition|Identifier|Executable Path|Team Identifier): ?(.*)$`)
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
		case "Executable Path":
			cur.exe = m[2]
		case "Team Identifier":
			cur.team = m[2]
		}
	}
	flush()
	return items
}

// launchItems is the fallback when sfltool gives nothing: launchd plists and non-Apple launchctl jobs.
func (c *Connector) launchItems(ctx context.Context, r *reporter) {
	home, _ := c.Home()
	for _, dir := range []string{home + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"} {
		for _, p := range plists(dir) {
			r.report(check{id: "launch-item:" + p, resource: "background_item", sev: finding.SevInfo, detail: p,
				title: "Launch item " + p, rem: manual("Check you recognise it.")})
		}
	}
	out, _ := c.text(ctx, "/bin/launchctl", "list")
	for i, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 3 || strings.HasPrefix(f[2], "com.apple.") {
			continue
		}
		r.report(check{id: "launchctl:" + f[2], resource: "background_item", sev: finding.SevInfo, detail: f[2],
			title: "launchd job " + f[2], rem: manual("Check you recognise it.")})
	}
}
