package windows

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/finding"
)

type listener struct {
	port  string
	addrs []string
	proc  string
}

func loopback(addr string) bool { return strings.HasPrefix(addr, "127.") || addr == "::1" }

// listeners groups the probe's listening TCP sockets (MSFT_NetTCPConnection, State 2) by port,
// in port order; loopback ones only when withLoopback.
func listeners(p probe, withLoopback bool) []listener {
	byPort := map[string]*listener{}
	for _, r := range p.all("tcp") {
		addr := r.get("addr")
		if !withLoopback && loopback(addr) {
			continue
		}
		port := r.get("port")
		l, ok := byPort[port]
		if !ok {
			l = &listener{port: port, proc: cmp.Or(r.get("proc"), "pid "+r.get("pid"))}
			byPort[port] = l
		}
		if !slices.Contains(l.addrs, addr) {
			l.addrs = append(l.addrs, addr)
		}
	}
	out := make([]listener, 0, len(byPort))
	for _, l := range byPort {
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := strconv.Atoi(out[i].port)
		b, _ := strconv.Atoi(out[j].port)
		return a < b
	})
	return out
}

const winRMFix = "Unless this PC is managed remotely, run `Disable-PSRemoting -Force; Stop-Service WinRM; Set-Service WinRM -StartupType Disabled` in an elevated PowerShell."

var knownPorts = map[string]struct{ label, fix string }{
	"21":   {"FTP", "Stop the FTP server if you do not use it (Settings > System > Optional features, or the app that installed it)."},
	"22":   {"SSH (OpenSSH Server)", "Unless you connect to this PC over SSH, run `Stop-Service sshd; Set-Service sshd -StartupType Disabled` in an elevated PowerShell."},
	"23":   {"Telnet", "Turn off the Telnet server: it sends passwords in clear text."},
	"5900": {"VNC", "Quit or uninstall the VNC server unless you control this PC remotely."},
	"5985": {"WinRM (PowerShell remoting)", winRMFix},
	"5986": {"WinRM over HTTPS (PowerShell remoting)", winRMFix},
}

// systemProcs run the services every Windows PC listens with: RPC (135 and the dynamic range),
// NetBIOS and SMB (139, 445), device discovery, Delivery Optimization.
var systemProcs = []string{"System", "svchost", "lsass", "wininit", "services", "spoolsv"}

// listenerChecks reports every TCP port listening outside loopback: known remote-access services
// one by one, Windows' own services together, any other program as information. Remote Desktop's
// port is the remote-desktop check.
func listenerChecks(p probe) []check {
	if why, st, bad := p.unread("tcp", ""); bad {
		return []check{skipped("listen", "listen", why, st)}
	}
	ls := listeners(p, false)
	if len(ls) == 0 {
		return []check{{ID: "listen", Area: "listen", OK: true, Detail: "no TCP port listening outside loopback"}}
	}
	var out []check
	var system []string
	for _, l := range ls {
		where := fmt.Sprintf("%s (%s)", strings.Join(l.addrs, ", "), l.proc)
		ch := check{ID: "listen-" + l.port, Area: "listen", Resource: "listening_port", Name: "TCP " + l.port,
			Evidence: map[string]any{"port": l.port, "addresses": l.addrs, "process": l.proc}}
		known, isKnown := knownPorts[l.port]
		switch {
		case l.port == "3389" && l.proc == "svchost":
			continue
		case isKnown:
			ch.Sev, ch.Detail = finding.SevMedium, where+" "+known.label+", reachable from the network"
			ch.Title = fmt.Sprintf("%s listens on port %s for any device on the network", known.label, l.port)
			ch.Rem = posture.Manual(known.fix)
		case slices.Contains(systemProcs, l.proc):
			system = append(system, l.port+" ("+l.proc+")")
			continue
		default:
			ch.Sev, ch.Detail = finding.SevInfo, where+" reachable from the local network"
			ch.Title = fmt.Sprintf("%s listens on port %s for other devices on the network", l.proc, l.port)
			ch.Rem = posture.Manual("If you do not need " + l.proc + " reachable from other devices, turn off its network feature; with Microsoft Defender Firewall on, Windows asks before an app accepts connections from other devices.")
		}
		out = append(out, ch)
	}
	if len(system) > 0 {
		out = append(out, check{ID: "listen-windows-services", Area: "listen", Resource: "listening_port", Name: "Windows services", Sev: finding.SevInfo,
			Detail:   "Windows services listen on " + strings.Join(system, ", "),
			Evidence: map[string]any{"ports": system},
			Title:    "Windows' own services (RPC, file and printer sharing, discovery) listen for other devices on the network",
			Rem:      posture.Manual("They come with Windows. Keep Microsoft Defender Firewall on, with the Public profile for networks you do not trust, so other devices cannot reach them.")})
	}
	return out
}

var browsers = []struct{ exe, id, label string }{
	{"brave.exe", "brave", "Brave"},
	{"chrome.exe", "chrome", "Chrome"},
	{"msedge.exe", "edge", "Microsoft Edge"},
}

// browserChecks: while a debugging port is open any local process can drive every signed-in
// session. The probe lists only browser processes whose command line names one.
func browserChecks(p probe) []check {
	if why, st, bad := p.unread("browser", ""); bad {
		return []check{skipped("browser-remote-debugging", "browser-remote-debugging", why, st)}
	}
	var out []check
	for _, b := range browsers {
		ch := check{ID: b.id + "-remote-debugging", Area: "browser-remote-debugging", Sev: finding.SevHigh, Blast: finding.BlastBrowser,
			OK: true, Detail: b.label + " is not running with --remote-debugging-port",
			Title: b.label + " runs with a remote debugging port: any local process can act as every signed-in account",
			Rem:   posture.Manual("Quit " + b.label + " (every window, and its icon in the notification area) and start it without --remote-debugging-port. Start it with the flag only while running the google-personal or connected-apps connectors.")}
		flags := map[string]bool{}
		port := ""
		for _, r := range p.all("browser") {
			if strings.EqualFold(r.get("name"), b.exe) {
				if v := posture.DebugFlags(r.get("cmd"), flags); v != "" {
					port = v
				}
			}
		}
		if len(flags) > 0 {
			var binds []string
			for _, l := range listeners(p, true) {
				if l.port == port {
					binds = l.addrs
				}
			}
			ch = posture.Debugging(ch, flags, binds)
		}
		out = append(out, ch)
	}
	return out
}
