package macos

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// agentVendor is how an endpoint security or management agent shows on disk and in ps.
type agentVendor struct {
	name    string
	labels  []string // launchd plist name prefixes
	apps    []string // bundle name prefixes in /Applications
	dirs    []string
	account string // the service account it creates
}

var agentVendors = []agentVendor{
	{name: "ESET", labels: []string{"com.eset."}, apps: []string{"ESET"}, dirs: []string{"/Library/Application Support/ESET"}},
	{name: "Sophos", labels: []string{"com.sophos."}, apps: []string{"Sophos"},
		dirs: []string{"/Library/Application Support/Sophos", "/Library/Sophos Anti-Virus"}, account: "_sophos"},
	{name: "CrowdStrike Falcon", labels: []string{"com.crowdstrike."}, apps: []string{"Falcon"}, dirs: []string{"/Library/Application Support/CrowdStrike"}},
	{name: "SentinelOne", labels: []string{"com.sentinelone."}, apps: []string{"SentinelOne"}, dirs: []string{"/Library/Sentinel"}},
	{name: "Microsoft Defender", labels: []string{"com.microsoft.wdav", "com.microsoft.fresno"}, apps: []string{"Microsoft Defender"},
		dirs: []string{"/Library/Application Support/Microsoft/Defender"}},
	{name: "Malwarebytes", labels: []string{"com.malwarebytes."}, apps: []string{"Malwarebytes"}, dirs: []string{"/Library/Application Support/Malwarebytes"}},
	{name: "Bitdefender", labels: []string{"com.bitdefender."}, apps: []string{"Bitdefender"}, dirs: []string{"/Library/Bitdefender"}},
	{name: "Kaspersky", labels: []string{"com.kaspersky."}, apps: []string{"Kaspersky"}, dirs: []string{"/Library/Application Support/Kaspersky Lab"}},
	{name: "Avast or AVG", labels: []string{"com.avast.", "com.avg."}, apps: []string{"Avast", "AVG"}, dirs: []string{"/Library/Application Support/Avast", "/Library/Application Support/AVGAntivirus"}},
	{name: "Norton or Symantec", labels: []string{"com.symantec.", "com.norton."}, apps: []string{"Norton", "Symantec"}, dirs: []string{"/Library/Application Support/Symantec"}},
	{name: "Trend Micro", labels: []string{"com.trendmicro."}, apps: []string{"Trend Micro"}, dirs: []string{"/Library/Application Support/TrendMicro"}},
	{name: "Intego", labels: []string{"com.intego."}, apps: []string{"Intego", "VirusBarrier"}, dirs: []string{"/Library/Intego"}},
	{name: "Jamf", labels: []string{"com.jamf.", "com.jamfsoftware."}, apps: []string{"Jamf"}, dirs: []string{"/Library/Application Support/JAMF"}},
}

type agentTrace struct {
	launchd, apps, dirs, procs []string
	account                    string
}

func (t agentTrace) found() bool {
	return len(t.launchd)+len(t.apps)+len(t.dirs)+len(t.procs) > 0 || t.account != ""
}

func (t agentTrace) active() bool { return len(t.apps) > 0 || len(t.procs) > 0 }

// endpointAgents reports present agents as info, and one with no app and nothing running as the
// leftover of an uninstall (low).
func (c *Connector) endpointAgents(ctx context.Context, users []localUser) []check {
	var plistNames []string
	for _, d := range []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"} {
		for _, p := range plists(c.path(d)) {
			plistNames = append(plistNames, c.shown(p))
		}
	}
	apps, _ := os.ReadDir(c.path("/Applications"))
	ps, _ := c.text(ctx, psBin, "-axo", "command=")
	procs := strings.Split(ps, "\n")
	accounts := map[string]bool{}
	for _, u := range users {
		accounts[u.name] = true
	}
	var out []check
	for _, v := range agentVendors {
		var t agentTrace
		for _, p := range plistNames {
			if hasAnyPrefix(filepath.Base(p), v.labels) {
				t.launchd = append(t.launchd, p)
			}
		}
		for _, a := range apps {
			if strings.HasSuffix(a.Name(), ".app") && hasAnyPrefix(a.Name(), v.apps) {
				t.apps = append(t.apps, "/Applications/"+a.Name())
			}
		}
		for _, d := range v.dirs {
			if pathExists(c.path(d)) {
				t.dirs = append(t.dirs, d)
			}
		}
		for _, p := range procs {
			if agentProcess(p, v) && !slices.Contains(t.procs, p) {
				t.procs = append(t.procs, p)
			}
		}
		if accounts[v.account] {
			t.account = v.account
		}
		if t.found() {
			out = append(out, agentCheck(v.name, t))
		}
	}
	return out
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func agentProcess(cmd string, v agentVendor) bool {
	for _, a := range v.apps {
		if strings.HasPrefix(cmd, "/Applications/"+a) {
			return true
		}
	}
	for _, d := range v.dirs {
		if strings.HasPrefix(cmd, d+"/") {
			return true
		}
	}
	return false
}

func agentCheck(name string, t agentTrace) check {
	var parts []string
	add := func(label string, items []string) {
		if len(items) > 0 {
			parts = append(parts, label+" "+strings.Join(items, ", "))
		}
	}
	add("app", t.apps)
	add("launchd", t.launchd)
	add("folders", t.dirs)
	if n := len(t.procs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d running processes", n))
	}
	if t.account != "" {
		parts = append(parts, "service account "+t.account)
	}
	ch := check{id: "endpoint-agent:" + name, resource: "endpoint_agent", name: name, blast: finding.BlastLeftovers,
		detail: strings.Join(parts, "; "),
		evidence: map[string]any{"vendor": name, "apps": t.apps, "launchd": t.launchd, "folders": t.dirs,
			"running": len(t.procs) > 0, "service_account": t.account}}
	if t.active() {
		ch.sev = finding.SevInfo
		ch.title = fmt.Sprintf("Endpoint agent %s is installed", name)
		ch.rem = manual("Context: keep it if you or your organisation chose it, and keep it up to date; if nobody remembers installing it, uninstall it with its own uninstaller.")
		return ch
	}
	ch.sev = finding.SevLow
	ch.title = fmt.Sprintf("Leftovers of endpoint agent %s: no app installed and nothing running", name)
	ch.rem = manual("Run the vendor's uninstaller or removal tool to clean up what is left (" + strings.Join(parts, "; ") +
		"). A leftover service account or launch item from an agent nobody manages is attack surface with no protection behind it.")
	return ch
}
