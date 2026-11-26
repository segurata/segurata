package macos

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

var (
	braveProcess = regexp.MustCompile(`Brave Browser\.app/Contents/MacOS/Brave Browser( |$)`)
	debugFlag    = regexp.MustCompile(`--remote-debugging-(port|address)=\S+`)
)

// braveDebugging: while the port is open any local process can drive every signed-in session.
func (c *Connector) braveDebugging(ctx context.Context) check {
	ch := check{id: "brave-remote-debugging", sev: finding.SevHigh, blast: finding.BlastBrowser,
		title: "Brave runs with a remote debugging port: any local process can act as every signed-in account",
		rem:   manual("Quit Brave and start it without --remote-debugging-port. Start it with the flag only while running the google-personal or connected-apps connectors.")}
	ps, _ := c.text(ctx, psBin, "-axo", "command=")
	flags := map[string]bool{}
	port := ""
	for _, l := range strings.Split(ps, "\n") {
		if !braveProcess.MatchString(l) {
			continue
		}
		for _, f := range debugFlag.FindAllString(l, -1) {
			flags[f] = true
			if v, ok := strings.CutPrefix(f, "--remote-debugging-port="); ok {
				port = v
			}
		}
	}
	if len(flags) == 0 {
		ch.ok, ch.detail = true, "Brave is not running with --remote-debugging-port"
		return ch
	}
	list := slices.Sorted(maps.Keys(flags))
	var binds []string
	if port != "" {
		ns, _ := c.text(ctx, netstatBin, "-anv", "-p", "tcp")
		for _, line := range strings.Split(ns, "\n") {
			if f := strings.Fields(line); len(f) > 5 && f[5] == "LISTEN" && strings.HasSuffix(f[3], "."+port) && !slices.Contains(binds, f[3]) {
				binds = append(binds, f[3])
			}
		}
	}
	bind := strings.Join(binds, ",")
	if bind == "" {
		bind = "?"
	}
	ch.detail = fmt.Sprintf("%s listening on %s. The google-personal and connected-apps connectors need it, but while it is open any local process (an npm package, an editor extension) can read cookies and act as every signed-in account without asking.", strings.Join(list, " "), bind)
	ch.evidence = map[string]any{"flags": list, "listening": binds}
	return ch
}
