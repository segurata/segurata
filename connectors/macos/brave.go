package macos

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/posture"
	"github.com/segurata/segurata/internal/finding"
)

var braveProcess = regexp.MustCompile(`Brave Browser\.app/Contents/MacOS/Brave Browser( |$)`)

// braveDebugging: while the port is open any local process can drive every signed-in session.
func (c *Connector) braveDebugging(ctx context.Context) check {
	ch := check{ID: "brave-remote-debugging", Sev: finding.SevHigh, Blast: finding.BlastBrowser,
		Title: "Brave runs with a remote debugging port: any local process can act as every signed-in account",
		Rem:   posture.Manual("Quit Brave and start it without --remote-debugging-port. Start it with the flag only while running the google-personal or connected-apps connectors.")}
	ps, _ := c.text(ctx, psBin, "-axo", "command=")
	flags := map[string]bool{}
	port := ""
	for _, l := range strings.Split(ps, "\n") {
		if braveProcess.MatchString(l) {
			if p := posture.DebugFlags(l, flags); p != "" {
				port = p
			}
		}
	}
	if len(flags) == 0 {
		ch.OK, ch.Detail = true, "Brave is not running with --remote-debugging-port"
		return ch
	}
	var binds []string
	if port != "" {
		ns, _ := c.text(ctx, netstatBin, "-anv", "-p", "tcp")
		for _, line := range strings.Split(ns, "\n") {
			if f := strings.Fields(line); len(f) > 5 && f[5] == "LISTEN" && strings.HasSuffix(f[3], "."+port) && !slices.Contains(binds, f[3]) {
				binds = append(binds, f[3])
			}
		}
	}
	return posture.Debugging(ch, flags, binds)
}
