package posture

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

var debugFlag = regexp.MustCompile(`--remote-debugging-(port|address)=\S+`)

// DebugFlags adds a browser command line's remote debugging flags to flags and returns the port
// it names, or "".
func DebugFlags(cmdline string, flags map[string]bool) (port string) {
	for _, f := range debugFlag.FindAllString(cmdline, -1) {
		flags[f] = true
		if v, ok := strings.CutPrefix(f, "--remote-debugging-port="); ok {
			port = v
		}
	}
	return port
}

// Debugging is the failing check of a browser running with a debugging port: flags as DebugFlags
// collected them, binds the addresses listening on the port.
func Debugging(ch Check, flags map[string]bool, binds []string) Check {
	list := slices.Sorted(maps.Keys(flags))
	ch.OK = false
	ch.Detail = fmt.Sprintf("%s listening on %s. The google-personal and connected-apps connectors need it, but while it is open any local process (an npm package, an editor extension) can read cookies and act as every signed-in account without asking.", strings.Join(list, " "), cmp.Or(strings.Join(binds, ","), "?"))
	ch.Evidence = map[string]any{"flags": list, "listening": binds}
	return ch
}
