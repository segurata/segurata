package macos

import (
	"testing"
	"time"
)

// An accepted risk is keyed by finding id, so the debugging-port finding must keep its id when
// Brave restarts on another port or under another pid.
func TestBraveDebuggingFindingIDIsStable(t *testing.T) {
	ids := map[string]bool{}
	for _, port := range []string{"9222", "9333"} {
		r := healthy()
		r[psBin+" -axo command="] = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser --remote-debugging-port=" + port + "\n"
		c, _, _ := newTest(t, r)
		f := inventory(t, c).ByResource(t, "macos_setting", "brave-remote-debugging")
		f.Connector = "macos"
		f.Fill(time.Now())
		ids[f.ID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("debugging-port finding id changes with the port: %v", ids)
	}
}
