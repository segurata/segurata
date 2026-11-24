package macos

import (
	"fmt"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestEndpointAgentsAreListedAndLeftoversGraded(t *testing.T) {
	r := healthy()
	r[strings.Join(listUIDs, " ")] = "root 0\n_sophos 502\nalice 501\n"
	r[psBin+" -axo command="] = "/Applications/Malwarebytes.app/Contents/MacOS/RTProtectionDaemon --run\n" +
		"/Library/Application Support/CrowdStrike/falcond\n/Applications/Brave Browser.app/Contents/MacOS/Brave Browser\n"
	c, _, _ := newTest(t, r)
	touch(t, c.Root,
		"Applications/Malwarebytes.app/Contents/Info.plist",
		"Library/LaunchDaemons/com.malwarebytes.mbam.rtprotection.daemon.plist",
		"Library/Application Support/Sophos/configuration.plist",
		"Library/Application Support/ESET/esets_uninstall.log",
		"Library/LaunchDaemons/com.eset.remoteadministrator.agent.plist",
		"Library/Application Support/CrowdStrike/falcond",
		"Applications/Esetera.txt", // not an app bundle
	)
	rec := inventory(t, c)
	want := map[string]finding.Severity{
		"endpoint-agent:Malwarebytes":       finding.SevInfo, // app and process
		"endpoint-agent:CrowdStrike Falcon": finding.SevInfo, // running from its folder
		"endpoint-agent:Sophos":             finding.SevLow,  // folder and service account only
		"endpoint-agent:ESET":               finding.SevLow,  // folder and a launch daemon, no app
	}
	got := map[string]finding.Severity{}
	for _, f := range rec.Findings {
		if f.Resource.Type == "endpoint_agent" {
			got[f.Resource.ID] = f.Severity
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	sophos := rec.ByResource(t, "endpoint_agent", "endpoint-agent:Sophos")
	if sophos.Evidence["service_account"] != "_sophos" || fmt.Sprint(sophos.Evidence["folders"]) != "[/Library/Application Support/Sophos]" ||
		!strings.HasPrefix(sophos.Title, "Leftovers of endpoint agent Sophos") {
		t.Errorf("sophos %q %v", sophos.Title, sophos.Evidence)
	}
	eset := rec.ByResource(t, "endpoint_agent", "endpoint-agent:ESET")
	if fmt.Sprint(eset.Evidence["launchd"]) != "[/Library/LaunchDaemons/com.eset.remoteadministrator.agent.plist]" || eset.Evidence["running"] != false {
		t.Errorf("eset %v", eset.Evidence)
	}
	mb := rec.ByResource(t, "endpoint_agent", "endpoint-agent:Malwarebytes")
	if fmt.Sprint(mb.Evidence["apps"]) != "[/Applications/Malwarebytes.app]" || mb.Evidence["running"] != true {
		t.Errorf("malwarebytes %v", mb.Evidence)
	}
}
