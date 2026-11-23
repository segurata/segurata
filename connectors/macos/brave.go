package macos

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

const braveDir = "Library/Application Support/BraveSoftware/Brave-Browser"

var (
	braveProcess = regexp.MustCompile(`Brave Browser\.app/Contents/MacOS/Brave Browser( |$)`)
	debugFlag    = regexp.MustCompile(`--remote-debugging-(port|address)=\S+`)
)

// braveDebugging flags Brave running with --remote-debugging-port: while it is open any local
// process can drive the browser with every signed-in session.
func (c *Connector) braveDebugging(ctx context.Context) check {
	ch := check{id: "brave-remote-debugging", sev: finding.SevHigh,
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

var broadHost = regexp.MustCompile(`^(<all_urls>|\*://\*/\*|https?://\*/\*|file:///\*)$`)

var sensitiveAPIs = map[string]bool{"cookies": true, "webRequest": true, "webRequestBlocking": true, "debugger": true, "proxy": true,
	"nativeMessaging": true, "history": true, "management": true, "privacy": true, "clipboardRead": true, "downloads": true,
	"declarativeNetRequestWithHostAccess": true, "scripting": true, "tabs": true, "webNavigation": true, "desktopCapture": true}

// riskyAPIs alone make an enabled extension a warning.
var riskyAPIs = map[string]bool{"debugger": true, "proxy": true, "nativeMessaging": true, "cookies": true, "webRequestBlocking": true}

var profileDir = regexp.MustCompile(`^(Default|Profile \d+)$`)

type extSettings struct {
	Location           int             `json:"location"`
	Path               string          `json:"path"`
	Manifest           *manifest       `json:"manifest"`
	ActivePermissions  *permissions    `json:"active_permissions"`
	GrantedPermissions *permissions    `json:"granted_permissions"`
	DisableReasons     json.RawMessage `json:"disable_reasons"`
	State              *int            `json:"state"`
	FromWebstore       bool            `json:"from_webstore"`
	Withholding        bool            `json:"withholding_permissions"`
}

type manifest struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	DefaultLocale string `json:"default_locale"`
	Permissions   []any  `json:"permissions"`
}

type permissions struct {
	API            []any    `json:"api"`
	ExplicitHost   []string `json:"explicit_host"`
	ScriptableHost []string `json:"scriptable_host"`
}

type prefsFile struct {
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
	Extensions struct {
		Settings map[string]json.RawMessage `json:"settings"`
	} `json:"extensions"`
}

func readJSON(path string, v any) bool {
	raw, err := os.ReadFile(path)
	return err == nil && json.Unmarshal(raw, v) == nil
}

// braveExtensions reports every extension a user installed in each Brave profile, with the
// permissions it holds. Settings from Secure Preferences override those in Preferences.
func (c *Connector) braveExtensions(r *reporter) {
	home, err := c.Home()
	if err != nil {
		r.report(check{id: "brave-extensions", skip: err.Error()})
		return
	}
	dir := filepath.Join(home, braveDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		r.report(check{id: "brave-extensions", skip: "no Brave profile in " + dir})
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !profileDir.MatchString(e.Name()) {
			continue
		}
		for _, ch := range profileExtensions(dir, e.Name()) {
			r.report(ch)
		}
	}
}

func profileExtensions(dir, prof string) []check {
	var prefs, secure prefsFile
	readJSON(filepath.Join(dir, prof, "Preferences"), &prefs)
	readJSON(filepath.Join(dir, prof, "Secure Preferences"), &secure)
	name := prefs.Profile.Name
	if name == "" {
		name = prof
	}
	settings := map[string]json.RawMessage{}
	maps.Copy(settings, prefs.Extensions.Settings)
	maps.Copy(settings, secure.Extensions.Settings)
	var out []check
	for _, id := range slices.Sorted(maps.Keys(settings)) {
		var e extSettings
		if json.Unmarshal(settings[id], &e) != nil {
			continue
		}
		switch e.Location {
		case 1, 4, 6, 8: // web store, unpacked, external, command line; the rest ship with Brave
		default:
			continue
		}
		out = append(out, extensionCheck(dir, prof, name, id, e))
	}
	return out
}

func extensionCheck(dir, prof, profName, id string, e extSettings) check {
	extDir := ""
	if e.Path != "" {
		extDir = e.Path
		if !filepath.IsAbs(extDir) {
			extDir = filepath.Join(dir, prof, "Extensions", e.Path)
		}
	}
	man := manifest{}
	if e.Manifest != nil {
		man = *e.Manifest
	} else if extDir != "" {
		readJSON(filepath.Join(extDir, "manifest.json"), &man)
	}
	label := localize(man, extDir)
	if label == "" {
		label = id
	}
	act := e.ActivePermissions
	if act == nil {
		act = e.GrantedPermissions
	}
	if act == nil {
		act = &permissions{}
	}
	api := strs(act.API)
	if act.API == nil {
		api = strs(man.Permissions)
	}
	var hosts []string
	for _, h := range append(append([]string{}, act.ExplicitHost...), act.ScriptableHost...) {
		if !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	var broad, sens []string
	for _, h := range hosts {
		if broadHost.MatchString(h) {
			broad = append(broad, h)
		}
	}
	risky := false
	for _, p := range api {
		if sensitiveAPIs[p] {
			sens = append(sens, p)
		}
		risky = risky || riskyAPIs[p]
	}
	enabled := !disabled(e)

	var flags []string
	if len(broad) > 0 {
		f := "access to all sites (" + strings.Join(broad, " ") + ")"
		if e.Withholding {
			f += ", on click only"
		}
		flags = append(flags, f)
	}
	if len(sens) > 0 {
		flags = append(flags, "sensitive APIs: "+strings.Join(sens, ", "))
	}
	if e.Location == 4 {
		flags = append(flags, "unpacked (developer mode)")
	}
	if !e.FromWebstore && e.Location != 4 {
		flags = append(flags, "not from the Chrome Web Store")
	}
	warn := enabled && ((len(broad) > 0 && !e.Withholding) || e.Location == 4 || risky)

	state := "disabled"
	if enabled {
		state = "enabled"
	}
	shown := strings.Join(hosts, " ")
	if len(hosts) > 4 {
		shown = strings.Join(hosts[:4], " ") + fmt.Sprintf(" +%d", len(hosts)-4)
	}
	if shown == "" {
		shown = "none"
	}
	detail := fmt.Sprintf("[%s] %s (%s) %s, v%s; hosts: %s", profName, label, id, state, orQ(man.Version), shown)
	if len(flags) > 0 {
		detail += "; " + strings.Join(flags, "; ")
	}
	ch := check{id: "brave-extension:" + prof + "/" + id, resource: "browser_extension", name: label, detail: detail,
		sev:   finding.SevInfo,
		title: fmt.Sprintf("Brave extension %s in profile %s", label, profName),
		evidence: map[string]any{"profile": profName, "extension_id": id, "version": man.Version, "enabled": enabled,
			"hosts": hosts, "sensitive_apis": sens, "flags": flags},
		rem: manual("Remove it at brave://extensions if you do not use it, or set its site access to \"On click\".")}
	if warn {
		ch.sev = finding.SevMedium
		ch.title = fmt.Sprintf("Brave extension %s in profile %s: %s", label, profName, strings.Join(flags, "; "))
	}
	return ch
}

// disabled follows Chromium: a non-empty disable_reasons list or state 0. Newer versions store
// disable_reasons as a number, which the prototype ignored; so does this, to stay equivalent.
func disabled(e extSettings) bool {
	var reasons []any
	if json.Unmarshal(e.DisableReasons, &reasons) == nil && len(reasons) > 0 {
		return true
	}
	return e.State != nil && *e.State == 0
}

var msgName = regexp.MustCompile(`^__MSG_(.+)__$`)

// localize resolves a "__MSG_name__" extension name from its _locales messages.
func localize(man manifest, extDir string) string {
	m := msgName.FindStringSubmatch(man.Name)
	if m == nil || extDir == "" {
		return man.Name
	}
	loc := man.DefaultLocale
	if loc == "" {
		loc = "en"
	}
	var msgs map[string]struct {
		Message string `json:"message"`
	}
	readJSON(filepath.Join(extDir, "_locales", loc, "messages.json"), &msgs)
	for k, v := range msgs {
		if strings.EqualFold(k, m[1]) {
			return v.Message
		}
	}
	return man.Name
}

// strs keeps the string permissions; manifests also hold objects (e.g. usbDevices).
func strs(xs []any) []string {
	out := []string{}
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func plists(dir string) []string {
	m, _ := filepath.Glob(filepath.Join(dir, "*.plist"))
	return m
}
