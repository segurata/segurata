package browserext

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// install is one extension in one browser profile, as read from the profile's files.
type install struct {
	profile   string // display name
	daily     bool   // the profile was used in the last dailyWindow
	id        string
	name      string
	version   string
	location  int
	fromStore bool
	enabled   bool
	installed time.Time // zero when the profile does not say
	updated   time.Time
	hosts     []string
	allSites  bool // access to every site, granted without a click
	onClick   bool // access to every site, withheld until clicked
	apis      []string
}

// Chromium extension locations users install; the rest ship with the browser.
const (
	locWebStore = 1
	locUnpacked = 4
	locExternal = 6
	locCmdLine  = 8
)

// dailyWindow: a profile active this recently counts as one used for daily browsing.
const dailyWindow = 30 * 24 * time.Hour

var profileDir = regexp.MustCompile(`^(Default|Profile \d+)$`)

var broadHost = regexp.MustCompile(`^(<all_urls>|\*://\*/\*|https?://\*/\*|file:///\*)$`)

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
	FirstInstallTime   string          `json:"first_install_time"`
	InstallTime        string          `json:"install_time"` // older Chromium versions
	LastUpdateTime     string          `json:"last_update_time"`
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

type localState struct {
	Profile struct {
		InfoCache map[string]struct {
			ActiveTime float64 `json:"active_time"` // seconds since the Unix epoch
		} `json:"info_cache"`
	} `json:"profile"`
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// readBrowser returns every user-installed extension in every profile of one browser's data
// directory. Settings from Secure Preferences override those in Preferences.
func readBrowser(dir string, now time.Time) ([]install, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ls localState
	readJSON(filepath.Join(dir, "Local State"), &ls)
	var out []install
	var failures []error
	for _, e := range entries {
		if !e.IsDir() || !profileDir.MatchString(e.Name()) {
			continue
		}
		active := ls.Profile.InfoCache[e.Name()].ActiveTime
		daily := active > 0 && now.Sub(time.Unix(int64(active), 0)) < dailyWindow
		installs, err := readProfile(dir, e.Name(), daily)
		out = append(out, installs...)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return out, errors.Join(failures...)
}

func readProfile(dir, prof string, daily bool) ([]install, error) {
	var prefs, secure prefsFile
	var failures []error
	var read int
	for _, file := range []struct {
		name  string
		prefs *prefsFile
	}{{"Preferences", &prefs}, {"Secure Preferences", &secure}} {
		var parsed *prefsFile
		err := readJSON(filepath.Join(dir, prof, file.name), &parsed)
		switch {
		case err == nil && parsed != nil:
			*file.prefs = *parsed
			read++
		case err == nil:
			failures = append(failures, fmt.Errorf("profile %q: %s is null", prof, file.name))
		case !errors.Is(err, os.ErrNotExist):
			failures = append(failures, fmt.Errorf("profile %q: could not read %s: %w", prof, file.name, err))
		}
	}
	if read == 0 && len(failures) == 0 {
		return nil, nil // a remnant directory, as a failed profile deletion leaves: no extensions
	}
	name := prefs.Profile.Name
	if name == "" {
		name = prof
	}
	settings := map[string]json.RawMessage{}
	maps.Copy(settings, prefs.Extensions.Settings)
	maps.Copy(settings, secure.Extensions.Settings)
	var out []install
	for _, id := range slices.Sorted(maps.Keys(settings)) {
		var e *extSettings
		if err := json.Unmarshal(settings[id], &e); err != nil || e == nil {
			failures = append(failures, fmt.Errorf("profile %q: invalid extension record %q", prof, id))
			continue
		}
		switch e.Location {
		case locWebStore, locUnpacked, locExternal, locCmdLine:
			in := newInstall(filepath.Join(dir, prof), id, *e)
			in.profile, in.daily = name, daily
			out = append(out, in)
		}
	}
	return out, errors.Join(failures...)
}

func newInstall(profDir, id string, e extSettings) install {
	extDir := e.Path
	if extDir != "" && !filepath.IsAbs(extDir) {
		extDir = filepath.Join(profDir, "Extensions", e.Path)
	}
	man := manifest{}
	if e.Manifest != nil {
		man = *e.Manifest
	} else if extDir != "" {
		readJSON(filepath.Join(extDir, "manifest.json"), &man)
	}
	in := install{id: id, name: localize(man, extDir), version: man.Version, location: e.Location,
		fromStore: e.FromWebstore, enabled: !disabled(e), updated: chromeTime(e.LastUpdateTime)}
	if in.name == "" {
		in.name = id
	}
	in.installed = chromeTime(e.FirstInstallTime)
	if in.installed.IsZero() {
		in.installed = chromeTime(e.InstallTime)
	}
	if in.updated.IsZero() {
		in.updated = in.installed
	}
	act := e.ActivePermissions
	if act == nil {
		act = e.GrantedPermissions
	}
	if act == nil {
		act = &permissions{}
	}
	in.apis = strs(act.API)
	if act.API == nil {
		in.apis = strs(man.Permissions)
	}
	for _, h := range append(slices.Clone(act.ExplicitHost), act.ScriptableHost...) {
		if !slices.Contains(in.hosts, h) {
			in.hosts = append(in.hosts, h)
		}
		if broadHost.MatchString(h) {
			in.allSites, in.onClick = !e.Withholding, e.Withholding
		}
	}
	return in
}

// chromeTime parses Chromium's timestamps: microseconds since 1601-01-01 UTC, as a string.
func chromeTime(s string) time.Time {
	const epochDelta = 11644473600 * 1_000_000 // 1601-01-01 to 1970-01-01, in microseconds
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= epochDelta {
		return time.Time{}
	}
	return time.UnixMicro(v - epochDelta).UTC()
}

// disabled follows Chromium: a non-empty disable_reasons list or state 0. Newer versions store
// disable_reasons as a number; zero means none.
func disabled(e extSettings) bool {
	var reasons []any
	if json.Unmarshal(e.DisableReasons, &reasons) == nil && len(reasons) > 0 {
		return true
	}
	var n int
	if json.Unmarshal(e.DisableReasons, &n) == nil && n != 0 {
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
