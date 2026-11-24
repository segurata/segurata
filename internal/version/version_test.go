package version

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func buildInfo(mainVersion string, settings ...string) *debug.BuildInfo {
	bi := &debug.BuildInfo{Main: debug.Module{Path: "github.com/segurata/segurata", Version: mainVersion}}
	for i := 0; i+1 < len(settings); i += 2 {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: settings[i], Value: settings[i+1]})
	}
	return bi
}

func TestResolve(t *testing.T) {
	vcs := []string{"vcs.revision", "abc123", "vcs.time", "2026-11-24T10:00:00Z", "vcs.modified", "false"}
	for _, tc := range []struct {
		name                  string
		version, commit, date string
		bi                    *debug.BuildInfo
		want                  Info
	}{
		{"linker stamps win", "v1.2.3", "fff", "2026-11-25T00:00:00Z", buildInfo("v1.0.0", vcs...),
			Info{Version: "v1.2.3", Commit: "fff", Date: "2026-11-25T00:00:00Z"}},
		{"go install at a version", "", "", "", buildInfo("v1.0.0"),
			Info{Version: "v1.0.0"}},
		{"go build in a checkout", "", "", "", buildInfo("(devel)", vcs...),
			Info{Version: "dev", Commit: "abc123", Date: "2026-11-24T10:00:00Z"}},
		{"uncommitted changes", "", "", "", buildInfo("(devel)", "vcs.revision", "abc123", "vcs.modified", "true"),
			Info{Version: "dev", Commit: "abc123-dirty"}},
		{"no build info", "", "", "", nil,
			Info{Version: "dev"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolve(tc.version, tc.commit, tc.date, tc.bi)
			tc.want.Go, tc.want.OS, tc.want.Arch = runtime.Version(), runtime.GOOS, runtime.GOARCH
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestString(t *testing.T) {
	s := Info{Version: "v1.2.3", Commit: "abc123", Date: "2026-11-24T10:00:00Z", Go: "go1.26.3", OS: "linux", Arch: "arm64"}.String()
	if want := "segurata v1.2.3 commit abc123 built 2026-11-24T10:00:00Z go1.26.3 linux/arm64"; s != want {
		t.Errorf("got %q, want %q", s, want)
	}
	if s := (Info{Version: "dev", Go: "go1.26.3", OS: "darwin", Arch: "amd64"}).String(); strings.Contains(s, "commit") || strings.Contains(s, "built") {
		t.Errorf("empty fields rendered: %q", s)
	}
}
