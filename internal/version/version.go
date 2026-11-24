// Package version reports which build of segurata is running.
//
// Release builds stamp Version, Commit and Date through the linker (see .goreleaser.yaml):
//
//	-X github.com/segurata/segurata/internal/version.Version=v1.2.3
//
// Builds without those flags (go install, go build) fall back to the module version and VCS
// data the Go toolchain embeds in the binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set by the linker in release builds.
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

// Info describes the running binary.
type Info struct {
	Version string
	Commit  string
	Date    string
	Go      string
	OS      string
	Arch    string
}

// Get returns the build information of the running binary.
func Get() Info {
	bi, _ := debug.ReadBuildInfo()
	return resolve(Version, Commit, Date, bi)
}

// resolve prefers linker-stamped values and fills the gaps from the embedded build info.
func resolve(version, commit, date string, bi *debug.BuildInfo) Info {
	info := Info{Version: version, Commit: commit, Date: date, Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if bi != nil {
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		var modified bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if modified && commit == "" && info.Commit != "" {
			info.Commit += "-dirty"
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
}

// String renders the information on one line, as `segurata version` prints it.
func (i Info) String() string {
	s := "segurata " + i.Version
	if i.Commit != "" {
		s += " commit " + i.Commit
	}
	if i.Date != "" {
		s += " built " + i.Date
	}
	return s + fmt.Sprintf(" %s %s/%s", i.Go, i.OS, i.Arch)
}
