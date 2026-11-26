// Package version reports which build of segurata is running: what the linker stamped in release
// builds (.goreleaser.yaml), else the module version and VCS data the toolchain embeds.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var (
	Version = ""
	Commit  = ""
	Date    = ""
)

type Info struct {
	Version string
	Commit  string
	Date    string
	Go      string
	OS      string
	Arch    string
}

func Get() Info {
	bi, _ := debug.ReadBuildInfo()
	return resolve(Version, Commit, Date, bi)
}

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
