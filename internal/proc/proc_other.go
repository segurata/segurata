//go:build !unix

package proc

import "os/exec"

// ownGroup leaves cmd as exec.CommandContext made it: Windows has no process groups to kill, so
// only the direct child is killed (see the package documentation).
func ownGroup(*exec.Cmd) {}
