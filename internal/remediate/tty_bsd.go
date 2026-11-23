//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package remediate

import "syscall"

const getTermios = syscall.TIOCGETA
