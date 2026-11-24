//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package prompt

import "syscall"

const getTermios = syscall.TIOCGETA
