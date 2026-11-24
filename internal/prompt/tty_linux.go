//go:build linux

package prompt

import "syscall"

const getTermios = syscall.TCGETS
