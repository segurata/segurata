//go:build linux

package remediate

import "syscall"

const getTermios = syscall.TCGETS
