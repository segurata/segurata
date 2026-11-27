//go:build windows

package windows

import "github.com/segurata/segurata/internal/winsys"

func system32() (string, error) { return winsys.System32() }
