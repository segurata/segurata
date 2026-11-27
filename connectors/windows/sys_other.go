//go:build !windows

package windows

func system32() (string, error) { return "", errNotWindows }
