//go:build !windows

package windows

import "errors"

var errNotWindows = errors.New("the Windows registry and tools exist only on Windows")

type sysRegistry struct{}

func (sysRegistry) Read(Hive, string, ...string) (map[string]RegValue, error) {
	return nil, errNotWindows
}

func (sysRegistry) Has(Hive, string, string) (bool, error) { return false, errNotWindows }
