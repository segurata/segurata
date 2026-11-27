package windows

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// Hive is a registry root the connector reads.
type Hive string

const (
	HKLM Hive = "HKLM"
	HKCU Hive = "HKCU"
)

// Registry value types the connector reads and writes back (winnt.h).
const (
	regSZ       uint32 = 1
	regExpandSZ uint32 = 2
	regDWORD    uint32 = 4
	regQWORD    uint32 = 11
)

// RegValue is one registry value: Text is a string's data or a number in decimal.
type RegValue struct {
	Type uint32
	Text string
}

// Registry reads the values the checks name, with read access only. A key that does not exist is
// an error matching fs.ErrNotExist and one the user may not open fs.ErrPermission; a missing value
// is left out of the map.
type Registry interface {
	Read(hive Hive, path string, names ...string) (map[string]RegValue, error)
	// Has says whether the value exists without reading its data, for a value that may hold a
	// password.
	Has(hive Hive, path, name string) (bool, error)
}

// regKey is one key's values as read, or why it could not be.
type regKey struct {
	hive Hive
	path string
	vals map[string]RegValue
	err  error
}

func (c *Connector) key(hive Hive, path string, names ...string) regKey {
	v, err := c.Reg.Read(hive, path, names...)
	return regKey{hive: hive, path: path, vals: v, err: err}
}

func (k regKey) String() string { return string(k.hive) + `\` + k.path }

// text is the value's data, and whether it is set.
func (k regKey) text(name string) (string, bool) {
	v, ok := k.vals[name]
	return strings.TrimSpace(v.Text), ok
}

// num is the value as a whole number, whether stored as a number or as a string (ScreenSaveTimeOut).
func (k regKey) num(name string) (int64, bool) {
	s, ok := k.text(name)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// psPath is the key as PowerShell's registry provider names it, for the commands a fix gives.
func (k regKey) psPath() string { return string(k.hive) + `:\` + k.path }

// unreadable is why a key's checks cannot run: an absent key is not, since its values take their
// defaults.
func (k regKey) unreadable() (string, finding.State, bool) {
	switch {
	case k.err == nil || errors.Is(k.err, fs.ErrNotExist):
		return "", "", false
	case errors.Is(k.err, fs.ErrPermission):
		return needsAdmin("Get-ItemProperty -Path " + connector.PowerShellString(k.psPath())), finding.StateUnsupported, true
	}
	return fmt.Sprintf("could not read %s: %v", k, k.err), finding.StateError, true
}
