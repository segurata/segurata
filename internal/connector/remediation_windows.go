//go:build windows

package connector

import (
	"fmt"
	"strings"
)

// callOperator is PowerShell's &, which a quoted program needs to run rather than print.
func callOperator(parts []string) string {
	if len(parts) > 0 && strings.HasPrefix(parts[0], "'") {
		return "& "
	}
	return ""
}

func (c FileChange) String() string {
	now := "readable"
	switch read, write := c.Was&0o044 != 0, c.Was&0o022 != 0; {
	case read && write:
		now = "readable and writable"
	case write:
		now = "writable"
	}
	return fmt.Sprintf("make %s private: protected access list, full control for you and SYSTEM only (now %s by other accounts)", shellQuote(c.Path), now)
}
