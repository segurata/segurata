//go:build unix

package connector

import "fmt"

func callOperator([]string) string { return "" }

func (c FileChange) String() string {
	return fmt.Sprintf("chmod %o %s (now %o)", c.Mode.Perm(), shellQuote(c.Path), c.Was.Perm())
}
