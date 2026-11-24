package connector

import (
	"testing"
	"time"
)

// SetDescribeTimeout shortens how long LoadExternal waits for describe, for the test's duration.
func SetDescribeTimeout(t *testing.T, d time.Duration) {
	old := describeTimeout
	describeTimeout = d
	t.Cleanup(func() { describeTimeout = old })
}
