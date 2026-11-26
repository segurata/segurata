package connector_test

import (
	"testing"

	"github.com/segurata/segurata/internal/proc/proctest"
)

// The fake executables some tests start are this binary under another name.
func TestMain(m *testing.M) { proctest.Main(m) }
