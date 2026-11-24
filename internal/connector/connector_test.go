package connector_test

import (
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
)

func TestHintFor(t *testing.T) {
	if got := connector.HintFor("KEY", "KEY", "create one"); got != "create one" {
		t.Errorf("the connector's secret: %q", got)
	}
	if got := connector.HintFor("OTHER", "KEY", "create one"); got != "" {
		t.Errorf("another secret: %q", got)
	}
}

func TestNow(t *testing.T) {
	fixed := time.Date(2026, 11, 24, 10, 0, 0, 0, time.FixedZone("CET", 3600))
	if got := connector.Now(func() time.Time { return fixed }); !got.Equal(fixed) || got.Location() != time.UTC {
		t.Errorf("a fixed clock: %v", got)
	}
	if got := connector.Now(nil); got.Location() != time.UTC || time.Since(got) > time.Minute {
		t.Errorf("the real clock: %v", got)
	}
}
