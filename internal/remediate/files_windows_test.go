package remediate

import (
	"errors"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

func TestWindowsRefusesUnixChmodBeforePlanningOrApplying(t *testing.T) {
	if _, err := (files{}).PlanGroup(t.Context(), nil); !errors.Is(err, errChmodOnWindows) {
		t.Fatalf("plan: %v", err)
	}
	if err := (files{}).ApplyGroup(t.Context(), nil, connector.Plan{}, connector.IO{}); !errors.Is(err, errChmodOnWindows) {
		t.Fatalf("apply: %v", err)
	}
}
