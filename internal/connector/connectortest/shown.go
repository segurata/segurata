package connectortest

import (
	"context"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

// ShownOnce is a Remediator whose first Plan is Shown, as if the owner had confirmed that plan,
// and whose every later Plan is the wrapped remediator's. A test drives it through the core to
// check that a confirmed plan which is no longer the remediator's never runs.
type ShownOnce struct {
	connector.Remediator
	Shown *connector.Plan // nil once shown
}

func (s *ShownOnce) Plan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	if p := s.Shown; p != nil {
		s.Shown = nil
		return *p, nil
	}
	return s.Remediator.Plan(ctx, f)
}
