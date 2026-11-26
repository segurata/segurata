package remediate

import (
	"context"
	"errors"
	"testing"

	"github.com/segurata/segurata/internal/config"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/run"
)

// scripted is a connector whose inventory is a function, run for real through run.Inventory so the
// check sees the run_end record the core writes.
type scripted func(ctx context.Context, emit connector.Emitter) error

func (scripted) Describe() connector.Description {
	return connector.Description{Name: "macos", Version: "0", Protocol: 1}
}

func (s scripted) Inventory(ctx context.Context, _ connector.Request, emit connector.Emitter) error {
	return s(ctx, emit)
}

func checkRun(t *testing.T, s scripted) Reinventory {
	return func(ctx context.Context) ([]*run.Result, error) {
		cfg := config.Config{Connectors: map[string]config.ConnectorConfig{"macos": {}}}
		targets, err := run.Targets(cfg, []connector.Connector{s}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return run.Inventory(ctx, cfg, targets, t.TempDir(), nil, run.Lent{})
	}
}

// A fix is verified only by a check run that inspected the finding's scope.
func TestVerifyNeedsTheFindingsScopeInspected(t *testing.T) {
	scoped := target
	scoped.Scope = "repo:me/app"
	ok := func(emit connector.Emitter) { emit.Status(finding.Status{Account: "mac", State: finding.StateOK}) }
	cases := []struct {
		name   string
		f      finding.Finding
		s      scripted
		verify bool
	}{
		{"inspected and gone", target, func(_ context.Context, e connector.Emitter) error { ok(e); return nil }, true},
		{"account signed out", target, func(_ context.Context, e connector.Emitter) error {
			e.Status(finding.Status{Account: "mac", State: finding.StateSignedOut})
			return nil
		}, false},
		{"scope skipped by the rate limit", scoped, func(_ context.Context, e connector.Emitter) error {
			ok(e)
			e.Scope("repo:me/app", false, "rate limit")
			return nil
		}, false},
		{"other scope skipped", scoped, func(_ context.Context, e connector.Emitter) error {
			ok(e)
			e.Scope("repo:me/other", false, "rate limit")
			return nil
		}, true},
		{"nothing said ok", target, func(context.Context, connector.Emitter) error { return nil }, false},
		{"interrupted", target, func(ctx context.Context, e connector.Emitter) error { ok(e); return nil }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if c.name == "interrupted" {
				cancel()
			}
			r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
			err := Execute(ctx, c.f, r, Options{Apply: true, Yes: true, IO: connectortest.QuietIO()}, checkRun(t, c.s))
			if c.verify && err != nil {
				t.Fatalf("want verified, got %v", err)
			}
			if !c.verify && !errors.Is(err, errUnverified) {
				t.Fatalf("want errUnverified, got %v", err)
			}
		})
	}
	killed := func(context.Context) ([]*run.Result, error) { return []*run.Result{{Name: "macos"}}, nil }
	r := &fakeRemediator{plan: connector.Plan{Action: "macos.firewall.enable"}}
	if err := Execute(context.Background(), target, r, Options{Apply: true, Yes: true, IO: connectortest.QuietIO()}, killed); !errors.Is(err, errUnverified) {
		t.Fatalf("a check run without run_end must not verify: %v", err)
	}
}
