package connector_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/connector/connectortest"
	"github.com/segurata/segurata/internal/winsys"
)

// Windows has no sudo to prompt on the terminal: a sudo step is refused before anything runs.
func TestSystemRefusesSudoOnWindows(t *testing.T) {
	sys32, err := winsys.System32()
	if err != nil {
		t.Fatal(err)
	}
	hostname := filepath.Join(sys32, "hostname.exe")
	io := connectortest.QuietIO()
	err = connector.System{}.Run(context.Background(), connector.Step{Argv: []string{hostname}, Sudo: true}, io)
	if err == nil || !strings.Contains(err.Error(), "needs an elevated prompt; run it by hand") {
		t.Fatalf("a sudo step: %v", err)
	}
	if err := (connector.System{}).Run(context.Background(), connector.Step{Argv: []string{hostname}}, io); err != nil {
		t.Fatal(err)
	}
}
