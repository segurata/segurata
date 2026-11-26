//go:build !darwin && !windows

package clipboard

import (
	"context"
	"strings"
	"testing"
)

func TestOtherPlatformsPointToStdin(t *testing.T) {
	if _, err := Default().Read(context.Background()); err == nil || !strings.Contains(err.Error(), "--stdin") {
		t.Errorf("read: %v", err)
	}
	if err := Default().Clear(context.Background()); err == nil {
		t.Error("clear succeeded")
	}
}
