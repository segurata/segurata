//go:build !darwin && !windows

package keychain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOtherPlatformsRefuseAndPointElsewhere(t *testing.T) {
	s := Default("me")
	err := s.Store(context.Background(), "svc", "v4lue-not-shown")
	if err == nil || strings.Contains(err.Error(), "v4lue-not-shown") || !strings.Contains(err.Error(), "use env: or op://") {
		t.Errorf("store: %v", err)
	}
	if _, err := s.Read(context.Background(), "svc"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("read: %v", err)
	}
	if !strings.Contains(s.Hint("svc"), "use env: or op://") {
		t.Errorf("hint %q", s.Hint("svc"))
	}
}
