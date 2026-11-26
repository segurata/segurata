//go:build windows

package secrets

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"
)

func TestAMissingCredentialPointsToCmdkey(t *testing.T) {
	svc := "segurata-test-missing-" + rand.Text()
	_, err := Resolve(context.Background(), "keychain:"+svc)
	if err == nil || !strings.Contains(err.Error(), "not found (add it with: cmdkey /generic:"+svc+" ") {
		t.Fatalf("got %v", err)
	}
}
