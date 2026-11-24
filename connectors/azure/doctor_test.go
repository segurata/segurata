package azure

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/connector"
)

func TestDoctor(t *testing.T) {
	checks := (&Connector{Run: fixture(), Now: time.Now}).Doctor(context.Background(), connector.Request{})
	if len(checks) != 1 || checks[0].Level != connector.OK || checks[0].Detail != "subscription Example in example.onmicrosoft.com" {
		t.Fatalf("%+v", checks)
	}
	cases := []struct {
		err         error
		detail, fix string
	}{
		{fmt.Errorf("az: %w", exec.ErrNotFound), "not installed", "install-azure-cli"},
		{errors.New("ERROR: Please run 'az login' to setup account."), "not signed in", "az login"},
		{errors.New("AADSTS700082: The refresh token has expired due to inactivity."), "expired", "az login"},
	}
	for _, tc := range cases {
		fr := &fakeRunner{errs: map[string]error{"account show": tc.err}}
		checks := (&Connector{Run: fr, Now: time.Now}).Doctor(context.Background(), connector.Request{})
		if len(checks) != 1 || checks[0].Level != connector.Fail || !strings.Contains(checks[0].Detail, tc.detail) || !strings.Contains(checks[0].Fix, tc.fix) {
			t.Errorf("%v: %+v", tc.err, checks)
		}
	}
}
