package aws

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

func TestDoctor(t *testing.T) {
	fr := &fakeRunner{
		replies: map[string]string{"sts get-caller-identity": `{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/me"}`},
	}
	checks := newTest(fr, "").Doctor(context.Background(), connector.Request{Config: map[string]any{"profiles": []any{"main"}}})
	if len(checks) != 1 || checks[0].Level != connector.OK || !strings.Contains(checks[0].Detail, "123456789012") {
		t.Fatalf("%+v", checks)
	}

	fr = &fakeRunner{errs: map[string]error{"sts get-caller-identity": errors.New("Error when retrieving token from sso: Token has expired and refresh failed")}}
	checks = newTest(fr, "").Doctor(context.Background(), connector.Request{Config: map[string]any{"profiles": []any{"main"}}})
	if len(checks) != 1 || checks[0].Level != connector.Fail || checks[0].Fix != "aws sso login --profile main" {
		t.Fatalf("%+v", checks)
	}

	fr = &fakeRunner{errs: map[string]error{"sts get-caller-identity": errors.New("An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation")}}
	checks = newTest(fr, "").Doctor(context.Background(), connector.Request{Config: map[string]any{"profiles": []any{"old"}}})
	if len(checks) != 1 || checks[0].Level != connector.Fail || !strings.Contains(checks[0].Fix, "aws configure --profile old") {
		t.Fatalf("static key: %+v", checks)
	}

	fr = &fakeRunner{errs: map[string]error{"configure list-profiles": fmt.Errorf("aws: %w", exec.ErrNotFound)}}
	checks = newTest(fr, "").Doctor(context.Background(), connector.Request{})
	if len(checks) != 1 || checks[0].Level != connector.Fail || !strings.Contains(checks[0].Fix, "install") {
		t.Fatalf("%+v", checks)
	}

	fr = &fakeRunner{replies: map[string]string{"configure list-profiles": ""}}
	if checks = newTest(fr, "").Doctor(context.Background(), connector.Request{}); checks[0].Level != connector.Fail || !strings.Contains(checks[0].Fix, "aws configure sso") {
		t.Fatalf("%+v", checks)
	}
}
