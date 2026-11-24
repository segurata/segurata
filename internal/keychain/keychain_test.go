package keychain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestStoreSendsTheValueOnStdinOnly(t *testing.T) {
	var gotArgs []string
	var gotIn string
	k := Keychain{Account: "me", Run: func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
		gotArgs, gotIn = append([]string{name}, args...), string(stdin)
		return nil, errors.New("security: failed for s3cr3t-v4lue")
	}}
	err := k.Store(context.Background(), "svc", "s3cr3t-v4lue")
	if strings.Join(gotArgs, " ") != Security+" -i" || gotIn != "add-generic-password -U -a me -s svc -w s3cr3t-v4lue\n" {
		t.Errorf("ran %v with %q", gotArgs, gotIn)
	}
	if err == nil || strings.Contains(err.Error(), "s3cr3t-v4lue") {
		t.Errorf("error must name no value: %v", err)
	}
}

func TestStoreRefusesWhatSecurityWouldAlter(t *testing.T) {
	k := Keychain{Run: func(context.Context, []byte, string, ...string) ([]byte, error) {
		t.Fatal("security ran")
		return nil, nil
	}}
	for _, v := range []string{"", "two words", `quo"te`, "it's", `back\slash`, "ñ", "tab\there", "line\n"} {
		if err := k.Store(context.Background(), "svc", v); err == nil || strings.Contains(err.Error(), v) && v != "" {
			t.Errorf("%q: %v", v, err)
		}
	}
}

func TestReadTakesTheValueFromStdout(t *testing.T) {
	var gotArgs []string
	k := Keychain{Run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		gotArgs = args
		if args[len(args)-2] == "missing" {
			return nil, errors.New("not found")
		}
		return []byte("v4lue\n"), nil
	}}
	if v, err := k.Read(context.Background(), "svc"); err != nil || v != "v4lue" || strings.Join(gotArgs, " ") != "find-generic-password -s svc -w" {
		t.Errorf("%q %v %v", v, err, gotArgs)
	}
	if _, err := k.Read(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "reading missing") {
		t.Errorf("missing: %v", err)
	}
}
