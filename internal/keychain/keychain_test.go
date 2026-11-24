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

func TestFindReadsAttributesOnly(t *testing.T) {
	var gotArgs []string
	k := Keychain{Run: func(_ context.Context, _ []byte, _ string, args ...string) ([]byte, error) {
		gotArgs = args
		if args[len(args)-1] == "missing" {
			return nil, errors.New("not found")
		}
		return []byte("keychain: \"x\"\nattributes:\n    \"acct\"<blob>=\"dgil\"\n    \"svce\"<blob>=\"svc\"\n"), nil
	}}
	if acct, err := k.Find(context.Background(), "svc"); err != nil || acct != "dgil" || strings.Join(gotArgs, " ") != "find-generic-password -s svc" {
		t.Errorf("%q %v %v", acct, err, gotArgs)
	}
	if _, err := k.Find(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}
