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
	never := func(context.Context, []byte, string, ...string) ([]byte, error) {
		t.Fatal("security ran")
		return nil, nil
	}
	for _, v := range []string{"", "two words", `quo"te`, "it's", `back\slash`, "ñ", "tab\there", "line\n"} {
		if err := (Keychain{Account: "me", Run: never}).Store(context.Background(), "svc", v); err == nil || strings.Contains(err.Error(), v) && v != "" {
			t.Errorf("%q: %v", v, err)
		}
	}
	// security -i would read "-a -s svc" as the account "-s".
	for _, k := range []Keychain{{Run: never}, {Account: "two words", Run: never}} {
		if err := k.Store(context.Background(), "svc", "v4lue"); err == nil {
			t.Errorf("account %q accepted", k.Account)
		}
	}
	if err := (Keychain{Account: "me", Run: never}).Store(context.Background(), "a b", "v4lue"); err == nil {
		t.Error("a service with a space accepted")
	}
}

func TestRead(t *testing.T) {
	cases := []struct {
		account, out, fail string
		args, value, err   string
		missing            bool
	}{
		{out: "v4lue\n", args: "find-generic-password -s svc -w", value: "v4lue"},
		{account: "me", out: "v4lue\r\n", args: "find-generic-password -a me -s svc -w", value: "v4lue"},
		{fail: "security: The specified item could not be found in the keychain.", missing: true},
		{fail: "security: User interaction is not allowed.", err: "reading svc from the Keychain: security: User interaction is not allowed."},
	}
	for _, c := range cases {
		var gotArgs []string
		k := Keychain{Account: c.account, Run: func(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
			if name != Security || stdin != nil {
				t.Errorf("ran %s with stdin %q", name, stdin)
			}
			gotArgs = args
			if c.fail != "" {
				return nil, errors.New(c.fail)
			}
			return []byte(c.out), nil
		}}
		v, err := k.Read(context.Background(), "svc")
		switch {
		case c.missing:
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("missing: %v", err)
			}
		case c.err != "":
			if errors.Is(err, ErrNotFound) || err == nil || err.Error() != c.err {
				t.Errorf("denied: %v", err)
			}
		case err != nil || v != c.value || strings.Join(gotArgs, " ") != c.args:
			t.Errorf("read %q %v with %v", v, err, gotArgs)
		}
	}
}

func TestHintPromptsForTheValue(t *testing.T) {
	if got := Default("me").Hint("svc"); got != "add it with: security add-generic-password -s svc -a $USER -w" {
		t.Errorf("hint %q", got)
	}
}
