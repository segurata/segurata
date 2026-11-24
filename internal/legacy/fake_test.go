package legacy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/keychain"
)

// item is one generic password in the fake Keychain.
type item struct{ account, value string }

type call struct {
	name, stdin string
	args        []string
}

// fakeKeychain stands in for /usr/bin/security: a Keychain in memory and every call recorded, so a
// test can check that no value ever reached an argument list.
type fakeKeychain struct {
	items       map[string]item
	calls       []call
	garbleStore bool // security -i "succeeds" but stores something else
}

func newFake(items map[string]item) *fakeKeychain {
	if items == nil {
		items = map[string]item{}
	}
	return &fakeKeychain{items: items}
}

// flags reads -a and -s and reports -w.
func flags(args []string) (account, service string, w bool) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-a":
			i++
			account = args[i]
		case "-s":
			i++
			service = args[i]
		case "-w":
			w = true
		}
	}
	return account, service, w
}

func (f *fakeKeychain) run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name: name, stdin: string(stdin), args: append([]string(nil), args...)})
	if name != keychain.Security || len(args) == 0 {
		return nil, fmt.Errorf("unexpected program %s %v", name, args)
	}
	notFound := errors.New("security: The specified item could not be found in the keychain.")
	if args[0] == "-i" {
		fields := strings.Fields(string(stdin))
		if len(fields) != 8 || fields[0] != "add-generic-password" || fields[1] != "-U" {
			return nil, fmt.Errorf("unexpected security -i input")
		}
		account, service, _ := flags(fields[2:6])
		value := fields[7]
		if f.garbleStore {
			value = "garbled"
		}
		f.items[service] = item{account: account, value: value}
		return []byte("security> "), nil
	}
	account, service, w := flags(args[1:])
	it, ok := f.items[service]
	if !ok || (account != "" && account != it.account) {
		return nil, notFound
	}
	switch args[0] {
	case "find-generic-password":
		if w {
			return []byte(it.value + "\n"), nil
		}
		return fmt.Appendf(nil, "keychain: \"/Users/u/Library/Keychains/login.keychain-db\"\nattributes:\n    \"acct\"<blob>=\"%s\"\n    \"svce\"<blob>=\"%s\"\n", it.account, service), nil
	case "delete-generic-password":
		delete(f.items, service)
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected security %v", args)
}

func (f *fakeKeychain) keychain() keychain.Keychain { return keychain.Keychain{Run: f.run} }

// assertNoLeak fails when a value appears in an argument list, in a stdin other than security -i's
// add command, or in what the command printed.
func (f *fakeKeychain) assertNoLeak(t *testing.T, printed string, values ...string) {
	t.Helper()
	for _, v := range values {
		if strings.Contains(printed, v) {
			t.Errorf("a secret value was printed")
		}
		for _, c := range f.calls {
			if strings.Contains(strings.Join(c.args, " "), v) {
				t.Errorf("a secret value reached the arguments of %s %s", c.name, c.args[0])
			}
			if strings.Contains(c.stdin, v) && !(len(c.args) == 1 && c.args[0] == "-i") {
				t.Errorf("a secret value reached the stdin of %s %v", c.name, c.args)
			}
		}
	}
}
