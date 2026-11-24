package legacy

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

type kmFixture struct {
	cfg      string
	fake     *fakeKeychain
	out, err bytes.Buffer
}

func newKM(t *testing.T, items map[string]item) *kmFixture {
	x := &kmFixture{cfg: filepath.Join(t.TempDir(), "config.json"), fake: newFake(items)}
	write(t, x.cfg, oldConfig, 0o600)
	return x
}

func (x *kmFixture) run(in string, tty bool, args ...string) int {
	return KeychainCLI{Config: x.cfg, Exec: x.fake.run, In: strings.NewReader(in), Out: &x.out, Err: &x.err, TTY: tty}.Run(args)
}

func (x *kmFixture) printed() string { return x.out.String() + x.err.String() }

func twoItems() map[string]item {
	return map[string]item{
		"securizame-vercel":       {"u", "vercel-tok"},
		"securizame-openai-admin": {"me", "sk-admin-1"},
	}
}

func TestKeychainMigrateDryRunChangesNothing(t *testing.T) {
	x := newKM(t, twoItems())
	if code := x.run("", false); code != 0 {
		t.Fatalf("exit %d: %s", code, x.printed())
	}
	out := x.out.String()
	for _, want := range []string{"securizame-vercel", "-> segurata-vercel", `(account "me")`, "Dry run: nothing was changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if read(t, x.cfg) != oldConfig || len(x.fake.items) != 2 {
		t.Error("a dry run changed the config or the Keychain")
	}
	for _, c := range x.fake.calls {
		if _, _, w := flags(c.args); w || c.args[0] != "find-generic-password" {
			t.Errorf("a dry run ran security %v", c.args)
		}
	}
	x.fake.assertNoLeak(t, x.printed(), "vercel-tok", "sk-admin-1")
}

func TestKeychainMigrateApplyMovesEachItem(t *testing.T) {
	items := twoItems()
	items["segurata-vercel"] = item{"u", "vercel-tok"} // already copied: kept, old one removed
	x := newKM(t, items)
	if code := x.run("", false, "--apply", "--yes"); code != 0 {
		t.Fatalf("exit %d: %s", code, x.printed())
	}
	want := strings.NewReplacer("keychain:securizame-", "keychain:segurata-").Replace(oldConfig)
	if got := read(t, x.cfg); got != want {
		t.Errorf("config:\n%s\nwant:\n%s", got, want)
	}
	if mode(t, x.cfg) != 0o600 {
		t.Error("config mode")
	}
	if got := x.fake.items; len(got) != 2 || got["segurata-openai-admin"] != (item{"me", "sk-admin-1"}) || got["segurata-vercel"] != (item{"u", "vercel-tok"}) {
		t.Errorf("Keychain after: %v", got)
	}
	for _, want := range []string{"moved securizame-openai-admin to segurata-openai-admin", "moved securizame-vercel to segurata-vercel"} {
		if !strings.Contains(x.out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, x.out.String())
		}
	}
	x.fake.assertNoLeak(t, x.printed(), "vercel-tok", "sk-admin-1")
	// The old item is deleted only after the config points at the new one.
	last := x.fake.calls[len(x.fake.calls)-1]
	if last.args[0] != "delete-generic-password" {
		t.Errorf("last call %v", last.args)
	}
}

func TestKeychainMigrateApplyNeedsAnAnswer(t *testing.T) {
	x := newKM(t, twoItems())
	if code := x.run("", false, "--apply"); code != 1 || !strings.Contains(x.err.String(), "not a terminal") {
		t.Errorf("no TTY: exit %d %q", code, x.err.String())
	}
	y := newKM(t, twoItems())
	if code := y.run("n\n", true, "--apply"); code != 1 {
		t.Errorf("answered no: exit %d", code)
	}
	for _, f := range []*kmFixture{x, y} {
		if read(t, f.cfg) != oldConfig || len(f.fake.items) != 2 {
			t.Error("changed without a yes")
		}
	}
	z := newKM(t, twoItems())
	if code := z.run("y\n", true, "--apply"); code != 0 || len(z.fake.items) != 2 || z.fake.items["segurata-vercel"].value != "vercel-tok" {
		t.Errorf("answered yes: exit %d %v %s", code, z.fake.items, z.printed())
	}
}

func TestKeychainMigrateKeepsTheOldItemWhenTheCopyFails(t *testing.T) {
	for name, tc := range map[string]struct {
		items  map[string]item
		garble bool
		want   string
	}{
		"copy not stored": {twoItems(), true, "does not hold the value after storing it"},
		"new one differs": {map[string]item{"securizame-vercel": {"u", "vercel-tok"}, "securizame-openai-admin": {"me", "sk-admin-1"},
			"segurata-vercel": {"u", "other-tok"}, "segurata-openai-admin": {"me", "other-admin"}}, false, "already exists with a different value"},
		"value security -i would alter": {map[string]item{"securizame-vercel": {"u", "two words"}, "securizame-openai-admin": {"me", `q"uote`}}, false, "store it by hand"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newKM(t, tc.items)
			x.fake.garbleStore = tc.garble
			before := map[string]item{}
			for k, v := range x.fake.items {
				before[k] = v
			}
			if code := x.run("", false, "--apply", "--yes"); code != 1 || !strings.Contains(x.err.String(), tc.want) {
				t.Errorf("exit %d, stderr %q", code, x.err.String())
			}
			if read(t, x.cfg) != oldConfig {
				t.Error("the config changed")
			}
			for k, v := range before {
				if x.fake.items[k] != v && !strings.HasPrefix(k, "segurata-") {
					t.Errorf("%s changed", k)
				}
			}
			var values []string
			for _, v := range before {
				values = append(values, v.value)
			}
			x.fake.assertNoLeak(t, x.printed(), values...)
		})
	}
}

func TestKeychainMigrateSkipsMissingItemsAndCleanConfigs(t *testing.T) {
	x := newKM(t, map[string]item{"securizame-vercel": {"u", "vercel-tok"}})
	if code := x.run("", false, "--apply", "--yes"); code != 0 {
		t.Fatalf("exit %d: %s", code, x.printed())
	}
	if !strings.Contains(x.out.String(), "securizame-openai-admin") || !strings.Contains(x.out.String(), "missing from the Keychain: skipped") {
		t.Errorf("output:\n%s", x.out.String())
	}
	if cfg := read(t, x.cfg); !strings.Contains(cfg, "keychain:segurata-vercel") || !strings.Contains(cfg, "keychain:securizame-openai-admin") {
		t.Errorf("config:\n%s", cfg)
	}
	// Nothing left under the old name.
	x.out.Reset()
	write(t, x.cfg, `{"connectors": {}}`, 0o600)
	if code := x.run("", false); code != 0 || !strings.Contains(x.out.String(), "nothing to do") {
		t.Errorf("clean config: exit %d %q", code, x.out.String())
	}
	if code := x.run("", false, "extra"); code != 2 {
		t.Errorf("usage: exit %d", code)
	}
}
