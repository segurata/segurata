package doctor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/run"
	"github.com/segurata/segurata/internal/tracker"
)

const secretValue = "sk-test-0123456789abcdef"

// plain is a connector without a Doctor: the core checks its needs.
type plain struct{ d connector.Description }

func (p plain) Describe() connector.Description { return p.d }
func (plain) Inventory(context.Context, connector.Request, connector.Emitter) error {
	return nil
}

// selfChecking reports its own checks and records the request it got.
type selfChecking struct {
	plain
	checks []connector.Check
	got    *connector.Request
}

func (s selfChecking) Doctor(_ context.Context, req connector.Request) []connector.Check {
	*s.got = req
	return s.checks
}

type fixture struct {
	home string
	env  Env
	out  *bytes.Buffer
	got  connector.Request
}

func newFixture(t *testing.T, cfg string) *fixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DOCTOR_TEST_KEY", secretValue)
	dir := filepath.Join(home, ".config", "segurata")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fx := &fixture{home: home, out: &bytes.Buffer{}}
	if cfg != "" {
		write(t, filepath.Join(dir, "config.json"), cfg, 0o600)
	}
	installed := map[string]bool{"jq": true}
	fx.env = Env{
		Out:        fx.out,
		ConfigPath: filepath.Join(dir, "config.json"),
		KeyPath:    filepath.Join(dir, "fingerprint.key"),
		Tracker: tracker.Paths{Tracker: filepath.Join(home, ".segurata", "tracker.json"),
			LegacyLedger: filepath.Join(home, ".segurata", "rotations.json"), LegacyAccepted: filepath.Join(dir, "accepted.json")},
		OutDir: filepath.Join(home, "out"),
		GOOS:   "darwin",
		Connectors: []connector.Connector{
			plain{connector.Description{Name: "api", Needs: []string{"secret:API_KEY"}}},
			plain{connector.Description{Name: "browser", Needs: []string{"cdp", "os:linux"}}},
			plain{connector.Description{Name: "plugin", Needs: []string{"cli:jq", "cli:yq (optional)", "cli:zz"}}},
			selfChecking{plain{connector.Description{Name: "cloud", Needs: []string{"cli:cloudctl", "secret:CLOUD_TOKEN"}}},
				[]connector.Check{{Level: connector.OK, What: "cloudctl", Detail: "signed in"}}, &fx.got},
		},
		Request: run.NewRequest,
		CDPVersion: func(context.Context, string) (cdp.Version, error) {
			return cdp.Version{}, errors.New("connection refused")
		},
		LookPath: func(n string) (string, error) {
			if installed[n] {
				return "/usr/bin/" + n, nil
			}
			return "", exec.ErrNotFound
		},
	}
	return fx
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func (fx *fixture) run(t *testing.T, selectors ...string) (string, int) {
	t.Helper()
	fx.out.Reset()
	code := fx.env.Run(context.Background(), selectors)
	o := fx.out.String()
	if strings.Contains(o, secretValue) {
		t.Fatalf("secret printed:\n%s", o)
	}
	return o, code
}

func wantLines(t *testing.T, out string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(out, l) {
			t.Errorf("missing %q in:\n%s", l, out)
		}
	}
}

const testConfig = `{"connectors": {
  "api":        {"secrets": {"API_KEY": "env:DOCTOR_TEST_KEY"}},
  "api:broken": {"secrets": {"API_KEY": "env:DOCTOR_TEST_MISSING"}},
  "cloud":      {"secrets": {"CLOUD_TOKEN": "env:DOCTOR_TEST_KEY"}},
  "typo":       {}
}}`

func TestDoctorReportsEveryArea(t *testing.T) {
	fx := newFixture(t, testConfig)
	out, code := fx.run(t)
	if code != 1 {
		t.Errorf("exit %d with failures", code)
	}
	wantLines(t, out,
		"OK    config      "+fx.env.ConfigPath+": valid, 4 connector instance(s)",
		"WARN  config      connectors.typo: no connector is called typo",
		"FAIL  cdp         http://127.0.0.1:9222: not reachable (needed by browser): connection refused",
		"fix: start the browser with --remote-debugging-port=9222",
		"OK    api         secret API_KEY: env:DOCTOR_TEST_KEY resolves",
		"FAIL  api:broken  secret API_KEY: environment variable DOCTOR_TEST_MISSING is not set",
		"fix: make env:DOCTOR_TEST_MISSING resolve, or change connectors.api:broken.secrets.API_KEY",
		"WARN  browser     platform: runs on linux only; it reports unsupported on darwin",
		"OK    plugin      jq: /usr/bin/jq",
		"WARN  plugin      yq: not found in PATH",
		"FAIL  plugin      zz: not found in PATH",
		"OK    cloud       secret CLOUD_TOKEN: env:DOCTOR_TEST_KEY resolves",
		"OK    cloud       cloudctl: signed in",
		"WARN  state       fingerprint key "+fx.env.KeyPath+": not created yet",
		"OK    state       tracker "+fx.env.Tracker.Tracker+": none yet",
		"OK    state       tracker dir "+filepath.Dir(fx.env.Tracker.Tracker)+": not created yet",
		"OK    state       output dir "+fx.env.OutDir+": not created yet",
	)
	if strings.Contains(out, "cloudctl: not found") || strings.Contains(out, "secret CLOUD_TOKEN: not configured") {
		t.Error("a connector with a Doctor checks its own CLIs and secrets")
	}
	if fx.got.Secrets["CLOUD_TOKEN"] != secretValue {
		t.Error("the connector's Doctor did not get the resolved secret")
	}
}

func TestDoctorUnconfiguredSecretAndOneConnector(t *testing.T) {
	fx := newFixture(t, "")
	out, code := fx.run(t, "api")
	if code != 0 {
		t.Errorf("warnings only, exit %d:\n%s", code, out)
	}
	wantLines(t, out,
		"WARN  config  "+fx.env.ConfigPath+": not found",
		"WARN  api     secret API_KEY: not configured: the connector is skipped",
		`fix: add "secrets": {"API_KEY": "keychain:segurata-api"} to connectors.api`,
	)
	for _, other := range []string{"plugin", "cdp", "cloud"} {
		if strings.Contains(out, other) {
			t.Errorf("--connector api checked %s:\n%s", other, out)
		}
	}
	if _, code := fx.run(t, "nope"); code != 2 {
		t.Errorf("unknown connector: exit %d", code)
	}
}

func TestDoctorCDPReachable(t *testing.T) {
	fx := newFixture(t, "")
	fx.env.CDPVersion = func(_ context.Context, url string) (cdp.Version, error) {
		return cdp.Version{Browser: "Brave/1.80", WebSocketDebuggerURL: "ws://x"}, nil
	}
	out, _ := fx.run(t, "browser")
	wantLines(t, out, "OK    cdp      http://127.0.0.1:9222: Brave/1.80 (needed by browser). Accepted-risk tradeoff")
}

func TestDoctorInvalidConfig(t *testing.T) {
	fx := newFixture(t, `{"connectors": [`)
	out, code := fx.run(t)
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	wantLines(t, out, "FAIL  config  "+fx.env.ConfigPath+": invalid:", "OK    state")
}

func TestDoctorStateModes(t *testing.T) {
	fx := newFixture(t, "")
	write(t, fx.env.KeyPath, strings.Repeat("ab", 32)+"\n", 0o644)
	write(t, fx.env.Tracker.Tracker, `{broken`, 0o600)
	write(t, fx.env.Tracker.LegacyLedger, `{"version": 1, "items": []}`, 0o600)
	if err := os.Chmod(filepath.Dir(fx.env.Tracker.Tracker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fx.env.OutDir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := fx.run(t, "api")
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	wantLines(t, out,
		"FAIL  state   fingerprint key "+fx.env.KeyPath+": mode 0644, want 0600",
		"fix: chmod 600 "+fx.env.KeyPath,
		"FAIL  state   tracker "+fx.env.Tracker.Tracker+": unreadable:",
		"WARN  state   old state file "+fx.env.Tracker.LegacyLedger+": not imported into the tracker yet",
		"OK    state   tracker dir "+filepath.Dir(fx.env.Tracker.Tracker)+": mode 0700",
		"WARN  state   output dir "+fx.env.OutDir+": mode 0755, want 0700",
		"fix: chmod 700 "+fx.env.OutDir,
	)
	if strings.Contains(out, "abab") {
		t.Error("key printed")
	}
}

func TestKeychainServiceMatchesConnectorMessages(t *testing.T) {
	cases := map[[2]string]string{
		{"openai", "OPENAI_ADMIN_KEY"}:              "segurata-openai-admin",
		{"anthropic", "ANTHROPIC_ADMIN_KEY"}:        "segurata-anthropic-admin",
		{"openrouter", "OPENROUTER_MANAGEMENT_KEY"}: "segurata-openrouter-admin",
		{"vercel", "VERCEL_TOKEN"}:                  "segurata-vercel",
		{"cloudflare", "CLOUDFLARE_API_TOKEN"}:      "segurata-cloudflare",
	}
	for in, want := range cases {
		if got := keychainService(in[0], in[1]); got != want {
			t.Errorf("%v: got %q, want %q", in, got, want)
		}
	}
}
