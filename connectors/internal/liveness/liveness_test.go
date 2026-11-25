package liveness

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Invented values: none is a real key of anyone.
const (
	liveKey  = "LIVE-0000-fake-key-for-tests-only-aaaa"
	deadKey  = "DEAD-0000-fake-key-for-tests-only-bbbb"
	flakyKey = "FLAKY-000-fake-key-for-tests-only-cccc"
	keyID    = "AKIAEXAMPLEFAKE00000"
)

// fake is every provider at once: it answers each endpoint as the provider documents, by the
// credential the request carries, and records the methods it saw.
type fake struct {
	*httptest.Server
	mu      sync.Mutex
	methods []string
	paths   []string
}

func newFake(t *testing.T) *fake {
	f := &fake{}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// credential is the secret the request carries, wherever the provider wants it.
func credential(r *http.Request) string {
	if v := r.Header.Get("X-Api-Key"); v != "" {
		return v
	}
	if v := r.Header.Get("Private-Token"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Goog-Api-Key"); v != "" {
		return v
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/bot"); ok {
		tok, _, _ := strings.Cut(rest, "/")
		return tok
	}
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.methods = append(f.methods, r.Method)
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	reply := func(code int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
	cred := credential(r)
	if r.Method != http.MethodGet && !(r.Method == http.MethodPost && r.URL.Path == "/api/auth.test" && r.ContentLength <= 0) {
		reply(http.StatusMethodNotAllowed, `{}`)
		return
	}
	if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
		auth := r.Header.Get("Authorization")
		switch {
		case r.URL.RawQuery != stsQuery || r.Header.Get("X-Amz-Date") == "":
			reply(http.StatusBadRequest, `<ErrorResponse><Error><Code>MissingAuthenticationToken</Code></Error></ErrorResponse>`)
		case strings.Contains(auth, "Credential="+keyID+"/"):
			reply(http.StatusOK, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::012345678901:user/me</Arn><UserId>AIDAFAKE</UserId><Account>012345678901</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case strings.Contains(auth, "Credential=AKIAMISMATCH00000000/"):
			reply(http.StatusForbidden, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`)
		default:
			reply(http.StatusForbidden, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>The security token included in the request is invalid.</Message></Error></ErrorResponse>`)
		}
		return
	}
	if cred == flakyKey {
		reply(http.StatusServiceUnavailable, `{}`)
		return
	}
	live := cred == liveKey || strings.HasSuffix(cred, liveKey)
	switch r.URL.Path {
	case "/api/auth.test": // Slack: 200 either way
		if live {
			reply(http.StatusOK, `{"ok":true,"team_id":"T0FAKE","user_id":"U0FAKE"}`)
		} else {
			reply(http.StatusOK, `{"ok":false,"error":"token_revoked"}`)
		}
	case "/v1beta/models": // Google
		switch {
		case live:
			reply(http.StatusForbidden, `{"error":{"code":403,"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED"}]}}`)
		default:
			reply(http.StatusBadRequest, `{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID"}]}}`)
		}
	default:
		switch {
		case live && r.URL.Path == "/user":
			reply(http.StatusOK, `{"login":"octocat","id":1}`)
		case live && r.URL.Path == "/api/v4/user":
			reply(http.StatusOK, `{"username":"gitlab-me"}`)
		case live && r.URL.Path == "/api/whoami-v2":
			reply(http.StatusOK, `{"name":"hf-me","type":"user"}`)
		case live && r.URL.Path == "/-/whoami":
			reply(http.StatusOK, `{"username":"npm-me"}`)
		case live && strings.HasSuffix(r.URL.Path, "/getMe"):
			reply(http.StatusOK, `{"ok":true,"result":{"id":1,"is_bot":true,"username":"fake_bot"}}`)
		case live:
			reply(http.StatusOK, `{"data":[]}`)
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			reply(http.StatusUnauthorized, `{"ok":false,"error_code":401,"description":"Unauthorized"}`)
		default:
			// Providers echo part of the key in their messages; results must not keep it.
			reply(http.StatusUnauthorized, `{"error":{"message":"Incorrect API key provided: `+cred+`"}}`)
		}
	}
}

func (f *fake) checker() *Checker {
	bases := map[string][]string{}
	for _, p := range providers {
		bases[p.name] = []string{f.URL}
	}
	return &Checker{Config: Config{Enabled: true, Owners: []attribution.Owner{attribution.Mine}}, Bases: bases, Interval: time.Millisecond}
}

func TestEveryProviderLiveAndDead(t *testing.T) {
	f := newFake(t)
	c := f.checker()
	cases := []struct {
		typ, prefix    string
		account        string
		deadState      secretrisk.LiveState
		liveReasonPart string
	}{
		{"openai-project", "sk-proj-", "", secretrisk.Dead, "HTTP 200"},
		{"openai-service", "sk-admin-", "", secretrisk.Dead, "HTTP 200"},
		{"anthropic", "sk-ant-api03-", "", secretrisk.Dead, "HTTP 200"},
		{"anthropic", "sk-ant-admin01-", "", secretrisk.Dead, "HTTP 200"},
		{"openrouter", "sk-or-v1-", "", secretrisk.Dead, "HTTP 200"},
		{"github", "ghp_", "github:octocat", secretrisk.Dead, "HTTP 200"},
		{"github-pat", "github_pat_", "github:octocat", secretrisk.Dead, "HTTP 200"},
		{"gitlab", "glpat-", "gitlab:gitlab-me", secretrisk.Unknown, "HTTP 200"},
		{"google-api-key", "AIza", "", secretrisk.Dead, "SERVICE_DISABLED"},
		{"slack-token", "xoxb-", "slack:T0FAKE", secretrisk.Dead, "ok"},
		{"stripe-live", "sk_live_", "", secretrisk.Dead, "HTTP 200"},
		{"stripe-test", "rk_test_", "", secretrisk.Dead, "HTTP 200"},
		{"sendgrid", "SG.", "", secretrisk.Dead, "HTTP 200"},
		{"telegram-bot", "123456789:AA", "telegram:@fake_bot", secretrisk.Dead, "HTTP 200"},
		{"huggingface", "hf_", "huggingface:hf-me", secretrisk.Dead, "HTTP 200"},
		{"npm-token", "npm_", "npm:npm-me", secretrisk.Dead, "HTTP 200"},
	}
	for _, tc := range cases {
		probes := []Probe{
			{Fingerprints: []string{"live"}, Type: tc.typ, Value: tc.prefix + liveKey},
			{Fingerprints: []string{"dead"}, Type: tc.typ, Value: tc.prefix + deadKey},
			{Fingerprints: []string{"flaky"}, Type: tc.typ, Value: flakyKey},
		}
		got, st := c.Check(context.Background(), probes)
		name := tc.typ + " " + tc.prefix
		if r := got["live"]; r.State != secretrisk.Live || r.Account != tc.account || !strings.Contains(r.Reason, tc.liveReasonPart) || r.CheckedAt.IsZero() || r.Endpoint == "" || r.Provider == "" {
			t.Errorf("%s live: %+v", name, r)
		}
		if r := got["dead"]; r.State != tc.deadState {
			t.Errorf("%s dead: %+v", name, r)
		}
		if r := got["flaky"]; r.State != secretrisk.Unknown {
			t.Errorf("%s flaky: %+v", name, r)
		}
		if st.Asked != 3 || st.Live != 1 {
			t.Errorf("%s stats %+v", name, st)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(string(raw), liveKey) || strings.Contains(string(raw), deadKey) || strings.Contains(string(raw), "0000-fake") {
			t.Errorf("%s: a result holds the key: %s", name, raw)
		}
	}
	for i, m := range f.methods {
		if m != http.MethodGet && f.paths[i] != "/api/auth.test" {
			t.Errorf("sent %s %s: only GET is allowed, and POST without a body to Slack's auth.test", m, f.paths[i])
		}
	}
}

func TestQuotaAndCreditsMeanAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/key" {
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := &Checker{Bases: map[string][]string{"openai": {srv.URL}, "openrouter": {srv.URL}}, Interval: time.Millisecond}
	got, _ := c.Check(context.Background(), []Probe{
		{Fingerprints: []string{"o"}, Type: "openai-project", Value: liveKey},
		{Fingerprints: []string{"r"}, Type: "openrouter", Value: liveKey},
	})
	if got["o"].State != secretrisk.Live || got["r"].State != secretrisk.Live {
		t.Errorf("429 from OpenAI and 402 from OpenRouter: %+v", got)
	}
}

func TestDeadOnlyWhenEveryRegionSaysSo(t *testing.T) {
	global, eu := newFake(t), newFake(t)
	c := global.checker()
	c.Bases["sendgrid"] = []string{global.URL, eu.URL}
	got, _ := c.Check(context.Background(), []Probe{{Fingerprints: []string{"d"}, Type: "sendgrid", Value: "SG." + deadKey}})
	if got["d"].State != secretrisk.Dead || len(eu.paths) != 1 {
		t.Errorf("a key both hosts reject: %+v, EU asked %d times", got["d"], len(eu.paths))
	}
	euOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"scopes":[]}`)) }))
	defer euOnly.Close()
	c.Bases["sendgrid"] = []string{global.URL, euOnly.URL}
	got, _ = c.Check(context.Background(), []Probe{{Fingerprints: []string{"e"}, Type: "sendgrid", Value: "SG." + deadKey}})
	if got["e"].State != secretrisk.Live {
		t.Errorf("an EU key the global host rejects: %+v", got["e"])
	}
	if p := byName("sendgrid"); len(p.bases) != 2 || !strings.Contains(p.bases[1], "api.eu.sendgrid.com") {
		t.Errorf("sendgrid hosts %v", p.bases)
	}
}

func TestEndpointsTried(t *testing.T) {
	f := newFake(t)
	c := f.checker()
	c.Check(context.Background(), []Probe{
		{Fingerprints: []string{"a"}, Type: "openai-service", Value: "sk-admin-" + liveKey},
		{Fingerprints: []string{"b"}, Type: "anthropic", Value: "sk-ant-admin01-" + liveKey},
		{Fingerprints: []string{"c"}, Type: "telegram-bot", Value: "123:AA" + liveKey},
	})
	joined := strings.Join(f.paths, " ")
	for _, want := range []string{"/v1/organization/projects", "/v1/organizations/me", "/getMe"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no call to %s in %s", want, joined)
		}
	}
	got, _ := c.Check(context.Background(), []Probe{{Fingerprints: []string{"t"}, Type: "telegram-bot", Value: "123:AA" + liveKey}})
	if strings.Contains(got["t"].Endpoint, liveKey) || !strings.Contains(got["t"].Endpoint, "/bot<token>/getMe") {
		t.Errorf("telegram endpoint shown as %q", got["t"].Endpoint)
	}
}

func TestAWSPair(t *testing.T) {
	f := newFake(t)
	c := f.checker()
	got, st := c.Check(context.Background(), []Probe{
		{Fingerprints: []string{"secret", "id"}, Type: "aws-secret-key", Value: "fake/secret/for/tests/only/0000000000000", KeyID: keyID},
		{Fingerprints: []string{"gone"}, Type: "aws-secret-key", Value: "fake/secret/for/tests/only/1111111111111", KeyID: "AKIADELETEDFAKE00000"},
		{Fingerprints: []string{"mismatch"}, Type: "aws-secret-key", Value: "fake/secret/for/tests/only/2222222222222", KeyID: "AKIAMISMATCH00000000"},
		{Fingerprints: []string{"alone"}, Type: "aws-secret-key", Value: "fake/secret/for/tests/only/3333333333333"},
	})
	if r := got["secret"]; r.State != secretrisk.Live || r.Account != "aws:012345678901" || got["id"] != r {
		t.Errorf("pair: %+v / %+v", r, got["id"])
	}
	if r := got["gone"]; r.State != secretrisk.Dead || r.Reason != "InvalidClientTokenId" {
		t.Errorf("deleted key id: %+v", r)
	}
	if r := got["mismatch"]; r.State != secretrisk.Unknown || r.Reason != "SignatureDoesNotMatch" {
		t.Errorf("secret that is not the key id's: %+v", r)
	}
	if _, ok := got["alone"]; ok || st.Unsupported != 1 {
		t.Errorf("a secret key without its key id cannot be tried: %+v %+v", got["alone"], st)
	}
}

// TestSigV4 checks the signer against AWS's Signature Version 4 test suite, case get-vanilla.
func TestSigV4(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	h := sigV4("", "example.amazonaws.com", "us-east-1", "service", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", at)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := h.Get("Authorization"); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if h.Get("X-Amz-Date") != "20150830T123600Z" {
		t.Errorf("date %s", h.Get("X-Amz-Date"))
	}
}

func TestUnsupportedAndAllowlist(t *testing.T) {
	f := newFake(t)
	c := f.checker()
	c.Config.Providers = []string{"github"}
	got, st := c.Check(context.Background(), []Probe{
		{Fingerprints: []string{"a"}, Type: "slack-webhook", Value: liveKey},   // trying it would post
		{Fingerprints: []string{"b"}, Type: "npm-authtoken", Value: liveKey},   // any registry
		{Fingerprints: []string{"c"}, Type: "aws-access-key-id", Value: keyID}, // needs its secret
		{Fingerprints: []string{"d"}, Type: "openai-project", Value: liveKey},  // not in the allowlist
		{Fingerprints: []string{"e"}, Type: "github", Value: "ghp_" + liveKey}, // allowed
	})
	if st.Unsupported != 3 || st.NotAllowed != 1 || st.Asked != 1 || len(got) != 1 {
		t.Errorf("stats %+v, results %v", st, got)
	}
	if len(f.paths) != 1 {
		t.Errorf("calls %v", f.paths)
	}
}

func TestCache(t *testing.T) {
	f := newFake(t)
	path := filepath.Join(t.TempDir(), "cache", "liveness.json")
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	c := f.checker()
	c.Cache, c.Now = LoadCache(path), func() time.Time { return now }
	probes := []Probe{
		{Fingerprints: []string{"live"}, Type: "github", Value: "ghp_" + liveKey},
		{Fingerprints: []string{"dead"}, Type: "github", Value: "ghp_" + deadKey},
		{Fingerprints: []string{"flaky"}, Type: "github", Value: flakyKey},
	}
	c.Check(context.Background(), probes)
	if err := c.Cache.Save(now); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache file %v %v", st, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "fake-key") {
		t.Fatal("the cache holds a value")
	}
	calls := func() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.paths) }
	before := calls()
	later := func(d time.Duration) (map[string]secretrisk.Liveness, Stats) {
		c.Cache, c.Now = LoadCache(path), func() time.Time { return now.Add(d) }
		return c.Check(context.Background(), probes)
	}
	got, st2 := later(time.Hour)
	if st2.Cached != 2 || st2.Asked != 1 || calls()-before != 1 || got["live"].State != secretrisk.Live || got["dead"].State != secretrisk.Dead {
		t.Errorf("an hour later: unknown is asked again, the rest comes from the cache: %+v", st2)
	}
	_, st3 := later(2 * 24 * time.Hour)
	if st3.Cached != 1 || st3.Asked != 2 {
		t.Errorf("two days later the live result expired, the dead one holds: %+v", st3)
	}
	_ = c.Cache.Save(now.Add(2 * 24 * time.Hour))
	_, st4 := later(8 * 24 * time.Hour)
	if st4.Cached != 0 {
		t.Errorf("eight days later nothing holds: %+v", st4)
	}
	if LoadCache(filepath.Join(t.TempDir(), "missing.json")).Results == nil {
		t.Error("a missing cache is an empty one")
	}
	broken := filepath.Join(t.TempDir(), "broken.json")
	_ = os.WriteFile(broken, []byte(`{"version":1,"results":null}`), 0o600)
	bc := LoadCache(broken)
	bc.put([]string{"x"}, secretrisk.Liveness{State: secretrisk.Live, CheckedAt: now})
	if _, ok := bc.fresh([]string{"x"}, now); !ok {
		t.Error("a cache file without results is an empty cache")
	}
}

func TestInterruptedAndRateLimited(t *testing.T) {
	f := newFake(t)
	c := f.checker()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, st := c.Check(ctx, []Probe{{Fingerprints: []string{"a"}, Type: "github", Value: liveKey}})
	if st.Interrupted != 1 || st.Asked != 0 {
		t.Errorf("a run out of time asks nothing: %+v", st)
	}
	c.Interval = 30 * time.Millisecond
	var probes []Probe
	for _, typ := range []string{"github", "openai-project", "huggingface", "npm-token"} {
		probes = append(probes, Probe{Fingerprints: []string{typ}, Type: typ, Value: liveKey})
	}
	start := time.Now()
	c.Check(context.Background(), probes)
	if d := time.Since(start); d < 3*c.Interval {
		t.Errorf("4 calls across providers took %s, under the global interval", d)
	}
}

func TestParseConfig(t *testing.T) {
	c, err := ParseConfig(nil)
	if err != nil || c.Enabled || len(c.Owners) != 1 || c.Owners[0] != attribution.Mine || c.Providers != nil {
		t.Errorf("default: %+v %v", c, err)
	}
	c, err = ParseConfig(map[string]any{"enabled": true, "owners": []any{"mine", "unknown"}, "providers": []any{"github", "aws"}})
	if err != nil || !c.Enabled || !c.Allows(attribution.Unknown) || c.Allows(attribution.NotMine) || !c.allowsProvider("aws") || c.allowsProvider("openai") {
		t.Errorf("full: %+v %v", c, err)
	}
	for _, bad := range []any{
		"yes",
		map[string]any{"enabled": "true"},
		map[string]any{"owners": []any{"not-mine"}},
		map[string]any{"owners": []any{"mine", "not-mine"}},
		map[string]any{"owners": "mine"},
		map[string]any{"providers": []any{"twilio"}},
	} {
		if _, err := ParseConfig(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSupported(t *testing.T) {
	for _, typ := range []string{"github", "aws-secret-key", "google-api-key", "slack-token"} {
		if !Supported(typ) {
			t.Errorf("%s unsupported", typ)
		}
	}
	for _, typ := range []string{"slack-webhook", "aws-access-key-id", "npm-authtoken", "private-key", "jwt"} {
		if Supported(typ) {
			t.Errorf("%s supported", typ)
		}
	}
}

// A 403 from GitHub may be an installation token on /user or a block after many invalid tokens:
// neither says whether this one works.
func TestGitHubForbiddenIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	c := &Checker{Bases: map[string][]string{"github": {srv.URL}}, Interval: time.Millisecond}
	got, _ := c.Check(context.Background(), []Probe{{Fingerprints: []string{"g"}, Type: "github", Value: "ghs_" + liveKey}})
	if got["g"].State != secretrisk.Unknown {
		t.Errorf("403: %+v", got["g"])
	}
}

// A probe without its value (git history replayed from the cache) recovers it only when the cache
// has no fresh answer and only within the run's time; one that cannot is counted, never asked.
func TestRecoverValueAtCheckTime(t *testing.T) {
	f := newFake(t)
	c := f.checker()
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	c.Cache, c.Now = LoadCache(filepath.Join(t.TempDir(), "l.json")), func() time.Time { return now }
	c.Cache.put([]string{"cached"}, secretrisk.Liveness{State: secretrisk.Dead, CheckedAt: now})
	calls := map[string]int{}
	recov := func(name, value, keyID string) func(context.Context) (string, string, bool) {
		return func(context.Context) (string, string, bool) {
			calls[name]++
			return value, keyID, value != ""
		}
	}
	got, st := c.Check(context.Background(), []Probe{
		{Fingerprints: []string{"cached"}, Type: "github", Recover: recov("cached", "ghp_"+liveKey, "")},
		{Fingerprints: []string{"gh"}, Type: "github", Recover: recov("gh", "ghp_"+liveKey, "")},
		{Fingerprints: []string{"aws", "aws-id"}, Type: "aws-secret-key", Recover: recov("aws", "fake/secret/for/tests/only/0000000000000", keyID)},
		{Fingerprints: []string{"lost"}, Type: "github", Recover: recov("lost", "", "")},
		{Fingerprints: []string{"aws-alone"}, Type: "aws-secret-key", Recover: recov("aws-alone", "fake/secret/for/tests/only/4444444444444", "")},
		{Fingerprints: []string{"none"}, Type: "github"},
	})
	if calls["cached"] != 0 || got["cached"].State != secretrisk.Dead {
		t.Errorf("a fresh cached answer needs no value: %d recoveries, %+v", calls["cached"], got["cached"])
	}
	if got["gh"].State != secretrisk.Live || got["aws"].State != secretrisk.Live || got["aws-id"] != got["aws"] {
		t.Errorf("recovered: %+v %+v %+v", got["gh"], got["aws"], got["aws-id"])
	}
	if _, ok := got["lost"]; ok {
		t.Errorf("a value not recovered was asked: %+v", got["lost"])
	}
	if st.Recovered != 3 || st.NoValue != 2 || st.Unsupported != 1 || st.Asked != 2 || st.Cached != 1 {
		t.Errorf("stats %+v", st)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	n := 0
	_, st = c.Check(ctx, []Probe{{Fingerprints: []string{"late"}, Type: "github", Recover: func(context.Context) (string, string, bool) { n++; return "ghp_" + liveKey, "", true }}})
	if n != 0 || st.Interrupted != 1 {
		t.Errorf("out of time: %d recoveries, %+v", n, st)
	}
}
