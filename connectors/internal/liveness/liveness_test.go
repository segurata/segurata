package liveness

import (
	"context"
	"encoding/json"
	"io"
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
	// disabledKey is a key the provider still recognises but reports disabled or expired.
	disabledKey = "DISABLED-fake-key-for-tests-only-dddd"
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
	switch {
	case r.Method == http.MethodGet:
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth.test" && r.ContentLength <= 0:
	case r.Method == http.MethodPost && r.URL.Path == "/graphql":
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"query":"{ viewer { id } }"}` || r.Header.Get("Content-Type") != "application/json" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			reply(http.StatusBadRequest, `{}`)
			return
		}
	default:
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
	if !live {
		// The documented invalid-key answers (docs/architecture.md, "Liveness").
		switch {
		case r.Header.Get("X-Api-Key") != "":
			reply(http.StatusUnauthorized, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		case r.URL.Path == "/api/v1/key":
			reply(http.StatusUnauthorized, `{"error":{"code":401,"message":"User not found."}}`)
			return
		case r.URL.Path == "/v1/balance":
			reply(http.StatusUnauthorized, `{"error":{"code":"api_key_expired","type":"invalid_request_error","message":"Expired API Key provided: `+cred+`"}}`)
			return
		}
	}
	switch r.URL.Path {
	case "/v1/api-key": // xAI: a disabled key still answers 200
		switch {
		case live:
			reply(http.StatusOK, `{"team_id":"team-1","api_key_blocked":false,"api_key_disabled":false,"team_blocked":false}`)
		case strings.HasSuffix(cred, disabledKey):
			reply(http.StatusOK, `{"team_id":"team-1","api_key_blocked":false,"api_key_disabled":true,"team_blocked":false}`)
		default:
			reply(http.StatusUnauthorized, `{"code":"Unauthenticated","error":"No authorization header or an invalid authorization token was provided"}`)
		}
	case "/v1/users/me": // Notion
		switch {
		case r.Header.Get("Notion-Version") == "":
			reply(http.StatusBadRequest, `{}`)
		case live:
			reply(http.StatusOK, `{"type":"bot","bot":{"workspace_id":"ws-1","workspace_name":"Mine"}}`)
		default:
			reply(http.StatusUnauthorized, `{"object":"error","status":401,"code":"unauthorized","message":"API token is invalid."}`)
		}
	case "/client/v4/user/tokens/verify": // Cloudflare: an account token fails here too
		switch {
		case live:
			reply(http.StatusOK, `{"success":true,"result":{"id":"t1","status":"active"}}`)
		case strings.HasSuffix(cred, disabledKey):
			reply(http.StatusOK, `{"success":true,"result":{"id":"t1","status":"expired"}}`)
		default:
			reply(http.StatusUnauthorized, `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`)
		}
	case "/v2/account": // DigitalOcean
		if live {
			reply(http.StatusOK, `{"account":{"uuid":"do-uuid-1","status":"active"}}`)
		} else {
			reply(http.StatusUnauthorized, `{"id":"unauthorized","message":"Unable to authenticate you."}`)
		}
	case "/graphql": // Linear
		if live {
			reply(http.StatusOK, `{"data":{"viewer":{"id":"lin-user-1"}}}`)
		} else {
			reply(http.StatusBadRequest, `{"errors":[{"message":"Authentication required, not authenticated","extensions":{"code":"AUTHENTICATION_ERROR"}}]}`)
		}
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
	return mineOnly(&Checker{Bases: bases, Interval: time.Millisecond})
}

// mineOnly lets c try every probe: each fingerprint attributed mine, mine allowed.
func mineOnly(c *Checker) *Checker {
	c.Config.Enabled, c.Config.Owners = true, []attribution.Owner{attribution.Mine}
	c.Attribution = func(string) (attribution.Owner, bool) { return attribution.Mine, true }
	return c
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
		// Dead only where the provider documents a body signal for an invalid key; a bare 401 (or
		// one whose cause the provider lists as several things) is unknown.
		{"openai-project", "sk-proj-", "", secretrisk.Unknown, "HTTP 200"},
		{"openai-service", "sk-admin-", "", secretrisk.Unknown, "HTTP 200"},
		{"anthropic", "sk-ant-api03-", "", secretrisk.Dead, "HTTP 200"},
		{"anthropic", "sk-ant-admin01-", "", secretrisk.Dead, "HTTP 200"},
		{"openrouter", "sk-or-v1-", "", secretrisk.Dead, "HTTP 200"},
		{"github", "ghp_", "github:octocat", secretrisk.Unknown, "HTTP 200"},
		{"github-pat", "github_pat_", "github:octocat", secretrisk.Unknown, "HTTP 200"},
		{"gitlab", "glpat-", "gitlab:gitlab-me", secretrisk.Unknown, "HTTP 200"},
		{"google-api-key", "AIza", "", secretrisk.Dead, "SERVICE_DISABLED"},
		{"slack-token", "xoxb-", "slack:T0FAKE", secretrisk.Dead, "ok"},
		{"stripe-live", "sk_live_", "", secretrisk.Dead, "HTTP 200"},
		{"stripe-test", "rk_test_", "", secretrisk.Dead, "HTTP 200"},
		{"sendgrid", "SG.", "", secretrisk.Unknown, "HTTP 200"},
		{"telegram-bot", "123456789:AA", "telegram:@fake_bot", secretrisk.Unknown, "HTTP 200"},
		{"huggingface", "hf_", "huggingface:hf-me", secretrisk.Unknown, "HTTP 200"},
		{"npm-token", "npm_", "npm:npm-me", secretrisk.Unknown, "HTTP 200"},
		{"xai", "xai-", "", secretrisk.Unknown, "HTTP 200"},
		{"groq", "gsk_", "", secretrisk.Unknown, "HTTP 200"},
		{"notion", "ntn_", "notion:ws-1", secretrisk.Dead, "HTTP 200"},
		{"cloudflare-token", "", "", secretrisk.Unknown, "active"},
		{"digitalocean", "dop_v1_", "digitalocean:do-uuid-1", secretrisk.Dead, "HTTP 200"},
		{"sentry-token", "sntryu_", "", secretrisk.Unknown, "HTTP 200"},
		{"linear", "lin_api_", "linear:lin-user-1", secretrisk.Unknown, "HTTP 200"},
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
		if m != http.MethodGet && f.paths[i] != "/api/auth.test" && f.paths[i] != "/graphql" {
			t.Errorf("sent %s %s: only GET is allowed, POST without a body to Slack's auth.test and a query to Linear's GraphQL", m, f.paths[i])
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
	c := mineOnly(&Checker{Bases: map[string][]string{"openai": {srv.URL}, "openrouter": {srv.URL}}, Interval: time.Millisecond})
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
	c.Bases["stripe"] = []string{global.URL, eu.URL}
	got, _ := c.Check(context.Background(), []Probe{{Fingerprints: []string{"d"}, Type: "stripe-live", Value: deadKey}})
	if got["d"].State != secretrisk.Dead || len(eu.paths) != 1 {
		t.Errorf("a key both hosts reject: %+v, EU asked %d times", got["d"], len(eu.paths))
	}
	euOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"scopes":[]}`)) }))
	defer euOnly.Close()
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer flaky.Close()
	for _, bases := range [][]string{{global.URL, euOnly.URL}, {flaky.URL, euOnly.URL}} {
		c.Bases["stripe"] = bases
		got, _ = c.Check(context.Background(), []Probe{{Fingerprints: []string{"e"}, Type: "stripe-live", Value: deadKey}})
		if got["e"].State != secretrisk.Live {
			t.Errorf("a key the second host accepts: %+v", got["e"])
		}
	}
	for _, bases := range [][]string{{global.URL, flaky.URL}, {flaky.URL, global.URL}} {
		c.Bases["stripe"] = bases
		got, _ = c.Check(context.Background(), []Probe{{Fingerprints: []string{"u"}, Type: "stripe-live", Value: deadKey}})
		if got["u"].State != secretrisk.Unknown {
			t.Errorf("one host dead, one without an answer: %+v", got["u"])
		}
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
	// The global STS endpoint also rejects keys of the GovCloud and China partitions this way.
	if r := got["gone"]; r.State != secretrisk.Unknown || r.Reason != "InvalidClientTokenId" {
		t.Errorf("a key id STS does not know: %+v", r)
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
		{Fingerprints: []string{"c"}, Type: "aws-access-key-id", Value: keyID}, // a lookup, not in the allowlist
		{Fingerprints: []string{"f"}, Type: "aws-secret-key", Value: liveKey},  // not in the allowlist (and without its key id)
		{Fingerprints: []string{"d"}, Type: "openai-project", Value: liveKey},  // not in the allowlist
		{Fingerprints: []string{"e"}, Type: "github", Value: "ghp_" + liveKey}, // allowed
	})
	c.Config.Providers = nil // allowed, but unsupported without its key id
	_, st2 := c.Check(context.Background(), []Probe{{Fingerprints: []string{"g"}, Type: "aws-secret-key", Value: liveKey}})
	st.Unsupported += st2.Unsupported
	if st.Unsupported != 3 || st.NotAllowed != 3 || st.Asked != 1 || len(got) != 1 {
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
		{Fingerprints: []string{"dead"}, Type: "anthropic", Value: deadKey},
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
	if err != nil || !c.Enabled || !c.Allows(attribution.Unknown, "github") || c.Allows(attribution.NotMine, "github") || !c.allowsProvider("aws") || c.allowsProvider("openai") {
		t.Errorf("full: %+v %v", c, err)
	}
	for _, bad := range []any{
		"yes",
		map[string]any{"enabled": "true"},
		map[string]any{"owners": []any{"not-mine"}},
		map[string]any{"owners": []any{"mine", "not-mine"}},
		map[string]any{"owners": "mine"},
		map[string]any{"aws_profiles": "prod"},
		map[string]any{"ssh_hosts": []any{"-oProxyCommand=sh"}},
		map[string]any{"ssh_hosts": []any{"host with space"}},
		map[string]any{"providers": []any{"twilio"}},
	} {
		if _, err := ParseConfig(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSupported(t *testing.T) {
	for _, typ := range []string{"github", "aws-secret-key", "google-api-key", "slack-token", "aws-access-key-id", "private-key", "ssh-key"} {
		if !Supported(typ) {
			t.Errorf("%s unsupported", typ)
		}
	}
	for _, typ := range []string{"slack-webhook", "npm-authtoken", "jwt"} {
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
	c := mineOnly(&Checker{Bases: map[string][]string{"github": {srv.URL}}, Interval: time.Millisecond})
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
	// Recover runs on each provider's goroutine, so providers recover concurrently.
	var mu sync.Mutex
	calls := map[string]int{}
	recov := func(name, value, keyID string) func(context.Context) (string, string, bool) {
		return func(context.Context) (string, string, bool) {
			mu.Lock()
			defer mu.Unlock()
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

// A key the provider recognises but reports disabled or expired is dead: xAI's flags, Cloudflare's
// token status.
func TestDisabledOrExpiredIsDead(t *testing.T) {
	f := newFake(t)
	got, _ := f.checker().Check(context.Background(), []Probe{
		{Fingerprints: []string{"x"}, Type: "xai", Value: "xai-" + disabledKey},
		{Fingerprints: []string{"c"}, Type: "cloudflare-token", Value: disabledKey},
	})
	if got["x"].State != secretrisk.Dead || got["x"].Reason != "api_key_disabled" {
		t.Errorf("xAI disabled key: %+v", got["x"])
	}
	if got["c"].State != secretrisk.Dead || got["c"].Reason != "token expired" {
		t.Errorf("Cloudflare expired token: %+v", got["c"])
	}
}

// A status alone never says dead: every provider answering 401 (or Slack's ok:false) without its
// documented invalid-key signal is unknown, and the item it would have closed stays open.
func TestBareStatusIsNeverDead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/auth.test":
			_, _ = w.Write([]byte(`{"ok":false,"error":"not_authed"}`))
		case r.URL.Path == "/client/v4/user/tokens/verify":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"result":{"status":"expired"}}`))
		case r.URL.Path == "/v1beta/models":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID"}]}}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"Bad credentials","error":{"code":"other","type":"other"},"code":"other","id":"other"}`))
		}
	}))
	defer srv.Close()
	bases := map[string][]string{}
	for _, p := range providers {
		bases[p.name] = []string{srv.URL}
	}
	c := mineOnly(&Checker{Bases: bases, Interval: time.Millisecond})
	var probes []Probe
	for _, p := range providers {
		probes = append(probes, Probe{Fingerprints: []string{p.name}, Type: p.types[0], Value: liveKey, KeyID: keyID})
	}
	got, st := c.Check(context.Background(), probes)
	for _, p := range providers {
		if r := got[p.name]; r.State != secretrisk.Unknown {
			t.Errorf("%s: a bare 401 judged %+v", p.name, r)
		}
	}
	if st.Dead != 0 || st.Asked != len(providers) {
		t.Errorf("stats %+v", st)
	}
}

// Every result says which verdict rules judged it, so a tracker can drop a dead verdict of older,
// looser rules.
func TestResultsCarryTheRules(t *testing.T) {
	f := newFake(t)
	got, _ := f.checker().Check(context.Background(), []Probe{
		{Fingerprints: []string{"a"}, Type: "anthropic", Value: deadKey},
		{Fingerprints: []string{"b"}, Type: "github", Value: flakyKey},
	})
	for fp, r := range got {
		if r.Rules != secretrisk.LivenessRules {
			t.Errorf("%s: rules %d, want %d", fp, r.Rules, secretrisk.LivenessRules)
		}
	}
}

// A cache written under older verdict rules is discarded: its dead results may be a bare 401.
func TestOlderCacheIsDiscarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "liveness.json")
	old := `{"version":1,"results":{"x":{"state":"dead","checked_at":"2026-11-25T00:00:00Z","provider":"github","reason":"HTTP 401"}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 25, 1, 0, 0, 0, time.UTC)
	if _, ok := LoadCache(path).fresh([]string{"x"}, now); ok {
		t.Error("a dead result of the old rules answered from the cache")
	}
}

// The owner and provider gates apply to every fingerprint of a probe, inside Check, before the
// cache and before a value is recovered: a pair whose key id is someone else's is never sent, nor
// answered from the cache; a lookup (it sends nothing) runs for unknown whatever owners says, never
// for not-mine; a fingerprint with no attribution is refused.
func TestGatesEveryFingerprint(t *testing.T) {
	f := newFake(t)
	c := f.checker()
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	c.Cache, c.Now = LoadCache(filepath.Join(t.TempDir(), "l.json")), func() time.Time { return now }
	owners := map[string]attribution.Owner{"mine": attribution.Mine, "mine-id": attribution.Mine, "their-id": attribution.NotMine,
		"cached-theirs": attribution.NotMine, "unknown-id": attribution.Unknown, "their-lone-id": attribution.NotMine, "cached-openai": attribution.Mine}
	c.Attribution = func(fp string) (attribution.Owner, bool) { o, ok := owners[fp]; return o, ok }
	c.Config.Providers = []string{"aws", "aws-keys", "github"}
	c.Cache.put([]string{"cached-theirs"}, secretrisk.Liveness{State: secretrisk.Live, CheckedAt: now, Account: "github:them"})
	c.Cache.put([]string{"cached-openai"}, secretrisk.Liveness{State: secretrisk.Live, CheckedAt: now})
	const theirSecret = "fake/secret/for/tests/only/9999999999999"
	recovered := false
	got, st := c.Check(context.Background(), []Probe{
		{Fingerprints: []string{"mine", "their-id"}, Type: "aws-secret-key", Value: theirSecret, KeyID: keyID},
		{Fingerprints: []string{"mine", "unattributed"}, Type: "aws-secret-key", Recover: func(context.Context) (string, string, bool) {
			recovered = true
			return theirSecret, keyID, true
		}},
		{Fingerprints: []string{"cached-theirs"}, Type: "github", Value: "ghp_" + liveKey},
		{Fingerprints: []string{"cached-openai"}, Type: "openai-project", Value: liveKey},
		{Fingerprints: []string{"their-lone-id"}, Type: "aws-access-key-id", Value: keyID},
		{Fingerprints: []string{"unknown-id"}, Type: "aws-access-key-id", Value: keyID},
	})
	if len(f.paths) != 0 || recovered {
		t.Errorf("someone else's key was sent (%v) or recovered (%v)", f.paths, recovered)
	}
	for _, fp := range []string{"mine", "their-id", "unattributed", "cached-theirs", "cached-openai", "their-lone-id"} {
		if r, ok := got[fp]; ok {
			t.Errorf("%s has a result: %+v", fp, r)
		}
	}
	if _, ok := got["unknown-id"]; !ok {
		t.Error("a lookup for an unknown key id did not run")
	}
	if st.NotAllowed != 5 || st.Cached != 0 || st.Recovered != 0 {
		t.Errorf("stats %+v", st)
	}
	noLeak(t, got, st, theirSecret, liveKey)
	if c.Attribution = nil; true {
		got, st = c.Check(context.Background(), []Probe{{Fingerprints: []string{"mine"}, Type: "github", Value: "ghp_" + liveKey}})
		if len(got) != 0 || st.NotAllowed != 1 || len(f.paths) != 0 {
			t.Errorf("a checker without attribution tried a key: %+v %+v", got, st)
		}
	}
}

// A result dated after now (a clock that jumped forward) is never fresh: its age would be
// negative, and it would stand for any later check.
func TestFutureResultIsNotFresh(t *testing.T) {
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	c := LoadCache(filepath.Join(t.TempDir(), "l.json"))
	c.put([]string{"x"}, secretrisk.Liveness{State: secretrisk.Dead, CheckedAt: now.Add(time.Hour)})
	if _, ok := c.fresh([]string{"x"}, now); ok {
		t.Error("a result from the future answered")
	}
}

// Every provider's body may echo the key in any field segurata reads: an error code, a reason, a
// status, an account. No part of the key reaches a result, whatever the answer's status, and a
// long or odd provider string is not kept either.
func TestProviderTextNeverHoldsTheKey(t *testing.T) {
	const key = "ECHO0key0for0tests0only0ZZZZ" // the characters a provider code may have
	echo := func(v string) string {
		return `{"login":"` + v + `","username":"` + v + `","name":"` + v + `","team_id":"` + v + `","ok":true,"error":"` + v +
			`","id":"` + v + `","code":"` + v + `","type":"` + v + `","account":{"uuid":"` + v + `"},"bot":{"workspace_id":"` + v +
			`"},"data":{"viewer":{"id":"` + v + `"}},"result":{"username":"` + v + `","status":"` + v + `"},"api_key_disabled":false,` +
			`"errors":[{"extensions":{"code":"` + v + `"}}],"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"` + v + `"}]}`
	}
	for _, code := range []int{http.StatusOK, http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden} {
		for _, v := range []string{key, strings.Repeat("A", 200), "a b<c>"} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4") {
					w.WriteHeader(code)
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>` + v + `</Code></Error><Account>` + v + `</Account></ErrorResponse>`))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_, _ = w.Write([]byte(echo(v)))
			}))
			bases := map[string][]string{}
			for _, p := range providers {
				bases[p.name] = []string{srv.URL}
			}
			c := mineOnly(&Checker{Bases: bases, Interval: time.Millisecond})
			var probes []Probe
			for _, p := range providers {
				if p.lookup == nil {
					probes = append(probes, Probe{Fingerprints: []string{p.name}, Type: p.types[0], Value: key, KeyID: keyID})
				}
			}
			got, st := c.Check(context.Background(), probes)
			srv.Close()
			noLeak(t, got, st, key)
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), strings.Repeat("A", 65)) || strings.Contains(string(raw), "a b<c>") {
				t.Errorf("HTTP %d: provider text kept: %s", code, raw)
			}
		}
	}
}
