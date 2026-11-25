package localsecrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/liveness"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/testcorpus"
)

// fakeProviders answers Anthropic (every key revoked), Stripe (every key works) and AWS STS (works
// for the key ids in live), and records which credentials it was asked about.
type fakeProviders struct {
	*httptest.Server
	mu    sync.Mutex
	asked []string // the credential header of every request
}

func newFakeProviders(t *testing.T, liveKeyIDs ...string) *fakeProviders {
	f := &fakeProviders{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization") + r.Header.Get("X-Api-Key")
		f.mu.Lock()
		f.asked = append(f.asked, auth)
		f.mu.Unlock()
		switch {
		case r.Header.Get("X-Api-Key") != "":
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasPrefix(auth, "AWS4-HMAC-SHA256"):
			for _, id := range liveKeyIDs {
				if strings.Contains(auth, "Credential="+id+"/") {
					_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>012345678901</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
					return
				}
			}
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`))
		default:
			_, _ = w.Write([]byte(`{"available":[]}`))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeProviders) askedAbout(s string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.asked {
		if strings.Contains(a, s) {
			return true
		}
	}
	return false
}

func (fx *fixture) livenessConnector(t *testing.T, f *fakeProviders) *Connector {
	c := fx.connector(t, fx.gitleaksReport())
	c.NewChecker = func(home string, cfg liveness.Config) *liveness.Checker {
		bases := map[string][]string{}
		for _, p := range liveness.Providers() {
			bases[p] = []string{f.URL}
		}
		return &liveness.Checker{Config: cfg, Bases: bases, Interval: time.Millisecond,
			Cache: liveness.LoadCache(filepath.Join(home, ".cache", "segurata", "liveness.json"))}
	}
	return c
}

func livenessOf(t *testing.T, rec *recorder, typ string) map[string]*secretrisk.Liveness {
	t.Helper()
	out := map[string]*secretrisk.Liveness{}
	for _, f := range rec.findings {
		ev, ok := findingEvidence(f)
		if ok && ev.Type == typ {
			out[ev.Source+":"+ev.Path] = ev.Liveness
		}
	}
	return out
}

func TestLivenessAtScanTime(t *testing.T) {
	fx := newFixture(t)
	mine := testcorpus.AWSKeyID("AKIA", 12345678901, false, 1)
	theirs := testcorpus.AWSKeyID("AKIA", 999999999999, false, 1)
	mineSecret, theirSecret := fake("", 40), fake("", 40)
	fx.secrets = append(fx.secrets, mine, theirs, mineSecret, theirSecret)
	fx.write(t, ".aws/credentials", "[default]\naws_access_key_id = "+mine+"\naws_secret_access_key = "+mineSecret+"\n", 0o600)
	fx.write(t, "src/legacy/.env", "AWS_ACCESS_KEY_ID="+theirs+"\naws_secret_access_key="+theirSecret+"\n", 0o600)

	f := newFakeProviders(t, mine)
	c := fx.livenessConnector(t, f)
	known := &attribution.Known{Owned: attribution.Owned{AWSAccounts: []string{"012345678901"}}}
	req := connector.Request{Known: known, Config: map[string]any{"liveness": map[string]any{"enabled": true, "owners": []any{"mine", "unknown"}}}}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal([]any{rec.findings, rec.statuses})
	for _, s := range fx.secrets {
		if len(s) >= 6 && strings.Contains(string(raw), s) {
			t.Fatal("a raw secret reached the output")
		}
	}
	if f.askedAbout(theirs) || f.askedAbout(theirSecret) {
		t.Error("a key attributed to someone else's AWS account was tried")
	}
	for where, l := range livenessOf(t, rec, "stripe-live") {
		if l == nil || l.State != secretrisk.Live || l.Provider != "stripe" {
			t.Errorf("stripe key at %s: %+v", where, l)
		}
	}
	if n := len(livenessOf(t, rec, "stripe-live")); n != 2 {
		t.Errorf("the stripe key's working copy and its git history both carry the result: %d", n)
	}
	for where, l := range livenessOf(t, rec, "anthropic") {
		if l == nil || l.State != secretrisk.Dead {
			t.Errorf("revoked anthropic key at %s: %+v", where, l)
		}
	}
	for _, typ := range []string{"aws-secret-key", "aws-access-key-id"} {
		for where, l := range livenessOf(t, rec, typ) {
			switch {
			case strings.Contains(where, "legacy"):
				if l != nil {
					t.Errorf("%s at %s, not-mine, has a result: %+v", typ, where, l)
				}
			case l == nil || l.State != secretrisk.Live || l.Account != "aws:012345678901":
				t.Errorf("%s at %s: %+v", typ, where, l)
			}
		}
	}
	detail := rec.statuses[0].Detail
	if !strings.Contains(detail, "liveness: 3 asked, 0 from cache; 2 live, 1 dead") || !strings.Contains(detail, "1 not allowed") {
		t.Errorf("status detail: %s", detail)
	}

	// A second run finds everything in the cache and asks nothing.
	before := len(f.asked)
	rec2 := &recorder{}
	if err := c.Inventory(context.Background(), req, rec2); err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != before || !strings.Contains(rec2.statuses[0].Detail, "0 asked, 3 from cache") {
		t.Errorf("second run asked %d more; %s", len(f.asked)-before, rec2.statuses[0].Detail)
	}
}

func TestLivenessGates(t *testing.T) {
	cases := []struct {
		name   string
		known  *attribution.Known
		config any
		detail string
	}{
		{"off by default", &attribution.Known{}, nil, ""},
		{"off", &attribution.Known{}, map[string]any{"enabled": false}, ""},
		{"no attribution lent", nil, map[string]any{"enabled": true, "owners": []any{"unknown"}}, "liveness: not run"},
		{"mine only: the unknown keys stay untried", &attribution.Known{}, map[string]any{"enabled": true}, "0 asked"},
		{"provider allowlist", &attribution.Known{}, map[string]any{"enabled": true, "owners": []any{"unknown"}, "providers": []any{"github"}}, "0 asked"},
	}
	for _, tc := range cases {
		fx := newFixture(t)
		f := newFakeProviders(t)
		c := fx.livenessConnector(t, f)
		req := connector.Request{Known: tc.known}
		if tc.config != nil {
			req.Config = map[string]any{"liveness": tc.config}
		}
		rec := &recorder{}
		if err := c.Inventory(context.Background(), req, rec); err != nil {
			t.Fatal(err)
		}
		if len(f.asked) != 0 {
			t.Errorf("%s: asked %d times", tc.name, len(f.asked))
		}
		detail := rec.statuses[0].Detail
		if tc.detail == "" && strings.Contains(detail, "liveness") || tc.detail != "" && !strings.Contains(detail, tc.detail) {
			t.Errorf("%s: %s", tc.name, detail)
		}
	}
	if _, err := parseSettings(map[string]any{"liveness": map[string]any{"enabled": true, "owners": []any{"not-mine"}}}, "/h"); err == nil {
		t.Error("liveness for not-mine accepted")
	}
}
