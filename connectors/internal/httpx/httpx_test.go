package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

func TestErrorMessage(t *testing.T) {
	cases := map[string]string{
		`{"error":{"message":"bad key"}}`: "bad key",
		`{"success":false,"errors":[{"code":9109,"message":"Unauthorized"},{"code":1,"message":"again"}]}`: "Unauthorized; again",
		`{"error":"plain string"}`: `{"error":"plain string"}`,
		`  not json  `:             "not json",
	}
	for body, want := range cases {
		if got := ErrorMessage([]byte(body)); got != want {
			t.Errorf("%s: got %q, want %q", body, got, want)
		}
	}
}

func TestMatchesRedacted(t *testing.T) {
	for _, c := range []struct {
		redacted, secret string
		want             bool
	}{
		{"sk-proj-****dYwA", "sk-proj-abcdefdYwA", true},
		{"sk-proj-****dYwA", "sk-proj-abcdefXXXX", false},
		{"sk-or-v1-27e...d4d", "sk-or-v1-27e0123456d4d", true},
		{"sk-or-v1-27e...d4d", "sk-or-v1-28e0123456d4d", false},
		{"sk-admin-…abcd", "sk-admin-0000abcd", true},
		{"no-mask", "no-mask", false},
		{"sk-****", "sk-anything", false}, // no visible suffix
		{"sk-proj-****dYwA", "", false},
		{"sk-or-v1-27e…d4d(?)", "sk-or-v1-27e0123456d4d", true},
		{"sk-proj-…dYwA(18)", "sk-proj-abcdefdYwA", true},
		{"sk-proj-…dYwA(19)", "sk-proj-abcdefdYwA", false},
	} {
		if got := MatchesRedacted(c.redacted, c.secret); got != c.want {
			t.Errorf("MatchesRedacted(%q, %q) = %v", c.redacted, c.secret, got)
		}
	}
}

func TestState(t *testing.T) {
	for err, want := range map[error]finding.State{
		&StatusError{Code: http.StatusUnauthorized}: finding.StateReauth,
		&StatusError{Code: http.StatusForbidden}:    finding.StateError,
		errors.New("dial tcp: refused"):             finding.StateError,
	} {
		if got := State(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}

func TestBase(t *testing.T) {
	for _, c := range []struct{ configured, want string }{
		{"", "https://api.example.com"}, {"http://127.0.0.1:9/", "http://127.0.0.1:9"}, {"http://127.0.0.1:9", "http://127.0.0.1:9"},
	} {
		if got := Base(c.configured, "https://api.example.com/"); got != c.want {
			t.Errorf("Base(%q) = %q, want %q", c.configured, got, c.want)
		}
	}
}

// A failed call's error names where it went, never the credential a path or query carries
// (Telegram's /bot<token>/, a key in the query).
func TestFetchErrorHidesThePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	base := srv.URL
	srv.Close() // nothing listens: the call fails
	const token = "123456789:AAsynthetic-telegram-token-for-tests"
	_, _, err := New(base, http.Header{}).Fetch(context.Background(), http.MethodGet, "/bot"+token+"/getMe", url.Values{"key": {"synthetic-query-key"}}, nil)
	if err == nil {
		t.Fatal("a call to a closed server succeeded")
	}
	msg := err.Error()
	if strings.Contains(msg, "synthetic") || !strings.Contains(msg, "/bot<token>/getMe") || !strings.Contains(msg, strings.TrimPrefix(base, "http://")) {
		t.Errorf("error %q", msg)
	}
	if ShownPath("/v1/models") != "/v1/models" || ShownPath("/bot") != "/bot" {
		t.Error("ShownPath changed a path without a token")
	}
}

func TestGetDecodesOnlyA2xxJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(`{"name":"n"}`))
		case "/html":
			_, _ = w.Write([]byte(`<html>`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"bad key"}}`))
		}
	}))
	defer srv.Close()
	c, ctx := New(srv.URL, http.Header{}), context.Background()
	var out struct{ Name string }
	if err := c.Get(ctx, "/ok", nil, &out); err != nil || out.Name != "n" {
		t.Fatalf("Get /ok: %v %+v", err, out)
	}
	if err := c.Get(ctx, "/html", nil, &out); err == nil || !strings.Contains(err.Error(), "unexpected response") {
		t.Errorf("an unreadable body: %v", err)
	}
	err := c.Get(ctx, "/denied", nil, &out)
	if !IsStatus(err, http.StatusUnauthorized) || err.Error() != "GET /denied: HTTP 401: bad key" {
		t.Errorf("a 401: %v", err)
	}
}

func TestTimes(t *testing.T) {
	str := func(s string) *string { return &s }
	sec := func(n int64) *int64 { return &n }
	at := time.Date(2026, 11, 24, 10, 30, 0, 0, time.UTC)
	for _, in := range []string{"2026-11-24T10:30:00Z", "2026-11-24T11:30:00+01:00", "2026-11-24T10:30:00", "2026-11-24 10:30:00Z", "2026-11-24 10:30:00"} {
		if got := ParseTime(str(in)); got == nil || !got.Equal(at) || got.Location() != time.UTC {
			t.Errorf("ParseTime(%q) = %v", in, got)
		}
	}
	for _, in := range []*string{nil, str(""), str("yesterday")} {
		if got := ParseTime(in); got != nil {
			t.Errorf("ParseTime guessed %v", got)
		}
	}
	if got := Unix(sec(at.Unix())); got == nil || !got.Equal(at) {
		t.Errorf("Unix = %v", got)
	}
	if Unix(nil) != nil || Unix(sec(0)) != nil {
		t.Error("Unix of nothing")
	}
	if Days(at, at.Add(-49*time.Hour)) != 2 {
		t.Error("Days counts whole days")
	}
}

func TestAssessmentKeepsTheWorstSeverity(t *testing.T) {
	var a Assessment
	a.Raise(finding.SevMedium, "m")
	a.Raise(finding.SevLow, "l")
	if a = a.Done("fine"); a.Severity != finding.SevMedium || len(a.Reasons) != 2 {
		t.Errorf("%+v", a)
	}
	if fine := (Assessment{}).Done("fine"); fine.Severity != finding.SevInfo || fine.Reasons[0] != "fine" {
		t.Errorf("nothing raised: %+v", fine)
	}
}
