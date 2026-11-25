package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
