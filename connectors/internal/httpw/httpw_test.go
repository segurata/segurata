package httpw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
)

// newServer records every request it gets and answers by path.
func newServer(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/keys/gone":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"message":"no such key"}}`))
		case "/v1/keys/readonly":
			w.WriteHeader(http.StatusForbidden)
		case "/v1/keys/moved":
			http.Redirect(w, r, "/v1/keys/elsewhere", http.StatusTemporaryRedirect)
		default:
			_, _ = w.Write([]byte(`{"deleted":true}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

func TestOnlyRoutedRequestsAreSent(t *testing.T) {
	srv, sent := newServer(t)
	c := newClient(srv.URL+"/v1", http.Header{"Authorization": {"Bearer w"}}, Delete(`/keys/`+Seg))
	ctx := context.Background()
	if err := c.do(ctx, http.MethodDelete, "/keys/abc_1-2"); err != nil {
		t.Fatal(err)
	}
	for _, refused := range []struct{ method, path string }{
		{http.MethodGet, "/keys/abc"},
		{http.MethodPost, "/keys/abc"},
		{http.MethodDelete, "/keys"},
		{http.MethodDelete, "/keys/abc/extra"},
		{http.MethodDelete, "/keys/../workspaces/w"},
		{http.MethodDelete, "/keys/a%2F..%2Fb"},
		{http.MethodDelete, "/keys/abc?force=1"},
		{http.MethodDelete, "/workspaces/abc"},
	} {
		if err := c.do(ctx, refused.method, refused.path); !errors.Is(err, errRefused) {
			t.Errorf("%s %s: want refusal, got %v", refused.method, refused.path, err)
		}
	}
	err := c.do(ctx, http.MethodDelete, "/keys/gone")
	var se *httpx.StatusError
	if !errors.As(err, &se) || se.Code != 404 || se.Message != "no such key" || err.Error() != "DELETE /keys/gone: HTTP 404: no such key" {
		t.Fatalf("status error: %v", err)
	}
	if err := c.do(ctx, http.MethodDelete, "/keys/moved"); !httpx.IsStatus(err, http.StatusTemporaryRedirect) {
		t.Fatalf("a redirect must not be followed: %v", err)
	}
	want := []string{"DELETE /v1/keys/abc_1-2 Bearer w", "DELETE /v1/keys/gone Bearer w", "DELETE /v1/keys/moved Bearer w"}
	if got := sent(); !slices.Equal(got, want) {
		t.Fatalf("sent %v, want %v", got, want)
	}
}

func TestSendStopsAtTheFirstFailure(t *testing.T) {
	srv, sent := newServer(t)
	base := srv.URL + "/v1"
	header := http.Header{"Authorization": {"Bearer w"}}
	call := func(id string) connector.Call {
		return connector.Call{Method: http.MethodDelete, URL: base + "/keys/" + id, Secret: "the write key"}
	}
	ctx := context.Background()
	if err := Send(ctx, base, header, []connector.Call{call("a"), call("b")}, Delete(`/keys/`+Seg)); err != nil {
		t.Fatal(err)
	}
	err := Send(ctx, base, header, []connector.Call{call("readonly"), call("c")}, Delete(`/keys/`+Seg))
	if !httpx.IsStatus(err, http.StatusForbidden) || !strings.Contains(err.Error(), "the write key was refused, probably because it is read-only") {
		t.Fatalf("a refused credential is named: %v", err)
	}
	if err := Send(ctx, base, header, []connector.Call{{Method: http.MethodDelete, URL: "https://elsewhere.example/v1/keys/d"}}, Delete(`/keys/`+Seg)); !errors.Is(err, errRefused) {
		t.Fatalf("a call outside the base: %v", err)
	}
	want := []string{"DELETE /v1/keys/a Bearer w", "DELETE /v1/keys/b Bearer w", "DELETE /v1/keys/readonly Bearer w"}
	if got := sent(); !slices.Equal(got, want) {
		t.Fatalf("sent %v, want %v", got, want)
	}
}
