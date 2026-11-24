package httpw

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestOnlyRoutedRequestsAreSent(t *testing.T) {
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
		case "/v1/keys/moved":
			http.Redirect(w, r, "/v1/keys/elsewhere", http.StatusTemporaryRedirect)
		default:
			_, _ = w.Write([]byte(`{"deleted":true}`))
		}
	}))
	defer srv.Close()
	c := New(srv.URL+"/v1", http.Header{"Authorization": {"Bearer w"}}, Delete(`/keys/`+Seg))
	ctx := context.Background()
	if err := c.Do(ctx, http.MethodDelete, "/keys/abc_1-2"); err != nil {
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
		if err := c.Do(ctx, refused.method, refused.path); !errors.Is(err, ErrRefused) {
			t.Errorf("%s %s: want refusal, got %v", refused.method, refused.path, err)
		}
	}
	err := c.Do(ctx, http.MethodDelete, "/keys/gone")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 404 || se.Message != "no such key" || !IsStatus(err, 404) {
		t.Fatalf("status error: %v", err)
	}
	if err := c.Do(ctx, http.MethodDelete, "/keys/moved"); !IsStatus(err, http.StatusTemporaryRedirect) {
		t.Fatalf("a redirect must not be followed: %v", err)
	}
	want := []string{"DELETE /v1/keys/abc_1-2 Bearer w", "DELETE /v1/keys/gone Bearer w", "DELETE /v1/keys/moved Bearer w"}
	if len(got) != len(want) {
		t.Fatalf("sent %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sent %v, want %v", got, want)
		}
	}
}
