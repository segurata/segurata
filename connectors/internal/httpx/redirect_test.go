package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A redirect to another host must not carry the credential headers the connector passed; Go
// itself strips only Authorization and cookies, and only across domains, not ports.
func TestRedirectToAnotherHostDropsTheCredential(t *testing.T) {
	var got http.Header
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer other.Close()
	var sameHost http.Header
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, other.URL+"/landing", http.StatusFound)
		case "/moved":
			http.Redirect(w, r, "/here", http.StatusFound)
		default:
			sameHost = r.Header.Clone()
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer api.Close()

	c := New(api.URL, http.Header{"X-Api-Key": {"k"}, "Authorization": {"Bearer t"}})
	var out struct{}
	if err := c.Get(context.Background(), "/away", nil, &out); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-Api-Key") != "" || got.Get("Authorization") != "" {
		t.Fatalf("credential reached another host: %v", got)
	}
	if got.Get("User-Agent") != "segurata" || got.Get("Accept") != "application/json" {
		t.Fatalf("plain headers lost: %v", got)
	}
	if err := c.Get(context.Background(), "/moved", nil, &out); err != nil {
		t.Fatal(err)
	}
	if sameHost.Get("X-Api-Key") != "k" || sameHost.Get("Authorization") != "Bearer t" {
		t.Fatalf("a same-host redirect lost the credential: %v", sameHost)
	}
}
