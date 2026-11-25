package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Go sets Referer to the previous URL before CheckRedirect runs: a credential in the path
// (Telegram's /bot<token>/) would reach the next host. No hop carries a Referer.
func TestRedirectNeverSendsTheReferer(t *testing.T) {
	const token = "123456:synthetic-telegram-token"
	var referers []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		referers = append(referers, r.Header.Get("Referer"))
		_, _ = w.Write([]byte(`{}`))
	}))
	defer other.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bot" + token + "/away":
			http.Redirect(w, r, other.URL+"/landing", http.StatusFound)
		case "/bot" + token + "/moved":
			http.Redirect(w, r, "/here", http.StatusFound)
		default:
			referers = append(referers, r.Header.Get("Referer"))
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer api.Close()

	c := New(api.URL, http.Header{})
	for _, p := range []string{"/bot" + token + "/away", "/bot" + token + "/moved"} {
		if _, _, err := c.Fetch(context.Background(), http.MethodGet, p, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if len(referers) != 2 {
		t.Fatalf("want two landings, got %v", referers)
	}
	for _, r := range referers {
		if r != "" {
			t.Fatalf("a redirect carried the Referer %q", r)
		}
	}
}

// A redirect from https to http would send the credential in cleartext: it is refused, whatever
// the host, before anything is sent.
func TestRedirectRefusesASchemeDowngrade(t *testing.T) {
	var reached bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		_, _ = w.Write([]byte(`{}`))
	}))
	defer plain.Close()
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/landing", http.StatusFound)
	}))
	defer api.Close()

	c := New(api.URL, http.Header{"Authorization": {"Bearer secret-value"}})
	c.HTTP.Transport = api.Client().Transport
	_, _, err := c.Fetch(context.Background(), http.MethodGet, "/start", nil, nil)
	if err == nil || reached {
		t.Fatalf("a downgrade to http was followed (err %v, reached %v)", err, reached)
	}
	if strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("the error carries the credential: %v", err)
	}
}
