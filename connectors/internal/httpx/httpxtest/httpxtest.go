// Package httpxtest holds the fakes the provider-API connector tests share: a recording emitter
// and an httptest server that checks credentials and refuses anything but GET.
package httpxtest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

// Recorder is a connector.Emitter that keeps everything it is given.
type Recorder struct {
	mu       sync.Mutex
	Findings []finding.Finding
	Statuses []finding.Status
	Logs     []string
}

func (r *Recorder) Finding(f finding.Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
}

func (r *Recorder) Status(s finding.Status) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Statuses = append(r.Statuses, s)
}

func (r *Recorder) Log(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Logs = append(r.Logs, msg)
}

// ByResource returns the finding for a resource id, failing the test when there is none.
func (r *Recorder) ByResource(t *testing.T, typ, id string) finding.Finding {
	t.Helper()
	for _, f := range r.Findings {
		if f.Resource.Type == typ && f.Resource.ID == id {
			return f
		}
	}
	t.Fatalf("no finding for %s %s; have %d findings", typ, id, len(r.Findings))
	return finding.Finding{}
}

// AssertNoSecret fails when the secret shows up in any record the connector emitted.
func (r *Recorder) AssertNoSecret(t *testing.T, secret string) {
	t.Helper()
	raw, _ := json.Marshal([]any{r.Findings, r.Statuses, r.Logs})
	if strings.Contains(string(raw), secret) {
		t.Fatal("secret value leaked into emitted records")
	}
}

// Route answers one path. It returns the HTTP status and a value to encode as JSON.
type Route func(q url.Values) (int, any)

// Server serves routes keyed by path, after checking every header in want on every request.
// Unknown paths get 404 and are recorded in Misses so tests can assert full coverage; Hits
// counts requests per path.
type Server struct {
	*httptest.Server
	mu     sync.Mutex
	Misses []string
	Hits   map[string]int
}

func NewServer(t *testing.T, want http.Header, routes map[string]Route) *Server {
	t.Helper()
	s := &Server{Hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("connector sent %s %s; only GET is allowed", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		for k := range want {
			if r.Header.Get(k) != want.Get(k) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"message":"missing or wrong ` + k + `"}}`))
				return
			}
		}
		s.mu.Lock()
		s.Hits[r.URL.Path]++
		route, ok := routes[r.URL.Path]
		if !ok {
			s.Misses = append(s.Misses, r.URL.Path)
		}
		s.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"message":"not found"}}`))
			return
		}
		code, body := route(r.URL.Query())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(s.Close)
	return s
}

// Static answers with a fixed body and 200.
func Static(body any) Route { return func(url.Values) (int, any) { return http.StatusOK, body } }

// Fail answers with an error status and the common error envelope.
func Fail(code int, msg string) Route {
	return func(url.Values) (int, any) {
		return code, map[string]any{"error": map[string]any{"message": msg}}
	}
}
