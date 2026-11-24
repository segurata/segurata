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
	Scopes   []Scope
	Logs     []string
}

// Scope is one Emitter.Scope call.
type Scope struct {
	ID        string
	Inspected bool
	Reason    string
}

func (r *Recorder) Scope(id string, inspected bool, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Scopes = append(r.Scopes, Scope{ID: id, Inspected: inspected, Reason: reason})
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
//
// A remediation test sets DeleteAuth: DELETE requests carrying exactly those headers are recorded
// in Deleted and answered 200 (or DeleteStatus[path]); any other DELETE gets 403, as a read-only
// key would. Without DeleteAuth only GET is allowed, which is what every inventory test asserts.
type Server struct {
	*httptest.Server
	mu           sync.Mutex
	Misses       []string
	Hits         map[string]int
	DeleteAuth   http.Header
	DeleteStatus map[string]int
	Deleted      []string
}

func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.DeleteAuth {
		if r.Header.Get(k) != s.DeleteAuth.Get(k) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"message":"this key is read-only"}}`))
			return
		}
	}
	s.Deleted = append(s.Deleted, r.URL.Path)
	code := http.StatusOK
	if c, ok := s.DeleteStatus[r.URL.Path]; ok {
		code = c
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"deleted":true}`))
}

func NewServer(t *testing.T, want http.Header, routes map[string]Route) *Server {
	t.Helper()
	s := &Server{Hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && s.DeleteAuth != nil {
			s.delete(w, r)
			return
		}
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
