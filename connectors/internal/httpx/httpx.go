// Package httpx is the small read-only HTTP client the provider-API connectors share, plus the
// timestamp helpers their payloads need. Standard library only.
package httpx

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

// IdleAfter is how long a credential can go unused before it is worth a look.
const IdleAfter = finding.IdleAfter

// Client issues GET requests against one API base URL with fixed headers.
type Client struct {
	BaseURL string
	Header  http.Header
	HTTP    *http.Client
}

// Base is the API base URL without a trailing slash: configured, or def when configured is empty.
func Base(configured, def string) string { return strings.TrimRight(cmp.Or(configured, def), "/") }

// New returns a client with a sane timeout. Header values are sent on every request, and they
// are the credential: a redirect to another host gets none of them.
func New(baseURL string, header http.Header) *Client {
	h := header.Clone()
	h.Set("Accept", "application/json")
	h.Set("User-Agent", "segurata")
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Header: h, HTTP: &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: keepOnSameHost(header),
	}}
}

// keepOnSameHost follows up to 10 redirects, as Go does, and drops the credential headers from any
// hop to a host (or port) other than the first request's. Go strips only Authorization and
// cookies, and keeps them on another port of the same host.
func keepOnSameHost(credential http.Header) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if req.URL.Host != via[0].URL.Host {
			for k := range credential {
				req.Header.Del(k)
			}
		}
		return nil
	}
}

// StatusError is a non-2xx answer. Message is the provider's error message, never a header value.
type StatusError struct {
	Path    string
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GET %s: HTTP %d: %s", e.Path, e.Code, e.Message)
}

// IsStatus reports whether err is a StatusError with the given HTTP code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// State is the status state of a failed call: reauth when the provider rejected the credential
// (HTTP 401), error otherwise.
func State(err error) finding.State {
	if IsStatus(err, http.StatusUnauthorized) {
		return finding.StateReauth
	}
	return finding.StateError
}

// Get fetches path (relative to BaseURL) with the query q and decodes the JSON body into out.
func (c *Client) Get(ctx context.Context, path string, q url.Values, out any) error {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header = c.Header.Clone()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// url.Error carries only the URL, which holds no credentials.
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &StatusError{Path: path, Code: resp.StatusCode, Message: ErrorMessage(body)}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("GET %s: unexpected response: %w", path, err)
	}
	return nil
}

// ErrorMessage pulls the message out of the JSON error envelope OpenAI, Anthropic and
// OpenRouter use (error.message) or Cloudflare's (errors[].message), falling back to a short
// prefix of the body.
func ErrorMessage(body []byte) string {
	type message struct {
		Message string `json:"message"`
	}
	var single struct {
		Error message `json:"error"`
	}
	if json.Unmarshal(body, &single) == nil && single.Error.Message != "" {
		return truncate(single.Error.Message)
	}
	var list struct {
		Errors []message `json:"errors"`
	}
	if json.Unmarshal(body, &list) == nil {
		var msgs []string
		for _, e := range list.Errors {
			if e.Message != "" {
				msgs = append(msgs, e.Message)
			}
		}
		if len(msgs) > 0 {
			return truncate(strings.Join(msgs, "; "))
		}
	}
	return truncate(strings.TrimSpace(string(body)))
}

// maxMessage is how many characters of a provider's error message an error keeps.
const maxMessage = 300

func truncate(s string) string { return textfmt.Truncate(s, maxMessage+1) }

// MatchesRedacted reports whether secret is the key a provider shows as redacted, a visible
// prefix and suffix around a mask ("sk-proj-****dYwA", "sk-or-v1-27e...d4d") or a hint in
// secretrisk.Redact's format. Both parts must be visible and match, and the length when the hint
// gives it; a redacted form without a mask matches nothing.
func MatchesRedacted(redacted, secret string) bool {
	h, ok := secretrisk.ReadHint(redacted)
	if !ok || h.Prefix == "" || h.Tail == "" || secret == "" || h.Len > 0 && h.Len != len(secret) {
		return false
	}
	return len(secret) >= len(h.Prefix)+len(h.Tail) && strings.HasPrefix(secret, h.Prefix) && strings.HasSuffix(secret, h.Tail)
}

// Unix converts Unix seconds to a time; 0 or nil means the provider did not say.
func Unix(sec *int64) *time.Time {
	if sec == nil || *sec == 0 {
		return nil
	}
	t := time.Unix(*sec, 0).UTC()
	return &t
}

// ParseTime reads an ISO 8601 timestamp; empty or unparseable input gives nil, never a guess.
func ParseTime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, *s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// Days is the whole number of days between t and now.
func Days(now, t time.Time) int { return int(now.Sub(t).Hours() / 24) }

// USD formats a dollar amount for titles.
func USD(v float64) string { return textfmt.USD(v) }

// Assessment accumulates why something is risky; Severity is the worst reason seen.
type Assessment struct {
	Severity finding.Severity
	Reasons  []string
}

// Raise records a reason and lifts the severity when sev is worse.
func (a *Assessment) Raise(sev finding.Severity, why string) {
	if a.Severity == "" || sev.Rank() > a.Severity.Rank() {
		a.Severity = sev
	}
	a.Reasons = append(a.Reasons, why)
}

// Done fills in an info-level reason when nothing was raised and returns the assessment.
func (a Assessment) Done(fine string) Assessment {
	if len(a.Reasons) == 0 {
		return Assessment{Severity: finding.SevInfo, Reasons: []string{fine}}
	}
	return a
}
