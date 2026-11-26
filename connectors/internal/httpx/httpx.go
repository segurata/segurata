// Package httpx is the read-only HTTP client the provider-API connectors share, with the helpers
// their payloads need.
package httpx

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/textfmt"
)

type Client struct {
	BaseURL string
	Header  http.Header
	HTTP    *http.Client
}

// Base is configured, or def when it is empty, without a trailing slash.
func Base(configured, def string) string { return strings.TrimRight(cmp.Or(configured, def), "/") }

// New returns a client that sends header, the credential, on every request but a redirect to
// another host.
func New(baseURL string, header http.Header) *Client {
	h := header.Clone()
	h.Set("Accept", "application/json")
	h.Set("User-Agent", "segurata")
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Header: h, HTTP: &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: keepOnSameHost(header),
	}}
}

// keepOnSameHost drops every credential header on a hop to another host or port: Go strips only
// Authorization and cookies, and keeps them on another port. No hop carries a Referer, which Go
// sets to the previous URL and a credential can ride in (Telegram's /bot<token>/). Downgrades
// from https are refused.
func keepOnSameHost(credential http.Header) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("refused a redirect from https to " + req.URL.Scheme)
		}
		req.Header.Del("Referer")
		if req.URL.Host != via[0].URL.Host {
			for k := range credential {
				req.Header.Del(k)
			}
		}
		return nil
	}
}

// NoRedirect is a CheckRedirect that follows none: the answer is the 3xx itself.
func NoRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// StatusError is a non-2xx answer. Message is the provider's error message, never a header value.
type StatusError struct {
	Method  string // "" for GET
	Path    string
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", cmp.Or(e.Method, http.MethodGet), e.Path, e.Code, e.Message)
}

func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// State is the status state of a failed call: reauth on a rejected credential (401).
func State(err error) finding.State {
	if IsStatus(err, http.StatusUnauthorized) {
		return finding.StateReauth
	}
	return finding.StateError
}

// Get decodes the JSON body of a 2xx answer into out.
func (c *Client) Get(ctx context.Context, path string, q url.Values, out any) error {
	code, body, err := c.Fetch(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	if code < 200 || code > 299 {
		return &StatusError{Path: path, Code: code, Message: ErrorMessage(body)}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("GET %s: unexpected response: %w", path, err)
	}
	return nil
}

// Fetch returns the status and body whatever the status, for callers that judge the answer. method
// is GET, or POST for a read-only call an API documents only as POST (Slack's auth.test, GraphQL).
func (c *Client) Fetch(ctx context.Context, method, path string, q url.Values, body []byte) (int, []byte, error) {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header = c.Header.Clone()
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// url.Error carries the URL, and a credential may ride in its path or query.
		var ue *url.Error
		if errors.As(err, &ue) {
			p, _, _ := strings.Cut(path, "?")
			ue.URL = req.URL.Scheme + "://" + req.URL.Host + ShownPath(p)
		}
		return 0, nil, err
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, answer, nil
}

// ErrorMessage is the message of an error.message (OpenAI, Anthropic, OpenRouter) or
// errors[].message (Cloudflare) envelope, else a short prefix of the body.
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

const maxMessage = 300

func truncate(s string) string { return textfmt.Truncate(s, maxMessage+1) }

// MatchesRedacted reports whether secret is the key a provider shows masked ("sk-proj-****dYwA")
// or a hint in Redact's format describes. Prefix and tail must both be visible.
func MatchesRedacted(redacted, secret string) bool {
	h, ok := secretrisk.ReadHint(redacted)
	if !ok || h.Prefix == "" || h.Tail == "" || secret == "" || h.Len > 0 && h.Len != len(secret) {
		return false
	}
	return len(secret) >= len(h.Prefix)+len(h.Tail) && strings.HasPrefix(secret, h.Prefix) && strings.HasSuffix(secret, h.Tail)
}

// Unix is nil for 0 or nil: the provider did not say.
func Unix(sec *int64) *time.Time {
	if sec == nil || *sec == 0 {
		return nil
	}
	t := time.Unix(*sec, 0).UTC()
	return &t
}

// ParseTime reads an ISO 8601 timestamp; nil, never a guess, for anything else.
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

// CursorList reads every page of a {data, has_more, last_id} listing, limit items a page, sending
// the last id seen as afterParam. A cursor that does not move ends the listing.
func CursorList[T any](ctx context.Context, api *Client, path string, q url.Values, limit int, afterParam string) ([]T, error) {
	var out []T
	after := ""
	for range 10000 {
		qq := url.Values{"limit": {strconv.Itoa(limit)}}
		for k, v := range q {
			qq[k] = v
		}
		if after != "" {
			qq.Set(afterParam, after)
		}
		var p struct {
			Data    []T     `json:"data"`
			HasMore bool    `json:"has_more"`
			LastID  *string `json:"last_id"`
		}
		if err := api.Get(ctx, path, qq, &p); err != nil {
			return out, err
		}
		out = append(out, p.Data...)
		if !p.HasMore || p.LastID == nil || *p.LastID == "" || *p.LastID == after {
			return out, nil
		}
		after = *p.LastID
	}
	return out, fmt.Errorf("GET %s: pagination did not end", path)
}

func Days(now, t time.Time) int { return int(now.Sub(t).Hours() / 24) }

// Assessment accumulates why something is risky; Severity is the worst reason's.
type Assessment struct {
	Severity finding.Severity
	Reasons  []string
}

func (a *Assessment) Raise(sev finding.Severity, why string) {
	if a.Severity == "" || sev.Rank() > a.Severity.Rank() {
		a.Severity = sev
	}
	a.Reasons = append(a.Reasons, why)
}

// Done is an info-level assessment with reason fine when nothing was raised.
func (a Assessment) Done(fine string) Assessment {
	if len(a.Reasons) == 0 {
		return Assessment{Severity: finding.SevInfo, Reasons: []string{fine}}
	}
	return a
}

// ShownPath replaces a token in the path (Telegram's /bot<token>/) by a placeholder.
func ShownPath(path string) string {
	if rest, ok := strings.CutPrefix(path, "/bot"); ok {
		if _, after, ok := strings.Cut(rest, "/"); ok {
			return "/bot<token>/" + after
		}
	}
	return path
}
