// Package httpw is the write client of remediation code paths: requests without a body, sent only
// when their method and path match one of the client's routes, written out by the remediation that
// uses it. Inventory uses httpx, which only sends GET; TestWriteClientOnlyInRemediations keeps this
// package out of every connector file but remediate.go. Standard library only.
package httpw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
)

// Seg is one id in a path: letters, digits, '_' and '-', so a path cannot climb out of the route
// it names ("..", "/", escapes) or carry a query.
const Seg = `[A-Za-z0-9_-]+`

// Route is one method and path a client may send. The pattern matches the whole path.
type Route struct {
	Method string
	path   *regexp.Regexp
}

// Delete is a DELETE route; pattern is a path under the base URL, built with Seg.
func Delete(pattern string) Route {
	return Route{Method: http.MethodDelete, path: regexp.MustCompile(`^` + pattern + `$`)}
}

// ErrRefused is returned for a request outside the client's routes, before anything is sent.
var ErrRefused = errors.New("refused request outside the remediation's routes")

// Client sends allowlisted requests against one API base URL with fixed headers.
type Client struct {
	BaseURL string
	Header  http.Header
	HTTP    *http.Client
	Routes  []Route
}

// New returns a client that follows no redirect, so a request and its credential never go
// anywhere but the URL the plan showed.
func New(baseURL string, header http.Header, routes ...Route) *Client {
	h := header.Clone()
	h.Set("Accept", "application/json")
	h.Set("User-Agent", "segurata")
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Header:  h,
		Routes:  routes,
		HTTP: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

// Check refuses a method and path no route allows.
func (c *Client) Check(method, path string) error {
	for _, r := range c.Routes {
		if r.Method == method && r.path.MatchString(path) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s", ErrRefused, method, path)
}

// StatusError is a non-2xx answer, with the provider's error message, never a header value.
type StatusError struct {
	Method, Path string
	Code         int
	Message      string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Code, e.Message)
}

// Do sends method to path (relative to BaseURL) after Check, and returns an error unless the
// answer is 2xx.
func (c *Client) Do(ctx context.Context, method, path string) error {
	if err := c.Check(method, path); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header = c.Header.Clone()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &StatusError{Method: method, Path: path, Code: resp.StatusCode, Message: httpx.ErrorMessage(body)}
	}
	return nil
}

// IsStatus reports whether err is a StatusError with the given code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// Send sends the calls of a confirmed plan in order with header (the write credential), through a
// client limited to routes, stopping at the first failure. Every call must be under base. A 401 or
// 403 names the credential that was refused.
func Send(ctx context.Context, base string, header http.Header, calls []connector.Call, routes ...Route) error {
	cl := New(base, header, routes...)
	for _, call := range calls {
		path, ok := strings.CutPrefix(call.URL, cl.BaseURL)
		if !ok {
			return fmt.Errorf("%w: %s is not under %s", ErrRefused, call.URL, cl.BaseURL)
		}
		if err := cl.Do(ctx, call.Method, path); err != nil {
			if IsStatus(err, http.StatusUnauthorized) || IsStatus(err, http.StatusForbidden) {
				return fmt.Errorf("%w: %s was refused, probably because it is read-only: give it write access to API keys, or create one that has it", err, call.Secret)
			}
			return err
		}
	}
	return nil
}
