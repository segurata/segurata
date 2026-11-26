// Package httpw is the write client of remediations: requests without a body, sent only when their
// method and path match one of the remediation's routes. TestWriteClientOnlyInRemediations keeps it
// out of every connector file but remediate.go.
package httpw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
)

// Seg is one id in a path, so a path cannot climb out of its route ("..", "/", escapes) or carry
// a query.
const Seg = `[A-Za-z0-9_-]+`

// Route is one method and whole path a client may send.
type Route struct {
	method string
	path   *regexp.Regexp
}

// Delete is a DELETE route; pattern is a path under the base URL, built with Seg.
func Delete(pattern string) Route {
	return Route{method: http.MethodDelete, path: regexp.MustCompile(`^` + pattern + `$`)}
}

var errRefused = errors.New("refused request outside the remediation's routes")

type client struct {
	*httpx.Client
	routes []Route
}

// newClient follows no redirect: a request and its credential go nowhere but the URL the plan
// showed.
func newClient(baseURL string, header http.Header, routes ...Route) *client {
	c := httpx.New(baseURL, header)
	c.HTTP.CheckRedirect = httpx.NoRedirect
	return &client{c, routes}
}

func (c *client) check(method, path string) error {
	for _, r := range c.routes {
		if r.method == method && r.path.MatchString(path) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s", errRefused, method, path)
}

func (c *client) do(ctx context.Context, method, path string) error {
	if err := c.check(method, path); err != nil {
		return err
	}
	code, body, err := c.Fetch(ctx, method, path, nil, nil)
	if err != nil {
		return err
	}
	if code < 200 || code > 299 {
		return &httpx.StatusError{Method: method, Path: path, Code: code, Message: httpx.ErrorMessage(body)}
	}
	return nil
}

// Send sends the calls of a confirmed plan in order with header (the write credential), through a
// client limited to routes, stopping at the first failure. Every call must be under base.
func Send(ctx context.Context, base string, header http.Header, calls []connector.Call, routes ...Route) error {
	cl := newClient(base, header, routes...)
	for _, call := range calls {
		path, ok := strings.CutPrefix(call.URL, cl.BaseURL)
		if !ok {
			return fmt.Errorf("%w: %s is not under %s", errRefused, call.URL, cl.BaseURL)
		}
		if err := cl.do(ctx, call.Method, path); err != nil {
			if httpx.IsStatus(err, http.StatusUnauthorized) || httpx.IsStatus(err, http.StatusForbidden) {
				return fmt.Errorf("%w: %s was refused, probably because it is read-only: give it write access to API keys, or create one that has it", err, call.Secret)
			}
			return err
		}
	}
	return nil
}
