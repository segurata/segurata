// Package cdp is a minimal Chrome DevTools Protocol client for the user's own running Brave; it
// drives no other browser. Scan pages open as hidden targets, which load with the browser's
// cookies but never appear in a window, so the user's tabs and focus are never touched.
package cdp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultTimeout = 30 * time.Second

var (
	pollInterval = 500 * time.Millisecond
	// A browser listening on the port answers at once, and nothing listening fails at once too.
	versionTimeout = 3 * time.Second
)

// Client is one browser-level CDP connection. Safe for concurrent use.
type Client struct {
	ws        *wsConn
	mu        sync.Mutex
	nextID    int64
	pending   map[int64]chan message
	listeners map[eventKey][]func(json.RawMessage)
	done      chan struct{}
	err       error // valid once done is closed
	// set once the browser refused a hidden target: scan pages then open as background tabs
	visibleScan atomic.Bool
}

type eventKey struct{ sessionID, method string }

type message struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    any             `json:"params,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Version is what <cdpURL>/json/version says about the browser.
type Version struct {
	Browser              string `json:"Browser"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// ReadVersion reads <cdpURL>/json/version without opening the WebSocket.
func ReadVersion(ctx context.Context, cdpURL string) (Version, error) {
	var v Version
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cdpURL, "/")+"/json/version", nil)
	if err != nil {
		return v, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return v, fmt.Errorf("cdp: browser not reachable at %s: %w", cdpURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return v, fmt.Errorf("cdp: %s/json/version: %s", cdpURL, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return v, fmt.Errorf("cdp: /json/version: %w", err)
	}
	if v.WebSocketDebuggerURL == "" {
		return v, errors.New("cdp: /json/version has no webSocketDebuggerUrl")
	}
	return v, nil
}

// ErrNotBrave: the endpoint answers but its browser is not Brave.
var ErrNotBrave = errors.New("not Brave")

// Brave reports itself as Chrome in /json/version and its user agent; only its own API tells.
const isBraveExpr = `(async () => !!(navigator.brave && await navigator.brave.isBrave()))()`

// Brave checks that the browser at cdpURL is Brave, then closes the connection.
func Brave(ctx context.Context, cdpURL string) (Version, error) {
	c, v, err := connect(ctx, cdpURL)
	if err == nil {
		c.Close()
	}
	return v, err
}

// Connect opens the browser at cdpURL once a hidden probe page proved it is Brave: no other
// browser is ever driven.
func Connect(ctx context.Context, cdpURL string) (*Client, error) {
	c, _, err := connect(ctx, cdpURL)
	return c, err
}

func connect(ctx context.Context, cdpURL string) (*Client, Version, error) {
	vctx, cancel := context.WithTimeout(ctx, versionTimeout)
	v, err := ReadVersion(vctx, cdpURL)
	cancel()
	if err != nil {
		return nil, v, err
	}
	c, err := connectTo(ctx, v)
	if err != nil {
		return nil, v, err
	}
	var brave bool
	err = c.WithPage(ctx, "about:blank", func(p *Page) error {
		raw, err := p.Evaluate(ctx, isBraveExpr)
		if err == nil {
			err = json.Unmarshal(raw, &brave)
		}
		return err
	})
	switch {
	case err != nil:
		err = fmt.Errorf("cdp: telling which browser answers at %s: %w", cdpURL, err)
	case !brave:
		err = fmt.Errorf("cdp: the browser at %s (%s) is %w", cdpURL, v.Browser, ErrNotBrave)
	}
	if err != nil {
		c.Close()
		return nil, v, err
	}
	return c, v, nil
}

func connectTo(ctx context.Context, v Version) (*Client, error) {
	ws, err := dialWS(ctx, v.WebSocketDebuggerURL)
	if err != nil {
		return nil, err
	}
	c := &Client{ws: ws, pending: map[int64]chan message{}, listeners: map[eventKey][]func(json.RawMessage){}, done: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

func (c *Client) readLoop() {
	var err error
	for {
		var raw []byte
		if raw, err = c.ws.readMessage(); err != nil {
			break
		}
		var m message
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		if m.ID == 0 {
			c.dispatch(raw)
			continue
		}
		c.mu.Lock()
		ch := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
	c.err = err
	close(c.done)
}

func (c *Client) dispatch(raw []byte) {
	var ev struct {
		Method    string          `json:"method"`
		SessionID string          `json:"sessionId"`
		Params    json.RawMessage `json:"params"`
	}
	if json.Unmarshal(raw, &ev) != nil || ev.Method == "" {
		return
	}
	c.mu.Lock()
	fns := c.listeners[eventKey{ev.SessionID, ev.Method}]
	c.mu.Unlock()
	for _, fn := range fns {
		fn(ev.Params)
	}
}

// Close shuts the connection; pending calls fail.
func (c *Client) Close() error { return c.ws.close() }

// send issues one CDP command and waits for its reply; sessionID is empty for browser commands.
func (c *Client) send(ctx context.Context, method string, params any, sessionID string) (json.RawMessage, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	if params == nil {
		params = struct{}{}
	}
	ch := make(chan message, 1)
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	c.pending[id] = ch
	c.mu.Unlock()
	forget := func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}

	raw, err := json.Marshal(message{ID: id, Method: method, Params: params, SessionID: sessionID})
	if err != nil {
		forget()
		return nil, err
	}
	if err := c.ws.writeText(raw); err != nil {
		forget()
		return nil, fmt.Errorf("cdp: %s: %w", method, err)
	}
	select {
	case m := <-ch:
		if m.Error != nil {
			return nil, fmt.Errorf("cdp: %s: %s (%d)", method, m.Error.Message, m.Error.Code)
		}
		return m.Result, nil
	case <-ctx.Done():
		forget()
		return nil, fmt.Errorf("cdp: %s: %w", method, ctx.Err())
	case <-c.done:
		return nil, fmt.Errorf("cdp: %s: connection closed: %v", method, c.err)
	}
}

// Page is one target attached with a flat session.
type Page struct {
	c         *Client
	sessionID string
}

func (p *Page) send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return p.c.send(ctx, method, params, p.sessionID)
}

// on registers fn for an event of this page until it closes. fn runs on the read loop, so it
// must return quickly and must not call send.
func (p *Page) on(method string, fn func(params json.RawMessage)) {
	p.c.mu.Lock()
	defer p.c.mu.Unlock()
	k := eventKey{p.sessionID, method}
	p.c.listeners[k] = append(p.c.listeners[k], fn)
}

func (c *Client) forgetListeners(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.listeners {
		if k.sessionID == sessionID {
			delete(c.listeners, k)
		}
	}
}

// EvalError is a JavaScript exception thrown by an evaluated expression.
type EvalError struct{ Text string }

func (e *EvalError) Error() string { return "cdp: evaluate: " + e.Text }

// Evaluate runs expr in the page, awaiting promises, and returns its value as JSON.
func (p *Page) Evaluate(ctx context.Context, expr string) (json.RawMessage, error) {
	raw, err := p.send(ctx, "Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true, "awaitPromise": true})
	if err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.ExceptionDetails != nil {
		return nil, &EvalError{Text: r.ExceptionDetails.Text}
	}
	return r.Result.Value, nil
}

// WaitFor evaluates expr every pollInterval until ready accepts the value or tries run out, and
// returns the last value either way, so the caller can inspect a page that never got ready. A
// JavaScript exception means "still loading"; it is returned only if no try ever succeeded.
func (p *Page) WaitFor(ctx context.Context, expr string, ready func(json.RawMessage) bool, tries int) (json.RawMessage, error) {
	var last json.RawMessage
	var evalErr *EvalError
	for i := 0; i < tries; i++ {
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(pollInterval):
		}
		v, err := p.Evaluate(ctx, expr)
		if errors.As(err, &evalErr) {
			continue
		}
		if err != nil {
			return last, err
		}
		last, evalErr = v, nil
		if ready(v) {
			break
		}
	}
	if last == nil && evalErr != nil {
		return nil, evalErr
	}
	return last, nil
}

// WithPage opens url in a new hidden target, hands fn the attached page and always closes the
// target afterwards, even when ctx is already cancelled.
func (c *Client) WithPage(ctx context.Context, url string, fn func(*Page) error) error {
	return c.withPageSetup(ctx, url, nil, fn)
}

// Load opens url in a hidden page and returns what WaitFor returns.
func (c *Client) Load(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int) (v json.RawMessage, err error) {
	err = c.WithPage(ctx, url, func(p *Page) error {
		v, err = p.WaitFor(ctx, expr, ready, tries)
		return err
	})
	return v, err
}

// Response is a body a page fetched. It may hold tokens: callers decode what they need and never
// log or store it.
type Response struct {
	Status int
	Body   []byte
}

// Capture is Load that also returns the last finished response, among those the page itself
// fetched, whose URL matches re. It never sends a request of its own.
func (c *Client) Capture(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int, re *regexp.Regexp) (v json.RawMessage, resp *Response, err error) {
	var mu sync.Mutex
	status := map[string]int{} // matching request id -> HTTP status
	var order []string
	finished := map[string]bool{}
	setup := func(p *Page) error {
		if _, err := p.send(ctx, "Network.enable", nil); err != nil {
			return err
		}
		p.on("Network.responseReceived", func(raw json.RawMessage) {
			var e struct {
				RequestID string `json:"requestId"`
				Response  struct {
					URL    string `json:"url"`
					Status int    `json:"status"`
				} `json:"response"`
			}
			if json.Unmarshal(raw, &e) == nil && re.MatchString(e.Response.URL) {
				mu.Lock()
				status[e.RequestID] = e.Response.Status
				order = append(order, e.RequestID)
				mu.Unlock()
			}
		})
		p.on("Network.loadingFinished", func(raw json.RawMessage) {
			var e struct {
				RequestID string `json:"requestId"`
			}
			if json.Unmarshal(raw, &e) == nil {
				mu.Lock()
				finished[e.RequestID] = true
				mu.Unlock()
			}
		})
		return nil
	}
	err = c.withPageSetup(ctx, url, setup, func(p *Page) error {
		if v, err = p.WaitFor(ctx, expr, ready, tries); err != nil {
			return err
		}
		mu.Lock()
		last := ""
		for _, id := range order {
			if finished[id] {
				last = id
			}
		}
		mu.Unlock()
		if last == "" {
			return nil
		}
		raw, err := p.send(ctx, "Network.getResponseBody", map[string]any{"requestId": last})
		if err != nil {
			return err
		}
		var r struct {
			Body          string `json:"body"`
			Base64Encoded bool   `json:"base64Encoded"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		body := []byte(r.Body)
		if r.Base64Encoded {
			if body, err = base64.StdEncoding.DecodeString(r.Body); err != nil {
				return err
			}
		}
		resp = &Response{Status: status[last], Body: body}
		return nil
	})
	return v, resp, err
}

// scanTarget creates the blank target a scan page loads in: hidden (in no window, never taking
// focus; checked on Brave 156, 2026-11-24) unless the browser refuses that, then a background tab.
// A dedicated scan window does not work: Target.createTarget cannot name a window, and window.open
// from that window's tab brings it to the front each time.
func (c *Client) scanTarget(ctx context.Context) (string, error) {
	if !c.visibleScan.Load() {
		id, err := c.createTarget(ctx, map[string]any{"url": "about:blank", "background": true, "hidden": true})
		if err == nil || ctx.Err() != nil {
			return id, err
		}
		c.visibleScan.Store(true)
	}
	return c.createTarget(ctx, map[string]any{"url": "about:blank", "background": true})
}

func (c *Client) createTarget(ctx context.Context, params map[string]any) (string, error) {
	raw, err := c.send(ctx, "Target.createTarget", params, "")
	if err != nil {
		return "", err
	}
	var t struct {
		TargetID string `json:"targetId"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return "", err
	}
	if t.TargetID == "" {
		return "", errors.New("cdp: Target.createTarget: no targetId")
	}
	return t.TargetID, nil
}

func (c *Client) attach(ctx context.Context, targetID string) (*Page, error) {
	raw, err := c.send(ctx, "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true}, "")
	if err != nil {
		return nil, err
	}
	var a struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	return &Page{c: c, sessionID: a.SessionID}, nil
}

// withPageSetup is WithPage with a setup step that runs on the attached page before it navigates.
func (c *Client) withPageSetup(ctx context.Context, url string, setup, fn func(*Page) error) (err error) {
	id, err := c.scanTarget(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultTimeout)
		defer cancel()
		if _, cerr := c.send(cctx, "Target.closeTarget", map[string]any{"targetId": id}, ""); cerr != nil && err == nil {
			err = cerr
		}
	}()

	p, err := c.attach(ctx, id)
	if err != nil {
		return err
	}
	defer c.forgetListeners(p.sessionID)
	if _, err := p.send(ctx, "Runtime.enable", nil); err != nil {
		return err
	}
	if _, err := p.send(ctx, "Emulation.setFocusEmulationEnabled", map[string]any{"enabled": true}); err != nil {
		return err
	}
	if setup != nil {
		if err := setup(p); err != nil {
			return err
		}
	}
	if _, err := p.send(ctx, "Page.navigate", map[string]any{"url": url}); err != nil {
		return err
	}
	return fn(p)
}

// OpenTab opens url in a foreground tab for the user to act on and attaches to it. The tab is
// the user's: it is never closed.
func (c *Client) OpenTab(ctx context.Context, url string) (*Page, error) {
	id, err := c.createTarget(ctx, map[string]any{"url": url})
	if err != nil {
		return nil, err
	}
	return c.attach(ctx, id)
}
