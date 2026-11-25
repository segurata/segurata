// Package cdp is a minimal Chrome DevTools Protocol client for the user's own running Brave,
// started with --remote-debugging-port; it drives no other browser (Connect). Scan pages open as
// hidden targets: they load with the browser's cookies but never appear in a window or the tab
// strip, so the user's tabs and focus are never touched. OpenTab opens the one kind of page the
// user is meant to see. Standard library only.
package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultTimeout bounds a single CDP command when the caller's context has no deadline.
const DefaultTimeout = 30 * time.Second

// pollInterval is how long WaitFor sleeps between evaluations. A variable so tests run fast.
var pollInterval = 500 * time.Millisecond

// Client is one browser-level CDP connection. Safe for concurrent use.
type Client struct {
	ws        *wsConn
	mu        sync.Mutex
	nextID    int64
	pending   map[int64]chan message
	listeners map[eventKey][]func(json.RawMessage)
	done      chan struct{}
	err       error // why the read loop stopped; valid once done is closed
	// visibleScan is set once the browser refused a hidden target: scan pages then open as
	// background tabs, as browsers without hidden targets need.
	visibleScan atomic.Bool
}

// eventKey routes an event to the listeners of one page session.
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

// versionTimeout bounds Brave's /json/version request: a browser listening on the port answers at
// once, and nothing listening fails at once too. A variable so tests run fast.
var versionTimeout = 3 * time.Second

// ErrNotBrave is the error of Brave when the endpoint answers but its browser is not Brave.
var ErrNotBrave = errors.New("not Brave")

// isBraveExpr is true only in Brave: navigator.brave.isBrave() is Brave's own API. Brave reports
// itself as Chrome in /json/version ("Browser": "Chrome/156…", checked on Brave 156) and in its
// user agent, so neither tells it from Chrome.
const isBraveExpr = `(async () => !!(navigator.brave && await navigator.brave.isBrave()))()`

// Brave checks that the browser at cdpURL answers over CDP and is Brave, without starting or
// focusing anything (see Connect), and closes the connection. It returns what /json/version said;
// the error wraps ErrNotBrave when the browser answered but is not Brave.
func Brave(ctx context.Context, cdpURL string) (Version, error) {
	c, v, err := connect(ctx, cdpURL)
	if err == nil {
		c.Close()
	}
	return v, err
}

// Connect opens the browser WebSocket at cdpURL once the browser there proved to be Brave: only
// Brave is ever driven, whoever started it and however the run was started. The proof is
// /json/version (bounded by versionTimeout), then isBraveExpr in a hidden about:blank target that
// is closed at once; Brave reports itself as Chrome in both /json/version and its user agent. The
// error wraps ErrNotBrave when the browser answered but is not Brave.
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

// dial opens the browser WebSocket at cdpURL without telling which browser it is: for this
// package's tests of the protocol, which a fake browser answers.
func dial(ctx context.Context, cdpURL string) (*Client, error) {
	v, err := ReadVersion(ctx, cdpURL)
	if err != nil {
		return nil, err
	}
	return connectTo(ctx, v)
}

// connectTo opens the browser WebSocket /json/version named.
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
		if _, raw, err = c.ws.ReadMessage(); err != nil {
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
	c.err = err // published to readers by close(c.done)
	close(c.done)
}

// dispatch hands an event to the listeners registered for its session and method.
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
func (c *Client) Close() error { return c.ws.Close() }

// Send issues one CDP command and waits for its reply, the context, or DefaultTimeout.
// sessionID is empty for browser-level commands.
func (c *Client) Send(ctx context.Context, method string, params any, sessionID string) (json.RawMessage, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimeout)
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
	if err := c.ws.WriteText(raw); err != nil {
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

// Send issues a CDP command on this page's session.
func (p *Page) Send(ctx context.Context, method string, params any) (json.RawMessage, error) {
	return p.c.Send(ctx, method, params, p.sessionID)
}

// On registers fn for the events called method on this page, until the page closes. fn runs on
// the connection's read loop, so it must return quickly and must not call Send.
func (p *Page) On(method string, fn func(params json.RawMessage)) {
	p.c.mu.Lock()
	defer p.c.mu.Unlock()
	k := eventKey{p.sessionID, method}
	p.c.listeners[k] = append(p.c.listeners[k], fn)
}

// forgetListeners drops every listener of a session.
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

// Evaluate runs expr in the page (awaiting promises) and returns its value as JSON.
// A JavaScript exception becomes an error.
func (p *Page) Evaluate(ctx context.Context, expr string) (json.RawMessage, error) {
	raw, err := p.Send(ctx, "Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true, "awaitPromise": true})
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

// WaitFor evaluates expr every pollInterval until ready accepts the value or tries run out.
// It returns the last value either way, so the caller can still inspect a page that never got
// ready (a sign-in wall, an empty list). A JavaScript exception counts as "not ready yet"
// (document.body is null while the page loads); it is returned only if no try ever succeeded.
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
	return c.WithPageSetup(ctx, url, nil, fn)
}

// scanTarget creates the blank target a scan page loads in. It is hidden: observable over CDP but
// in no window and not in the tab strip, so a run never flashes tabs among the user's own or takes
// focus (checked on Brave 156, 2026-11-24: it loads signed-in pages and reports itself visible).
// Opening scan tabs in one dedicated window instead was tried and dropped: Target.createTarget
// cannot name a window, so a window gets only the tab it is created with, and window.open from
// that tab brings the window to the front each time. A browser that refuses hidden targets gets
// background tabs, as before.
func (c *Client) scanTarget(ctx context.Context) (string, error) {
	if !c.visibleScan.Load() {
		raw, err := c.Send(ctx, "Target.createTarget", map[string]any{"url": "about:blank", "background": true, "hidden": true}, "")
		if err == nil {
			return targetID(raw)
		}
		if ctx.Err() != nil {
			return "", err
		}
		c.visibleScan.Store(true)
	}
	return c.createTarget(ctx, map[string]any{"url": "about:blank", "background": true})
}

// createTarget creates a target with params and returns its id.
func (c *Client) createTarget(ctx context.Context, params map[string]any) (string, error) {
	raw, err := c.Send(ctx, "Target.createTarget", params, "")
	if err != nil {
		return "", err
	}
	return targetID(raw)
}

// targetID reads the id of the target Target.createTarget created.
func targetID(raw json.RawMessage) (string, error) {
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

// attach opens a flat session on a target.
func (c *Client) attach(ctx context.Context, targetID string) (*Page, error) {
	raw, err := c.Send(ctx, "Target.attachToTarget", map[string]any{"targetId": targetID, "flatten": true}, "")
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

// WithPageSetup is WithPage with a setup step that runs on the attached page before it navigates:
// the place to enable a domain such as Network and subscribe to its events with On.
func (c *Client) WithPageSetup(ctx context.Context, url string, setup, fn func(*Page) error) (err error) {
	id, err := c.scanTarget(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), DefaultTimeout)
		defer cancel()
		if _, cerr := c.Send(cctx, "Target.closeTarget", map[string]any{"targetId": id}, ""); cerr != nil && err == nil {
			err = cerr
		}
	}()

	p, err := c.attach(ctx, id)
	if err != nil {
		return err
	}
	defer c.forgetListeners(p.sessionID)
	if _, err := p.Send(ctx, "Runtime.enable", nil); err != nil {
		return err
	}
	if _, err := p.Send(ctx, "Emulation.setFocusEmulationEnabled", map[string]any{"enabled": true}); err != nil {
		return err
	}
	if setup != nil {
		if err := setup(p); err != nil {
			return err
		}
	}
	if _, err := p.Send(ctx, "Page.navigate", map[string]any{"url": url}); err != nil {
		return err
	}
	return fn(p)
}

// OpenTab opens url in a normal foreground tab of the user's last active window and attaches to
// it, so its state can be read with Evaluate. The tab is the user's: it is never closed, and it
// stays open after the connection closes. For pages where the user has to act (sign in, confirm
// a password); scans use WithPage.
func (c *Client) OpenTab(ctx context.Context, url string) (*Page, error) {
	id, err := c.createTarget(ctx, map[string]any{"url": url})
	if err != nil {
		return nil, err
	}
	return c.attach(ctx, id)
}
