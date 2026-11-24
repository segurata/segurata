package cdp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- a tiny server side of RFC 6455, enough to exercise the client ---

type srvConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex
}

// upgrade completes the server handshake. acceptOverride, when set, sends a wrong accept key.
func upgrade(t *testing.T, w http.ResponseWriter, r *http.Request, acceptOverride string) *srvConn {
	t.Helper()
	if r.Header.Get("Sec-WebSocket-Version") != "13" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		t.Errorf("bad upgrade request headers: %v", r.Header)
	}
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Fatal(err)
	}
	accept := acceptKey(r.Header.Get("Sec-WebSocket-Key"))
	if acceptOverride != "" {
		accept = acceptOverride
	}
	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
	brw.Flush()
	return &srvConn{conn: conn, br: brw.Reader}
}

// writeFrame writes an unmasked server frame.
func (s *srvConn) writeFrame(fin bool, op byte, payload []byte) {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	hdr := []byte{b0}
	switch n := len(payload); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.conn.Write(append(hdr, payload...))
}

// readFrame reads one client frame, failing the test if it is not masked.
func (s *srvConn) readFrame(t *testing.T) (byte, []byte) {
	var h [2]byte
	if _, err := io.ReadFull(s.br, h[:]); err != nil {
		return 0, nil
	}
	if h[1]&0x80 == 0 {
		t.Errorf("client frame not masked")
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		io.ReadFull(s.br, b[:])
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		io.ReadFull(s.br, b[:])
		n = binary.BigEndian.Uint64(b[:])
	}
	var mask [4]byte
	io.ReadFull(s.br, mask[:])
	p := make([]byte, n)
	io.ReadFull(s.br, p)
	for i := range p {
		p[i] ^= mask[i%4]
	}
	return h[0] & 0x0F, p
}

func wsURL(srv *httptest.Server) string { return "ws" + strings.TrimPrefix(srv.URL, "http") }

func wsServer(t *testing.T, handle func(*srvConn)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := upgrade(t, w, r, "")
		defer s.conn.Close()
		handle(s)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialT(t *testing.T, url string) *wsConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, err := dialWS(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.conn.Close() })
	return ws
}

// --- framing ---

func TestAcceptKeyMatchesRFCExample(t *testing.T) {
	// RFC 6455 section 1.3.
	if got := acceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("acceptKey = %q", got)
	}
}

func TestFragmentedReplyWithInterleavedPing(t *testing.T) {
	pong := make(chan []byte, 1)
	srv := wsServer(t, func(s *srvConn) {
		op, p := s.readFrame(t)
		if op != opText || string(p) != "hello" {
			t.Errorf("server got op=%d %q", op, p)
		}
		s.writeFrame(false, opText, []byte("hel"))
		s.writeFrame(true, opPing, []byte("are you there"))
		s.writeFrame(false, opContinuation, []byte("lo, "))
		s.writeFrame(true, opContinuation, []byte("world"))
		op, p = s.readFrame(t)
		if op != opPong {
			t.Errorf("expected pong, got op=%d", op)
		}
		pong <- p
	})
	ws := dialT(t, wsURL(srv))
	if err := ws.WriteText([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	op, msg, err := ws.ReadMessage()
	if err != nil || op != opText || string(msg) != "hello, world" {
		t.Fatalf("ReadMessage = %d %q %v", op, msg, err)
	}
	if p := <-pong; string(p) != "are you there" {
		t.Fatalf("pong payload %q", p)
	}
}

func TestLargePayloadsBothDirections(t *testing.T) {
	for _, n := range []int{125, 126, 300, 65535, 65536, 200_000} {
		payload := bytes.Repeat([]byte("abcdefghij"), n/10+1)[:n]
		srv := wsServer(t, func(s *srvConn) {
			_, p := s.readFrame(t)
			if !bytes.Equal(p, payload) {
				t.Errorf("n=%d: server got %d bytes", n, len(p))
			}
			s.writeFrame(true, opText, p)
		})
		ws := dialT(t, wsURL(srv))
		if err := ws.WriteText(payload); err != nil {
			t.Fatal(err)
		}
		_, msg, err := ws.ReadMessage()
		if err != nil || !bytes.Equal(msg, payload) {
			t.Fatalf("n=%d: echo %d bytes, err %v", n, len(msg), err)
		}
	}
}

func TestCloseFromServerIsEchoed(t *testing.T) {
	echoed := make(chan byte, 1)
	srv := wsServer(t, func(s *srvConn) {
		s.writeFrame(true, opClose, []byte{0x03, 0xE8, 'b', 'y', 'e'})
		op, _ := s.readFrame(t)
		echoed <- op
	})
	ws := dialT(t, wsURL(srv))
	if _, _, err := ws.ReadMessage(); !errors.Is(err, errClosed) {
		t.Fatalf("err = %v, want errClosed", err)
	}
	if op := <-echoed; op != opClose {
		t.Fatalf("client answered op=%d, want close", op)
	}
}

func TestProtocolViolationsAreErrors(t *testing.T) {
	cases := map[string]func(*srvConn){
		"masked server frame": func(s *srvConn) { s.conn.Write([]byte{0x81, 0x81, 1, 2, 3, 4, 'x'}) },
		"orphan continuation": func(s *srvConn) { s.writeFrame(true, opContinuation, []byte("x")) },
		"fragmented ping":     func(s *srvConn) { s.writeFrame(false, opPing, nil) },
		"reserved bits":       func(s *srvConn) { s.conn.Write([]byte{0xC1, 0x01, 'x'}) },
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			srv := wsServer(t, func(s *srvConn) { send(s); time.Sleep(100 * time.Millisecond) })
			ws := dialT(t, wsURL(srv))
			if _, _, err := ws.ReadMessage(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestHandshakeRejectsBadAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := upgrade(t, w, r, "bm90IHRoZSByaWdodCBrZXk=")
		s.conn.Close()
	}))
	defer srv.Close()
	if _, err := dialWS(context.Background(), wsURL(srv)); err == nil || !strings.Contains(err.Error(), "Accept") {
		t.Fatalf("err = %v, want bad accept", err)
	}
}

func TestHandshakeRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := dialWS(context.Background(), wsURL(srv)); err == nil {
		t.Fatal("expected an error")
	}
}

// --- CDP client over a fake browser ---

type fakeBrowser struct {
	mu       sync.Mutex
	methods  []string
	closed   []string
	silent   map[string]bool // methods that never get an answer
	evals    int
	readyAt  int // Runtime.evaluate returns true from this call on
	evalFail bool
	failFor  int              // the first failFor evaluations throw, as while a page loads
	noHidden bool             // reject Target.createTarget with hidden, as a browser without hidden targets
	creates  []map[string]any // Target.createTarget params, in order
}

func (b *fakeBrowser) serve(t *testing.T) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/json/version" {
			json.NewEncoder(w).Encode(map[string]string{"webSocketDebuggerUrl": wsURL(srv) + "/devtools/browser/x"})
			return
		}
		s := upgrade(t, w, r, "")
		defer s.conn.Close()
		for {
			op, p := s.readFrame(t)
			if op != opText {
				return
			}
			var m struct {
				ID        int64          `json:"id"`
				Method    string         `json:"method"`
				Params    map[string]any `json:"params"`
				SessionID string         `json:"sessionId"`
			}
			if err := json.Unmarshal(p, &m); err != nil {
				t.Errorf("bad command %q", p)
				return
			}
			go b.answer(s, m.ID, m.Method, m.Params, m.SessionID)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (b *fakeBrowser) answer(s *srvConn, id int64, method string, params map[string]any, session string) {
	b.mu.Lock()
	b.methods = append(b.methods, method)
	if b.silent[method] {
		b.mu.Unlock()
		return
	}
	var result any = map[string]any{}
	var errObj any
	var events []map[string]any
	switch method {
	case "Page.navigate":
		// The page's own event, then the same event for another page: only the first may arrive.
		events = []map[string]any{
			{"method": "Network.responseReceived", "sessionId": "S1", "params": map[string]any{"requestId": "R1"}},
			{"method": "Network.responseReceived", "sessionId": "S2", "params": map[string]any{"requestId": "R2"}},
		}
	case "Target.createTarget":
		b.creates = append(b.creates, params)
		if b.noHidden && params["hidden"] == true {
			errObj = map[string]any{"code": -32602, "message": "Invalid parameters"}
		}
		result = map[string]any{"targetId": "T1"}
	case "Target.attachToTarget":
		result = map[string]any{"sessionId": "S1"}
	case "Target.closeTarget":
		b.closed = append(b.closed, params["targetId"].(string))
	case "Runtime.evaluate":
		b.evals++
		switch {
		case b.evalFail || b.evals <= b.failFor:
			result = map[string]any{"result": map[string]any{}, "exceptionDetails": map[string]any{"text": "Uncaught boom"}}
		default:
			result = map[string]any{"result": map[string]any{"value": map[string]any{"ready": b.evals >= b.readyAt, "n": b.evals}}}
		}
	case "Bogus.method":
		errObj = map[string]any{"code": -32601, "message": "'Bogus.method' wasn't found"}
	}
	b.mu.Unlock()
	// An unrelated event first: the client must skip it.
	ev, _ := json.Marshal(map[string]any{"method": "Target.targetInfoChanged", "params": map[string]any{}})
	s.writeFrame(true, opText, ev)
	for _, e := range events {
		raw, _ := json.Marshal(e)
		s.writeFrame(true, opText, raw)
	}
	reply := map[string]any{"id": id}
	if session != "" {
		reply["sessionId"] = session
	}
	if errObj != nil {
		reply["error"] = errObj
	} else {
		reply["result"] = result
	}
	raw, _ := json.Marshal(reply)
	s.writeFrame(true, opText, raw)
}

func connectT(t *testing.T, b *fakeBrowser) *Client {
	t.Helper()
	pollInterval = time.Millisecond
	srv := b.serve(t)
	c, err := Connect(context.Background(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestWithPageRunsTheSequenceAndWaitsUntilReady(t *testing.T) {
	b := &fakeBrowser{readyAt: 3}
	c := connectT(t, b)
	var got json.RawMessage
	err := c.WithPage(context.Background(), "https://example.com", func(p *Page) error {
		var err error
		got, err = p.WaitFor(context.Background(), "x", func(v json.RawMessage) bool {
			var r struct{ Ready bool }
			json.Unmarshal(v, &r)
			return r.Ready
		}, 10)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"n":3,"ready":true}` {
		t.Fatalf("WaitFor = %s", got)
	}
	want := "Target.createTarget Target.attachToTarget Runtime.enable Emulation.setFocusEmulationEnabled Page.navigate Runtime.evaluate Runtime.evaluate Runtime.evaluate Target.closeTarget"
	if s := strings.Join(b.methods, " "); s != want {
		t.Fatalf("methods:\n got %s\nwant %s", s, want)
	}
}

func TestWithPageSetupSubscribesBeforeNavigatingAndForgetsOnClose(t *testing.T) {
	b := &fakeBrowser{}
	c := connectT(t, b)
	var mu sync.Mutex
	var got []string
	setup := func(p *Page) error {
		if _, err := p.Send(context.Background(), "Network.enable", nil); err != nil {
			return err
		}
		p.On("Network.responseReceived", func(params json.RawMessage) {
			var e struct{ RequestID string }
			json.Unmarshal(params, &e)
			mu.Lock()
			got = append(got, e.RequestID)
			mu.Unlock()
		})
		return nil
	}
	err := c.WithPageSetup(context.Background(), "https://example.com", setup, func(p *Page) error {
		// The events precede the navigate reply on the wire, so they have been dispatched.
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, ",") != "R1" {
		t.Fatalf("events = %v, want only this page's R1", got)
	}
	want := "Target.createTarget Target.attachToTarget Runtime.enable Emulation.setFocusEmulationEnabled Network.enable Page.navigate Target.closeTarget"
	if s := strings.Join(b.methods, " "); s != want {
		t.Fatalf("methods:\n got %s\nwant %s", s, want)
	}
	c.mu.Lock()
	n := len(c.listeners)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d listeners left after the page closed", n)
	}
}

func TestWithPageSetupErrorStillClosesTheTarget(t *testing.T) {
	b := &fakeBrowser{}
	c := connectT(t, b)
	boom := errors.New("boom")
	err := c.WithPageSetup(context.Background(), "https://example.com", func(*Page) error { return boom }, func(*Page) error {
		t.Fatal("fn ran after a failed setup")
		return nil
	})
	if !errors.Is(err, boom) || len(b.closed) != 1 {
		t.Fatalf("err %v, closed %v", err, b.closed)
	}
}

func TestWaitForReturnsLastValueWhenNeverReady(t *testing.T) {
	b := &fakeBrowser{readyAt: 100}
	c := connectT(t, b)
	err := c.WithPage(context.Background(), "u", func(p *Page) error {
		v, err := p.WaitFor(context.Background(), "x", func(json.RawMessage) bool { return false }, 4)
		if string(v) != `{"n":4,"ready":false}` {
			t.Errorf("last value %s", v)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWaitForTreatsExceptionsAsNotReady(t *testing.T) {
	b := &fakeBrowser{failFor: 2, readyAt: 3}
	c := connectT(t, b)
	err := c.WithPage(context.Background(), "u", func(p *Page) error {
		v, err := p.WaitFor(context.Background(), "document.body.innerText", func(json.RawMessage) bool { return true }, 5)
		if string(v) != `{"n":3,"ready":true}` {
			t.Errorf("value %s", v)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWaitForReturnsTheExceptionWhenEveryTryThrows(t *testing.T) {
	b := &fakeBrowser{evalFail: true}
	c := connectT(t, b)
	err := c.WithPage(context.Background(), "u", func(p *Page) error {
		_, err := p.WaitFor(context.Background(), "x", func(json.RawMessage) bool { return true }, 3)
		return err
	})
	var ee *EvalError
	if !errors.As(err, &ee) || ee.Text != "Uncaught boom" {
		t.Fatalf("err = %v", err)
	}
}

func TestWithPageClosesTargetWhenFnFails(t *testing.T) {
	b := &fakeBrowser{evalFail: true}
	c := connectT(t, b)
	err := c.WithPage(context.Background(), "u", func(p *Page) error {
		_, err := p.Evaluate(context.Background(), "throw 1")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "Uncaught boom") {
		t.Fatalf("err = %v", err)
	}
	if len(b.closed) != 1 || b.closed[0] != "T1" {
		t.Fatalf("closed targets %v", b.closed)
	}
}

func TestWithPageClosesTargetWhenContextIsCancelled(t *testing.T) {
	b := &fakeBrowser{}
	c := connectT(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	err := c.WithPage(ctx, "u", func(p *Page) error {
		cancel()
		_, err := p.WaitFor(ctx, "x", func(json.RawMessage) bool { return false }, 5)
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if len(b.closed) != 1 {
		t.Fatalf("target not closed: %v", b.methods)
	}
}

func TestSendReportsProtocolErrorsAndTimeouts(t *testing.T) {
	b := &fakeBrowser{silent: map[string]bool{"Never.answers": true}}
	c := connectT(t, b)
	if _, err := c.Send(context.Background(), "Bogus.method", nil, ""); err == nil || !strings.Contains(err.Error(), "wasn't found") {
		t.Fatalf("err = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Send(ctx, "Never.answers", nil, ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline", err)
	}
	c.mu.Lock()
	n := len(c.pending)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d pending calls leaked", n)
	}
}

func TestSendFailsOnceConnectionDrops(t *testing.T) {
	b := &fakeBrowser{}
	c := connectT(t, b)
	c.ws.conn.Close()
	<-c.done
	if _, err := c.Send(context.Background(), "Target.createTarget", nil, ""); err == nil {
		t.Fatal("expected an error")
	}
}

func TestConnectNeedsDebuggerURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer srv.Close()
	if _, err := Connect(context.Background(), srv.URL); err == nil {
		t.Fatal("expected an error")
	}
}

func TestScanPagesOpenAsHiddenTargets(t *testing.T) {
	b := &fakeBrowser{}
	c := connectT(t, b)
	for range 2 {
		if err := c.WithPage(context.Background(), "u", func(*Page) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range b.creates {
		if p["hidden"] != true || p["background"] != true || p["newWindow"] != nil {
			t.Fatalf("createTarget params %v, want a hidden background target", p)
		}
	}
	if len(b.closed) != 2 {
		t.Fatalf("closed %v", b.closed)
	}
}

func TestScanFallsBackToBackgroundTabsWhenHiddenIsRefused(t *testing.T) {
	b := &fakeBrowser{noHidden: true}
	c := connectT(t, b)
	for range 2 {
		if err := c.WithPage(context.Background(), "u", func(*Page) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	// The first page asks for hidden once, then a background tab; the second asks straight away.
	if len(b.creates) != 3 || b.creates[0]["hidden"] != true || b.creates[1]["hidden"] != nil || b.creates[2]["hidden"] != nil {
		t.Fatalf("createTarget params %v", b.creates)
	}
	if b.creates[1]["background"] != true || b.creates[2]["background"] != true {
		t.Fatalf("fallback is not a background tab: %v", b.creates)
	}
}

func TestOpenTabIsAForegroundTabNeverClosed(t *testing.T) {
	b := &fakeBrowser{readyAt: 1}
	c := connectT(t, b)
	p, err := c.OpenTab(context.Background(), "https://github.com/settings/apps/authorizations")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Evaluate(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	<-c.done
	want := map[string]any{"url": "https://github.com/settings/apps/authorizations"}
	if len(b.creates) != 1 || fmt.Sprint(b.creates[0]) != fmt.Sprint(want) {
		t.Fatalf("createTarget params %v, want %v (foreground: no background, hidden or window)", b.creates, want)
	}
	if s := strings.Join(b.methods, " "); s != "Target.createTarget Target.attachToTarget Runtime.evaluate" {
		t.Fatalf("methods %s", s)
	}
}
