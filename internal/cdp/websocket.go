package cdp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// This file is a minimal RFC 6455 WebSocket client: enough for CDP, nothing more.
// No extensions, no subprotocols; text and binary messages, fragmentation, ping/pong, close.

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA

	// wsGUID is the fixed string RFC 6455 section 1.3 appends to the key.
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	// maxMessage caps a reassembled message so a misbehaving peer cannot exhaust memory.
	maxMessage = 64 << 20
)

// errClosed is returned by ReadMessage once the peer has sent a close frame.
var errClosed = errors.New("websocket: closed by peer")

type wsConn struct {
	conn net.Conn
	br   *bufio.Reader
	wmu  sync.Mutex // one writer at a time: frames must not interleave
}

// acceptKey is the Sec-WebSocket-Accept value the server must answer to key.
func acceptKey(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// dialWS opens a WebSocket connection to a ws:// or wss:// URL.
func dialWS(ctx context.Context, rawURL string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	var defaultPort string
	switch u.Scheme {
	case "ws":
		defaultPort = "80"
	case "wss":
		defaultPort = "443"
	default:
		return nil, fmt.Errorf("websocket: unsupported scheme %q", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		host += ":" + defaultPort
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "wss" {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	ws, err := handshake(ctx, conn, u)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ws, nil
}

func handshake(ctx context.Context, conn net.Conn, u *url.URL) (*wsConn, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(nonce)

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Host:       u.Host,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: http.Header{
			"Upgrade":               {"websocket"},
			"Connection":            {"Upgrade"},
			"Sec-WebSocket-Key":     {key},
			"Sec-WebSocket-Version": {"13"},
		},
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("websocket: handshake status %s", resp.Status)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		!headerHasToken(resp.Header, "Connection", "upgrade") {
		return nil, errors.New("websocket: server did not upgrade the connection")
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		return nil, errors.New("websocket: bad Sec-WebSocket-Accept")
	}
	return &wsConn{conn: conn, br: br}, nil
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// writeFrame sends one final frame. Client frames are always masked (RFC 6455 section 5.3).
func (w *wsConn) writeFrame(op byte, payload []byte) error {
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|op)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126)
		hdr = binary.BigEndian.AppendUint16(hdr, uint16(n))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}

	w.wmu.Lock()
	defer w.wmu.Unlock()
	if _, err := w.conn.Write(hdr); err != nil {
		return err
	}
	_, err := w.conn.Write(masked)
	return err
}

// WriteText sends payload as one text message.
func (w *wsConn) WriteText(payload []byte) error { return w.writeFrame(opText, payload) }

type frame struct {
	fin     bool
	op      byte
	payload []byte
}

func (w *wsConn) readFrame() (frame, error) {
	var h [2]byte
	if _, err := io.ReadFull(w.br, h[:]); err != nil {
		return frame{}, err
	}
	f := frame{fin: h[0]&0x80 != 0, op: h[0] & 0x0F}
	if h[0]&0x70 != 0 {
		return frame{}, errors.New("websocket: reserved bits set without a negotiated extension")
	}
	if h[1]&0x80 != 0 {
		return frame{}, errors.New("websocket: server frames must not be masked")
	}
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return frame{}, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(w.br, b[:]); err != nil {
			return frame{}, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if f.op >= opClose && (n > 125 || !f.fin) {
		return frame{}, errors.New("websocket: invalid control frame")
	}
	if n > maxMessage {
		return frame{}, fmt.Errorf("websocket: frame of %d bytes exceeds limit", n)
	}
	f.payload = make([]byte, n)
	if _, err := io.ReadFull(w.br, f.payload); err != nil {
		return frame{}, err
	}
	return f, nil
}

// ReadMessage returns the next complete data message, reassembling fragments and answering
// pings on the way. After a close frame it replies with close and returns errClosed.
func (w *wsConn) ReadMessage() (op byte, msg []byte, err error) {
	var started bool
	for {
		f, err := w.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch f.op {
		case opPing:
			if err := w.writeFrame(opPong, f.payload); err != nil {
				return 0, nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			code := f.payload
			if len(code) > 2 {
				code = code[:2]
			}
			_ = w.writeFrame(opClose, code)
			return 0, nil, errClosed
		case opText, opBinary:
			if started {
				return 0, nil, errors.New("websocket: new message before the previous one ended")
			}
			started, op, msg = true, f.op, f.payload
		case opContinuation:
			if !started {
				return 0, nil, errors.New("websocket: continuation without a message")
			}
			if len(msg)+len(f.payload) > maxMessage {
				return 0, nil, errors.New("websocket: message exceeds limit")
			}
			msg = append(msg, f.payload...)
		default:
			return 0, nil, fmt.Errorf("websocket: unknown opcode %#x", f.op)
		}
		if f.fin {
			return op, msg, nil
		}
	}
}

// Close sends a normal-closure frame and closes the socket without waiting for the echo.
func (w *wsConn) Close() error {
	_ = w.writeFrame(opClose, []byte{0x03, 0xE8}) // 1000, normal closure
	return w.conn.Close()
}
