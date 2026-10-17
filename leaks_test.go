package main

// Regression tests for the long-running resource issues found in review.
//
// Each test asserts the fixed behaviour (bodies closed, backend connections
// closed, no goroutines stuck, sessions torn down). They fail against the
// buggy code and pass once the corresponding leak/deadlock is fixed.
//
// Run just these with:
//
//	go test -run 'Leak|Closed|Closes' -v -timeout 120s
//
// The leak-related ones also print the offending goroutine stack on failure.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	grlws "github.com/gorilla/websocket"
)

// leakedRemoteConns retains remote TCP connections created by the websocket
// reproducer so that the goroutines blocked reading from them stay blocked
// (and never run their deferred logging) while the test suite runs.
var leakedRemoteConns []net.Conn

// ---------------------------------------------------------------------------
// 1. auth_http.go: HTTPAuthenticator.GetRoles never closes resp.Body.
// ---------------------------------------------------------------------------

type closeTrackingBody struct {
	data   []byte
	closed atomic.Bool
}

func (b *closeTrackingBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}

func (b *closeTrackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

type stubRoundTripper struct {
	status int
	body   *closeTrackingBody
}

func (rt *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: rt.status,
		Status:     fmt.Sprintf("%d %s", rt.status, http.StatusText(rt.status)),
		Header:     http.Header{},
		Body:       rt.body,
		Request:    req,
	}, nil
}

// TestHTTPAuthClosesResponseBody triggers the auth-body leak on both the
// success and the non-success code path.
func TestHTTPAuthClosesResponseBody(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(fmt.Sprintf("status-%d", status), func(t *testing.T) {
			ha, err := NewHTTPAuthenticator("http://auth.example/check", []string{"role"})
			if err != nil {
				t.Fatalf("NewHTTPAuthenticator: %s", err)
			}
			body := &closeTrackingBody{data: []byte("ok")}
			ha.(*HTTPAuthenticator).client = &http.Client{Transport: &stubRoundTripper{status: status, body: body}}

			req, err := http.NewRequest("GET", "http://svc.example/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ha.GetRoles(req, nil); err != nil {
				t.Fatalf("GetRoles: %s", err)
			}

			if !body.closed.Load() {
				t.Errorf("auth response body was not closed (status %d): "+
					"the underlying keep-alive connection/fd is leaked on every auth request", status)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. fcgi_handler.go: backend FastCGI connection is not closed when the
//    request fails after a successful Dial.
// ---------------------------------------------------------------------------

// fakeBadFCGIServer accepts one connection and writes a series of records
// with an invalid FCGI version so that FCGIClient.Request fails after Dial.
// (The library retries a couple of times, so several records are needed, and
// the connection is deliberately kept open.)
func fakeBadFCGIServer(ln net.Listener) chan net.Conn {
	accepted := make(chan net.Conn, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- conn:
			default:
				conn.Close()
			}
			// 8-byte headers with Version=2 (must be 1) -> record.read fails.
			for i := 0; i < 8; i++ {
				_, _ = conn.Write([]byte{2, 1, 0, 1, 0, 0, 0, 0})
			}
		}
	}()
	return accepted
}

// TestFastCGIErrorPathClosesBackend triggers the fcgi error-after-dial path.
func TestFastCGIErrorPathClosesBackend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := fakeBadFCGIServer(ln)

	fh := NewFastCGIHandler(ln.Addr().String(), &serverConfig{logger: &simpleLogger{currentLevel: logLevelFatal}})
	rec := httptest.NewRecorder()
	fh.ServeHTTP(rec, httptest.NewRequest("GET", "http://svc.example/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 from failed fcgi request, got %d", rec.Code)
	}

	var backend net.Conn
	select {
	case backend = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("fcgi backend never saw a connection")
	}
	defer backend.Close()

	// If the handler closed the FCGIClient we see EOF once the request bytes
	// it sent are drained; if it leaked, the connection stays open and the
	// read eventually times out.
	_ = backend.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	for {
		if _, err := backend.Read(buf); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("FastCGI backend connection was left open after a failed request: leaked socket/fd")
			}
			return // EOF / closed: expected
		}
	}
}

// ---------------------------------------------------------------------------
// 3. websock.go: a reader goroutine can block forever on the unbuffered
//    channel once the corresponding writer goroutine has exited.
// ---------------------------------------------------------------------------

// findGoroutineStack returns the first goroutine stack that contains needle
// and whose header contains state ("" for any). Empty string if none.
func findGoroutineStack(state, needle string) string {
	size := 1 << 20
	for {
		buf := make([]byte, size)
		n := runtime.Stack(buf, true)
		stacks := string(buf[:n])
		for _, g := range strings.Split(stacks, "\n\n") {
			if !strings.Contains(g, needle) {
				continue
			}
			head := g
			if i := strings.IndexByte(g, '\n'); i >= 0 {
				head = g[:i]
			}
			if state == "" || strings.Contains(head, state) {
				return g
			}
		}
		if n < size {
			return ""
		}
		size *= 2
		if size > 1<<26 {
			return ""
		}
	}
}

// TestWebSocketReaderGoroutineLeak triggers wsReader blocking on
// "dataFromWS <- data" after sockWriter has exited via the alive check.
//
// The remote connections are deliberately left open (and are not closed on
// cleanup) so that the leaked goroutines stay blocked and never run their
// deferred logging; that keeps the test itself free of data races on the
// shared logger state.
func TestWebSocketReaderGoroutineLeak(t *testing.T) {
	// Remote socket that accepts but never reads/closes, so sockReader
	// stays alive and only sockWriter exits.
	remoteLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remoteLn.Close()
	// Keep references so the accepted conns (and the goroutines reading
	// them) stay alive and blocked for the duration of the test.
	go func() {
		for {
			c, err := remoteLn.Accept()
			if err != nil {
				return
			}
			leakedRemoteConns = append(leakedRemoteConns, c)
		}
	}()

	// Small read timeout => sockWriter's alive check fails and it exits
	// soon after connect; stopRunning then waits 100ms before closing the
	// websocket, which is the window we aim at.
	wsh := newWebSocketHandler(remoteLn.Addr().String()).setReadTimeout(150 * time.Millisecond)
	srv := httptest.NewServer(wsh)
	defer srv.Close()

	ws, _, err := grlws.DefaultDialer.Dial("ws"+srv.URL[4:], nil)
	if err != nil {
		t.Fatalf("dial: %s", err)
	}
	defer ws.Close()
	// Do not read from ws, so the server's ping is never answered.

	// sockWriter exits at ~2*readTimeout (300ms) and closes the websocket at
	// ~400ms. Deliver messages into that window so wsReader blocks on the
	// send after its consumer is gone.
	time.Sleep(320 * time.Millisecond)
	for i := 0; i < 5; i++ {
		_ = ws.WriteMessage(grlws.BinaryMessage, []byte("ping-after-writer-exit"))
		time.Sleep(20 * time.Millisecond)
	}

	deadline := time.Now().Add(1500 * time.Millisecond)
	var stuck string
	for time.Now().Before(deadline) {
		if stuck = findGoroutineStack("[chan send]", "wsReader"); stuck != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stuck != "" {
		t.Errorf("wsReader is stuck sending on a channel whose consumer is gone (goroutine leak):\n%s", stuck)
	}
}

// ---------------------------------------------------------------------------
// 4. wstnl.go: closeWS waits for the writer goroutine before closing the
//    websocket, so it can block forever when the writer is stuck in
//    ws.WriteMessage (client connected but not reading).
// ---------------------------------------------------------------------------

// TestWSTNLListenerGoneClosesSessions triggers the wstnl teardown deadlock:
// a session writer is blocked writing to a client that does not read, then
// the listener goes away and the server must still close the client.
func TestWSTNLListenerGoneClosesSessions(t *testing.T) {
	srv := httptest.NewServer(&wstnlHandler{poolName: "leaktest", encoding: "utf-8"})
	defer srv.Close()
	wsURL := "ws" + srv.URL[4:] + "/tunnel/leaktest"

	// Listener side.
	ld := grlws.Dialer{Subprotocols: []string{"tcp-forwarder"}}
	listener, _, err := ld.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("listener dial: %s", err)
	}
	defer listener.Close()

	// Client side (does not request the forwarder subprotocol). Dialing blocks
	// until the server received CONNECTED from the listener, so do it async.
	clientCh := make(chan *grlws.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, _, err := grlws.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			errCh <- err
			return
		}
		clientCh <- c
	}()

	// Server asks the listener to open a session.
	_ = listener.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, msg, err := listener.ReadMessage()
	if err != nil {
		t.Fatalf("listener read OPEN: %s", err)
	}
	fields := strings.Fields(string(msg))
	if mt != grlws.TextMessage || len(fields) != 2 || fields[0] != "OPEN" {
		t.Fatalf("expected 'OPEN <id>', got type=%d %q", mt, msg)
	}
	id, err := parseUint32(fields[1])
	if err != nil {
		t.Fatalf("bad session id %q: %s", fields[1], err)
	}
	if err := listener.WriteMessage(grlws.TextMessage, []byte("CONNECTED "+fields[1])); err != nil {
		t.Fatalf("listener CONNECTED: %s", err)
	}
	_ = listener.SetReadDeadline(time.Time{})

	var client *grlws.Conn
	select {
	case client = <-clientCh:
	case err := <-errCh:
		t.Fatalf("client dial: %s", err)
	case <-time.After(10 * time.Second):
		t.Fatal("client dial timed out")
	}
	defer client.Close()

	// Flood binary data toward the client, which never reads it. The
	// server-side session writer blocks in ws.WriteMessage while the
	// write channel backs up.
	frame := make([]byte, 4+16*1024)
	binary.BigEndian.PutUint32(frame, id)
	flooding := make(chan struct{})
	go func() {
		defer close(flooding)
		for i := 0; i < 2048; i++ { // ~32MiB
			if err := listener.WriteMessage(grlws.BinaryMessage, frame); err != nil {
				return
			}
		}
	}()
	time.Sleep(1 * time.Second)

	// Listener goes away; the server should tear the session down and close
	// the client websocket. With the current closeWS ordering this deadlocks,
	// to be unblocked only once closeWS can actually reach s.ws.Close().
	_ = listener.Close()
	<-flooding

	deadline := time.Now().Add(10 * time.Second)
	_ = client.SetReadDeadline(deadline)
	for {
		if _, _, err := client.ReadMessage(); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("client websocket was not closed after the listener disconnected "+
					"(wstnl session teardown deadlocked; goroutine still blocked):\n%s",
					findGoroutineStack("", "closeWS"))
			}
			return // server closed the client: expected
		}
	}
}
