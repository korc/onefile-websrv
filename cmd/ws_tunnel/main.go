package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type clientState struct {
	id     uint32
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *clientState) closeOnce() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.closed = true
	return true
}

type listener struct {
	wsURL  string
	target string

	mu      sync.Mutex
	ws      *websocket.Conn
	clients map[uint32]*clientState
	done    chan struct{}
}

func (l *listener) isAlive() bool {
	select {
	case <-l.done:
		return false
	default:
		return true
	}
}

func newListener(wsURL, target string) *listener {
	return &listener{
		wsURL:   wsURL,
		target:  target,
		clients: make(map[uint32]*clientState),
		done:    make(chan struct{}),
	}
}

func (l *listener) sendText(s string) error {
	l.mu.Lock()
	ws := l.ws
	alive := l.isAlive()
	l.mu.Unlock()
	if !alive || ws == nil {
		return errors.New("listener closed")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return ws.WriteMessage(websocket.TextMessage, []byte(s))
}

func (l *listener) sendBinary(b []byte) error {
	l.mu.Lock()
	ws := l.ws
	alive := l.isAlive()
	l.mu.Unlock()
	if !alive || ws == nil {
		return errors.New("listener closed")
	}
	cp := append([]byte(nil), b...)
	l.mu.Lock()
	defer l.mu.Unlock()
	return ws.WriteMessage(websocket.BinaryMessage, cp)
}

func (l *listener) dialTarget() (net.Conn, error) {
	spec := strings.TrimSpace(l.target)
	switch {
	case strings.HasPrefix(spec, "tcp://"):
		return net.Dial("tcp", spec[len("tcp://"):])
	case strings.HasPrefix(spec, "tcp4://"):
		return net.Dial("tcp4", spec[len("tcp4://"):])
	case strings.HasPrefix(spec, "tcp6://"):
		return net.Dial("tcp6", spec[len("tcp6://"):])
	case strings.HasPrefix(spec, "unix://"):
		return net.Dial("unix", spec[len("unix://"):])
	case strings.HasPrefix(spec, "/"), strings.HasPrefix(spec, "./"), strings.HasPrefix(spec, "@"):
		addr := spec
		if strings.HasPrefix(spec, "@") {
			addr = "\x00" + spec[1:]
		}
		return net.Dial("unix", addr)
	}
	if i := strings.Index(spec, "://"); i >= 0 {
		proto := spec[:i]
		rest := spec[i+3:]
		switch proto {
		case "tcp", "tcp4", "tcp6":
			return net.Dial(proto, rest)
		default:
			return nil, fmt.Errorf("unsupported protocol %s", proto)
		}
	}
	// Assume host:port TCP target.
	return net.Dial("tcp", spec)
}

func (l *listener) handleOpen(id uint32) {
	conn, err := l.dialTarget()
	if err != nil {
		log.Printf("wstnl %s: dial target %s failed: %v", l.wsURL, l.target, err)
		_ = l.sendText(fmt.Sprintf("FAILED %d", id))
		return
	}

	l.mu.Lock()
	if old, ok := l.clients[id]; ok {
		old.closeOnce()
		old.conn.Close()
		delete(l.clients, id)
	}
	st := &clientState{id: id, conn: conn}
	l.clients[id] = st
	l.mu.Unlock()

	if err := l.sendText(fmt.Sprintf("CONNECTED %d", id)); err != nil {
		l.closeClient(id, false)
		return
	}
	go l.tcpToWS(id, conn)
}

func (l *listener) handleServerClose(id uint32) {
	l.mu.Lock()
	st, ok := l.clients[id]
	l.mu.Unlock()
	if !ok {
		return
	}
	if st.closeOnce() {
		st.conn.Close()
	}
}

func (l *listener) closeClient(id uint32, sendClosed bool) {
	l.mu.Lock()
	st, ok := l.clients[id]
	if ok {
		delete(l.clients, id)
	}
	l.mu.Unlock()
	if !ok {
		return
	}
	if st.closeOnce() {
		st.conn.Close()
	}
	if sendClosed {
		_ = l.sendText(fmt.Sprintf("CLOSED %d", id))
	}
}

func (l *listener) handleBinary(data []byte) {
	if len(data) < 4 {
		return
	}
	id := binary.BigEndian.Uint32(data[:4])
	payload := data[4:]

	l.mu.Lock()
	st, ok := l.clients[id]
	l.mu.Unlock()
	if !ok {
		return
	}

	if len(payload) == 0 {
		return
	}
	if err := writeAll(st.conn, payload); err != nil {
		l.closeClient(id, true)
	}
}

func writeAll(w io.Writer, b []byte) error {
	written := 0
	for len(b) > written {
		n, err := w.Write(b[written:])
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (l *listener) tcpToWS(id uint32, conn net.Conn) {
	defer l.closeClient(id, true)
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out := make([]byte, 4+n)
			binary.BigEndian.PutUint32(out, id)
			copy(out[4:], buf[:n])
			if werr := l.sendBinary(out); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func parseUint32(s string) (uint32, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(v), nil
}

func (l *listener) run() {
	header := http.Header{"Sec-Websocket-Protocol": {"tcp-forwarder"}}
	ws, resp, err := websocket.DefaultDialer.Dial(l.wsURL, header)
	if err != nil {
		log.Printf("wstnl: could not connect websocket %s: %v", l.wsURL, err)
		if resp != nil {
			log.Printf("wstnl: response: %#v", resp)
		}
		return
	}
	l.mu.Lock()
	l.ws = ws
	l.mu.Unlock()

	log.Printf("wstnl listener connected: ws=%s target=%s", l.wsURL, l.target)
	if resp != nil {
		log.Printf("wstnl: ws response: %#v", resp)
	}
	defer func() {
		l.mu.Lock()
		close(l.done)
		if l.ws != nil {
			l.ws.Close()
		}
		l.ws = nil
		l.mu.Unlock()
	}()

	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			log.Printf("wstnl: websocket %s read error: %v", l.wsURL, err)
			return
		}
		if mt == websocket.TextMessage {
			fields := strings.Fields(string(data))
			if len(fields) >= 2 {
				id, perr := parseUint32(fields[1])
				if perr == nil {
					switch fields[0] {
					case "OPEN":
						go l.handleOpen(id)
					case "CLOSE":
						l.handleServerClose(id)
					}
				}
			}
		} else if mt == websocket.BinaryMessage {
			l.handleBinary(data)
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var debug bool
	var insecure bool

	flag.BoolVar(&debug, "debug", false, "turn on debugging")
	flag.BoolVar(&insecure, "insecure", false, "allow insecure TLS connections")
	flag.Parse()

	_ = debug

	args := flag.Args()
	var pairs [][2]string

	if len(args)%2 != 0 {
		log.Fatalf("expected arguments in pairs of \"websocket address\" \"tcp://host:port\"")
	}
	for i := 0; i+1 < len(args); i += 2 {
		pairs = append(pairs, [2]string{args[i], args[i+1]})
	}

	if len(pairs) == 0 {
		log.Fatalf("Usage: %s [options] <ws-url> <tcp://host:port> [<ws-url> <tcp://host:port> ...]\n", "ws_tunnel")
	}

	if insecure {
		websocket.DefaultDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	var wg sync.WaitGroup
	for _, pr := range pairs {
		l := newListener(pr[0], pr[1])
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.run()
		}()
	}
	wg.Wait()
}
