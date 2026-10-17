package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/text/encoding/ianaindex"

	"github.com/gorilla/websocket"
)

type clientOutbound struct {
	msgType int
	data    []byte
}

type wstnlSession struct {
	id             uint32
	pool           *wstnlPool
	encoding       string
	ws             *websocket.Conn
	writeMu        sync.Mutex
	writeCh        chan clientOutbound
	writerDone     chan struct{}
	outbound       [][]byte
	closeOnce      sync.Once
	done           chan struct{}
	closedCh       chan struct{}
	opened         bool
	closed         bool
	lastClientText atomic.Bool
	packetsIn      atomic.Uint64
	bytesIn        atomic.Uint64
	packetsOut     atomic.Uint64
	bytesOut       atomic.Uint64
}

type wstnlListener struct {
	pool       *wstnlPool
	ws         *websocket.Conn
	writeMu    sync.Mutex
	closeOnce  sync.Once
	done       chan struct{}
	packetsIn  atomic.Uint64
	bytesIn    atomic.Uint64
	packetsOut atomic.Uint64
	bytesOut   atomic.Uint64
}

type wstnlPool struct {
	name     string
	lock     sync.Mutex
	listener *wstnlListener
	sessions map[uint32]*wstnlSession
	pending  map[uint32]chan error
}

var wstnlPools = make(map[string]*wstnlPool)
var wstnlPoolsLock = &sync.Mutex{}

func getWstnlPool(name string) *wstnlPool {
	wstnlPoolsLock.Lock()
	defer wstnlPoolsLock.Unlock()
	if p, have := wstnlPools[name]; have {
		return p
	}
	p := &wstnlPool{
		name:     name,
		sessions: make(map[uint32]*wstnlSession),
		pending:  make(map[uint32]chan error),
	}
	wstnlPools[name] = p
	return p
}

type wstnlHandler struct {
	poolName string
	cfg      *serverConfig
	encoding string
}

func isTcpForwarderRequest(r *http.Request) bool {
	for _, sp := range r.Header.Values("Sec-Websocket-Protocol") {
		for _, part := range strings.Split(sp, ",") {
			if strings.TrimSpace(part) == "tcp-forwarder" {
				return true
			}
		}
	}
	return false
}

func (l *wstnlListener) isAlive() bool {
	select {
	case <-l.done:
		return false
	default:
		return true
	}
}

func (l *wstnlListener) sendText(s string) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if !l.isAlive() {
		return errors.New("listener closed")
	}
	l.packetsOut.Add(1)
	l.bytesOut.Add(uint64(len(s)))
	return l.ws.WriteMessage(websocket.TextMessage, []byte(s))
}

func (l *wstnlListener) sendBinary(b []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if !l.isAlive() {
		return errors.New("listener closed")
	}
	cp := append([]byte(nil), b...)
	l.packetsOut.Add(1)
	l.bytesOut.Add(uint64(len(cp)))
	return l.ws.WriteMessage(websocket.BinaryMessage, cp)
}

func (l *wstnlListener) close() {
	l.closeOnce.Do(func() {
		log.Printf("wstnl listener disconnected: pool=%s packets_in=%d bytes_in=%d packets_out=%d bytes_out=%d",
			l.pool.name, l.packetsIn.Load(), l.bytesIn.Load(), l.packetsOut.Load(), l.bytesOut.Load())
		close(l.done)
		l.ws.Close()
	})
}

func (s *wstnlSession) closeWS() {
	s.closeOnce.Do(func() {
		log.Printf("wstnl client disconnected: pool=%s session=%d packets_in=%d bytes_in=%d packets_out=%d bytes_out=%d",
			s.pool.name, s.id, s.packetsIn.Load(), s.bytesIn.Load(), s.packetsOut.Load(), s.bytesOut.Load())
		// Signal any senders blocked on writeCh to stop first, then take the
		// lock. This avoids deadlocking against a sender that is blocked on a
		// full writeCh while holding writeMu.
		close(s.closedCh)
		s.writeMu.Lock()
		ch := s.writeCh
		s.writeCh = nil
		ws := s.ws
		s.ws = nil
		writerDone := s.writerDone
		s.writeMu.Unlock()
		// Close the websocket before waiting for the writer: if the writer is
		// blocked in WriteMessage (e.g. the client connected but is not
		// reading), closing the connection unblocks it. Doing it the other way
		// around deadlocks.
		if ws != nil {
			ws.Close()
		}
		if ch != nil {
			close(ch)
		}
		if writerDone != nil {
			<-writerDone
		}
		close(s.done)
	})
}

func (s *wstnlSession) setWS(ws *websocket.Conn) {
	s.writeMu.Lock()
	select {
	case <-s.closedCh:
		// The session was already closed (e.g. the listener went away) before
		// the client upgraded; do not start a writer that nobody will stop.
		s.writeMu.Unlock()
		ws.Close()
		return
	default:
	}
	s.ws = ws
	s.writeCh = make(chan clientOutbound, 1024)
	s.writerDone = make(chan struct{})
	go func(ch chan clientOutbound) {
		defer close(s.writerDone)
		for out := range ch {
			s.packetsOut.Add(1)
			s.bytesOut.Add(uint64(len(out.data)))
			ws.WriteMessage(out.msgType, out.data)
		}
	}(s.writeCh)
	for _, data := range s.outbound {
		s.queuePayloadLocked(data)
	}
	s.outbound = nil
	s.writeMu.Unlock()
	go s.readClientToListener()
}

func (s *wstnlSession) enqueueOutbound(data []byte) {
	cp := append([]byte(nil), data...)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.closedCh:
		return
	default:
	}
	if s.ws == nil || s.writeCh == nil {
		s.outbound = append(s.outbound, cp)
		return
	}
	s.queuePayloadLocked(cp)
}

func (s *wstnlSession) queuePayloadLocked(payload []byte) {
	msgType := websocket.BinaryMessage
	data := payload
	if s.lastClientText.Load() {
		if dec, err := decodePayload(s.encoding, payload); err == nil {
			msgType = websocket.TextMessage
			data = []byte(dec)
		}
	}
	const chunkSize = 16 * 1024
	send := func(out clientOutbound) bool {
		select {
		case s.writeCh <- out:
			return true
		case <-s.closedCh:
			return false
		}
	}
	if len(data) == 0 {
		send(clientOutbound{msgType: msgType, data: data})
		return
	}
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := append([]byte(nil), data[off:end]...)
		if !send(clientOutbound{msgType: msgType, data: chunk}) {
			return
		}
	}
}

func (p *wstnlPool) getListener() *wstnlListener {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.listener
}

func (p *wstnlPool) handleOpened(id uint32) {
	p.lock.Lock()
	ch, pending := p.pending[id]
	if s, have := p.sessions[id]; have {
		s.opened = true
	}
	if pending {
		delete(p.pending, id)
	}
	p.lock.Unlock()
	if pending {
		select {
		case ch <- nil:
		default:
		}
	}
}

func (p *wstnlPool) handleClosedByListener(id uint32) {
	p.lock.Lock()
	s, haveSession := p.sessions[id]
	if haveSession {
		delete(p.sessions, id)
	}
	ch, havePending := p.pending[id]
	if havePending {
		delete(p.pending, id)
	}
	p.lock.Unlock()
	if haveSession {
		s.closeWS()
	}
	if havePending {
		select {
		case ch <- errors.New("closed by listener"):
		default:
		}
	}
}

func (p *wstnlPool) newSessionID() uint32 {
	for {
		var b [4]byte
		_, _ = rand.Read(b[:])
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		p.lock.Lock()
		_, usedSession := p.sessions[id]
		_, usedPending := p.pending[id]
		p.lock.Unlock()
		if !usedSession && !usedPending {
			return id
		}
	}
}

func (p *wstnlPool) removePending(id uint32) {
	p.lock.Lock()
	delete(p.pending, id)
	delete(p.sessions, id)
	p.lock.Unlock()
}

func (p *wstnlPool) handleClientDisconnect(id uint32) {
	p.lock.Lock()
	s, have := p.sessions[id]
	if have {
		delete(p.sessions, id)
	}
	listener := p.listener
	p.lock.Unlock()
	if have {
		s.writeMu.Lock()
		already := s.closed
		s.closed = true
		s.writeMu.Unlock()
		s.closeWS()
		if !already && listener != nil && listener.isAlive() {
			listener.sendText(fmt.Sprintf("CLOSE %d", id))
		}
	}
}

func (p *wstnlPool) handleListenerBinary(data []byte) {
	if len(data) < 4 {
		return
	}
	id := binary.BigEndian.Uint32(data[:4])
	payload := data[4:]
	p.lock.Lock()
	s, have := p.sessions[id]
	p.lock.Unlock()
	if !have {
		return
	}
	s.enqueueOutbound(payload)
}

func (p *wstnlPool) handleListenerGone(l *wstnlListener) {
	p.lock.Lock()
	if p.listener != l {
		p.lock.Unlock()
		return
	}
	p.listener = nil
	sessions := make(map[uint32]*wstnlSession, len(p.sessions))
	for k, v := range p.sessions {
		sessions[k] = v
		delete(p.sessions, k)
	}
	pending := make(map[uint32]chan error, len(p.pending))
	for k, v := range p.pending {
		pending[k] = v
		delete(p.pending, k)
	}
	p.lock.Unlock()
	for _, s := range sessions {
		s.closeWS()
	}
	for _, ch := range pending {
		select {
		case ch <- errors.New("listener gone"):
		default:
		}
	}
}

func (s *wstnlSession) readClientToListener() {
	defer s.pool.handleClientDisconnect(s.id)
	ws := s.ws
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			break
		}
		s.lastClientText.Store(mt == websocket.TextMessage)
		s.packetsIn.Add(1)
		s.bytesIn.Add(uint64(len(data)))
		l := s.pool.getListener()
		if l == nil {
			break
		}
		const chunkSize = 16 * 1024
		sendFailed := false
		if len(data) == 0 {
			out := make([]byte, 4)
			binary.BigEndian.PutUint32(out, s.id)
			if err := l.sendBinary(out); err != nil {
				break
			}
		}
		for off := 0; off < len(data); off += chunkSize {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			out := make([]byte, 4+(end-off))
			binary.BigEndian.PutUint32(out, s.id)
			copy(out[4:], data[off:end])
			if err := l.sendBinary(out); err != nil {
				sendFailed = true
				break
			}
		}
		if sendFailed {
			break
		}
	}
}

func (h *wstnlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	poolName := h.poolName
	if poolName == "" {
		poolName = r.URL.Path
	}
	pool := getWstnlPool(poolName + " " + r.URL.Path)

	if isTcpForwarderRequest(r) {
		pool.lock.Lock()
		l := pool.listener
		if l != nil && l.isAlive() {
			pool.lock.Unlock()
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("409 Request conflict\n"))
			return
		}
		if l != nil {
			l.close()
			pool.listener = nil
		}
		pool.lock.Unlock()

		respHeader := http.Header{"Sec-Websocket-Protocol": {"tcp-forwarder"}}
		ws, err := upgrader.Upgrade(w, r, respHeader)
		if err != nil {
			log.Printf("wstnl: listener upgrade failed: %s", err)
			return
		}
		listener := &wstnlListener{
			pool: pool,
			ws:   ws,
			done: make(chan struct{}),
		}
		pool.lock.Lock()
		if pool.listener != nil && pool.listener.isAlive() {
			pool.lock.Unlock()
			ws.Close()
			return
		}
		pool.listener = listener
		pool.lock.Unlock()
		log.Printf("wstnl listener connected: pool=%s", pool.name)

		defer func() {
			listener.close()
			pool.handleListenerGone(listener)
		}()
		for {
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				break
			}
			listener.packetsIn.Add(1)
			listener.bytesIn.Add(uint64(len(data)))
			switch msgType {
			case websocket.TextMessage:
				fields := strings.Fields(string(data))
				if len(fields) >= 2 {
					id, err := parseUint32(fields[1])
					if err == nil {
						switch fields[0] {
						case "CONNECTED", "OPENED":
							pool.handleOpened(id)
						case "FAILED", "CLOSED":
							pool.handleClosedByListener(id)
						}
					}
				}
			case websocket.BinaryMessage:
				pool.handleListenerBinary(data)
			}
		}
		return
	}

	// client
	pool.lock.Lock()
	listener := pool.listener
	alive := listener != nil && listener.isAlive()
	pool.lock.Unlock()
	if !alive {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 Not Found\n"))
		return
	}

	id := pool.newSessionID()
	openedCh := make(chan error, 1)
	session := &wstnlSession{
		id:       id,
		pool:     pool,
		encoding: h.encoding,
		done:     make(chan struct{}),
		closedCh: make(chan struct{}),
	}
	pool.lock.Lock()
	pool.sessions[id] = session
	pool.pending[id] = openedCh
	pool.lock.Unlock()

	if err := listener.sendText(fmt.Sprintf("OPEN %d", id)); err != nil {
		pool.removePending(id)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("503 Service Unavailable\n"))
		return
	}

	select {
	case err := <-openedCh:
		if err != nil {
			pool.removePending(id)
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("503 Service Unavailable\n"))
			return
		}
	case <-listener.done:
		pool.removePending(id)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("503 Service Unavailable\n"))
		return
	case <-time.After(5 * time.Second):
		pool.removePending(id)
		listener.sendText(fmt.Sprintf("CLOSE %d", id))
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("503 Service Unavailable\n"))
		return
	}

	// ensure session exists and opened
	pool.lock.Lock()
	if s, have := pool.sessions[id]; have {
		s.opened = true
	}
	pool.lock.Unlock()

	respHeader := http.Header{}
	ws, err := upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		pool.handleClientDisconnect(id)
		return
	}
	session.setWS(ws)
	log.Printf("wstnl client connected: pool=%s session=%d", pool.name, id)

	// block until session closes
	<-session.done
}

func decodePayload(enc string, data []byte) (string, error) {
	if enc == "" {
		enc = "utf-8"
	}
	e, err := ianaindex.IANA.Encoding(enc)
	if err != nil {
		e, _ = ianaindex.IANA.Encoding("utf-8")
	}
	out, err := e.NewDecoder().Bytes(data)
	if err != nil {
		return "", err
	}
	return string(out), nil
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

func init() {
	addProtocolHandler("wstnl", func(urlPath, params string, cfg *serverConfig) (http.Handler, error) {
		opts, poolName := parseCurlyParams(params)
		if poolName == "" {
			poolName = urlPath
		}
		enc := opts["enc"]
		if enc == "" {
			enc = "utf-8"
		}
		return &wstnlHandler{poolName: poolName, cfg: cfg, encoding: enc}, nil
	})
}
