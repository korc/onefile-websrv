package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var debug = false

type wsClientHandler struct {
	ws          *websocket.Conn
	wsBuf       chan []byte
	proto       string
	addr        string
	clients     map[uint32]net.Conn
	clientsLock *sync.Mutex
}

func (h *wsClientHandler) toWSLoop() {
	defer h.ws.Close()
	for {
		data := <-h.wsBuf
		if data == nil {
			break
		}
		if err := h.ws.WriteMessage(websocket.BinaryMessage, data); err != nil {
			log.Printf("Error: could not write to server socket: %s", err)
			break
		}
	}
}

func (h *wsClientHandler) clientToWS(clientId uint32, conn net.Conn) error {
	defer conn.Close()
	defer h.closeClient(clientId)
	for {
		readBuf := make([]byte, 16*1024)
		n, err := conn.Read(readBuf)
		if debug {
			log.Printf("conn.Read n=%d clientId=%d conn=%v err=%v data:\n%s", n, clientId, conn, err, hex.Dump(readBuf[:n]))
		}
		if err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				log.Printf("error reading connection %d: %s", clientId, err)
			} else {
				log.Printf("connection %d closed", clientId)
			}
			return err
		}
		h.clientsLock.Lock()
		_, have := h.clients[clientId]
		h.clientsLock.Unlock()
		if !have {
			break
		}
		writeBuf := make([]byte, 4+n)
		binary.LittleEndian.PutUint32(writeBuf, clientId)
		copy(writeBuf[4:], readBuf)
		h.wsBuf <- writeBuf
		if n == 0 {
			break
		}
	}
	return nil
}

func (h *wsClientHandler) writeAll(w io.Writer, b []byte) error {
	written := 0
	for len(b) > written {
		n, err := w.Write(b)
		written += n
		if err != nil {
			log.Printf("Could not write all bytes (%d/%d) to conn: %s", written, len(b), err)
			return err
		}
		b = b[n:]
	}
	return nil
}

type WSPrxCmd struct {
	Connected uint32 `json:"connected,omitempty"`
}

func (h *wsClientHandler) addClient(clientId uint32) (conn net.Conn, err error) {
	log.Printf("client %d connected", clientId)
	conn, err = net.Dial(h.proto, h.addr)
	if err != nil {
		log.Printf("Could not connect to %s %s: %s", h.proto, h.addr, err)
		h.closeClient(clientId)
	}
	h.clientsLock.Lock()
	h.clients[clientId] = conn
	h.clientsLock.Unlock()
	go h.clientToWS(clientId, conn)
	return
}

func (h *wsClientHandler) closeClient(clientId uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, clientId)
	h.wsBuf <- buf
	h.clientsLock.Lock()
	delete(h.clients, clientId)
	h.clientsLock.Unlock()
}

func (h *wsClientHandler) readMessages() error {
	for {
		msgType, buf, err := h.ws.ReadMessage()
		if debug {
			log.Printf("ws.ReadMessage type=%d err=%v, data:\n%s", msgType, err, hex.Dump(buf))
		}
		if err != nil {
			return err
		}
		if msgType == websocket.TextMessage {
			var cmd WSPrxCmd
			if err := json.Unmarshal(buf, &cmd); err != nil {
				log.Printf("could not unmarshal: %q", string(buf))
				continue
			}
			if debug {
				log.Printf("received command: %#v", cmd)
			}
			h.addClient(cmd.Connected)
			continue
		} else if msgType != websocket.BinaryMessage {
			log.Printf("warning: message type[%#v] not a text/binary: %#v", msgType, string(buf))
		}
		if len(buf) < 4 {
			log.Printf("message too short (%d<4): %#v", len(buf), buf)
			continue
		}
		clientId := binary.LittleEndian.Uint32(buf)
		h.clientsLock.Lock()
		conn, have := h.clients[clientId]
		h.clientsLock.Unlock()
		if len(buf) == 4 {
			if !have {
				continue
			}
			log.Printf("client %d disconnected", clientId)
			conn.Close()
			h.clientsLock.Lock()
			delete(h.clients, clientId)
			h.clientsLock.Unlock()
		}
		if !have {
			if debug {
				log.Printf("client %d not found, connecting to %s / %s", clientId, h.proto, h.addr)
			}
			conn, err = h.addClient(clientId)
			if err != nil {
				return err
			}
		}
		go h.writeAll(conn, buf[4:])
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var (
		wsUrl       string
		connAddr    string
		headerFlags ArrayFlag
	)
	flag.StringVar(&wsUrl, "ws", "", "WebSocket URL")
	flag.StringVar(&connAddr, "connect", "", "connect target address")
	flag.Var(&headerFlags, "header", "request headers (ex: 'User-Agent: test'))")
	flag.BoolVar(&debug, "debug", false, "turn on debugging")
	flag.Parse()

	if wsUrl == "" || connAddr == "" {
		log.Fatalf("Need to set -ws and -connect options")
	}

	wsHeaders := make(http.Header)
	for _, hdr := range headerFlags {
		idx := strings.Index(hdr, ": ")
		if idx == -1 {
			log.Fatalf("no ': ' in header %#v", hdr)
		}
		wsHeaders.Add(hdr[:idx], hdr[idx+2:])
	}

	ws, resp, err := websocket.DefaultDialer.Dial(wsUrl, wsHeaders)
	if err != nil {
		log.Fatalf("could not connect websocket: %s", err)
	}
	log.Printf("connected to websocket %s", wsUrl)
	if debug {
		log.Printf("WS response: %#v", resp)
	}

	proto := "tcp"
	if strings.HasPrefix(connAddr, "unix:") {
		proto = "unix"
		connAddr = connAddr[5:]
	} else if strings.HasPrefix(connAddr, "/") {
		proto = "unix"
	}

	clients := &wsClientHandler{
		ws: ws, clients: make(map[uint32]net.Conn),
		clientsLock: &sync.Mutex{},
		proto:       proto, addr: connAddr,
		wsBuf: make(chan []byte, 32),
	}
	go clients.toWSLoop()
	if err := clients.readMessages(); err != nil {
		log.Fatalf("error reading messages: %s", err)
	}
}
