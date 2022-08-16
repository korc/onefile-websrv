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

	"github.com/gorilla/websocket"
)

var debug = false

type wsClientHandler struct {
	ws      *websocket.Conn
	wsBuf   chan []byte
	proto   string
	addr    string
	clients map[uint32]net.Conn
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
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			log.Printf("Could not write all bytes to conn: %s", err)
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
	h.clients[clientId] = conn
	go h.clientToWS(clientId, conn)
	return
}

func (h *wsClientHandler) closeClient(clientId uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, clientId)
	h.wsBuf <- buf
	delete(h.clients, clientId)
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
		conn, have := h.clients[clientId]
		if len(buf) == 4 {
			if !have {
				continue
			}
			log.Printf("client %d disconnected", clientId)
			conn.Close()
			delete(h.clients, clientId)
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

	clients := &wsClientHandler{
		ws: ws, clients: make(map[uint32]net.Conn),
		proto: "tcp", addr: connAddr,
		wsBuf: make(chan []byte, 32),
	}
	go clients.toWSLoop()
	if err := clients.readMessages(); err != nil {
		log.Fatalf("error reading messages: %s", err)
	}
}