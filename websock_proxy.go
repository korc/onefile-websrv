package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"regexp"
	"sync"

	"github.com/gorilla/websocket"
)

type wsSink struct {
	ws  *websocket.Conn
	buf chan interface{}
}

func newWSSink(ws *websocket.Conn, bufSize int) *wsSink {
	if bufSize == 0 {
		bufSize = 4
	}
	ret := &wsSink{ws: ws, buf: make(chan interface{}, bufSize)}
	go ret.copyToWSLoop()
	return ret
}

func (s *wsSink) copyToWSLoop() {
	defer s.ws.Close()
	for {
		data := <-s.buf
		if data == nil {
			break
		}
		msgType := websocket.BinaryMessage
		switch data.(type) {
		case []byte:
		default:
			dataOut, err := json.Marshal(data)
			if err != nil {
				log.Printf("ERROR: could not marshal %#v: %s", data, err)
				continue
			}
			msgType = websocket.TextMessage
			data = dataOut
		}
		s.ws.WriteMessage(msgType, data.([]byte))
	}
}

func (s *wsSink) Close() {
	close(s.buf)
}

type wsProxyService struct {
	clients  map[uint32]*wsSink
	listener *wsSink
	seq      uint32
	lock     *sync.Mutex
}

func (svc *wsProxyService) Reset() {
	svc.lock.Lock()
	defer svc.lock.Unlock()
	if svc.listener != nil {
		svc.listener.Close()
		svc.listener = nil
	}
	for _, cl := range svc.clients {
		cl.Close()
	}
	svc.clients = make(map[uint32]*wsSink)
	svc.seq = 0
}

func (svc *wsProxyService) handleListener(ws *websocket.Conn) {
	svc.lock.Lock()
	svc.listener = newWSSink(ws, 32)
	svc.lock.Unlock()
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			log.Printf("ws-listener err: %s", err)
			break
		}
		if len(data) < 4 {
			log.Printf("ws-listener data too short(%d<4): %#v", len(data), data)
			break
		}
		clientId := binary.LittleEndian.Uint32(data)
		client, have := svc.clients[clientId]
		if !have {
			if len(data) > 4 {
				log.Printf("data for non-existing client %d:\n%s", clientId, hex.Dump(data[4:]))
			}
			continue
		}
		if len(data) == 4 {
			client.Close()
			svc.lock.Lock()
			delete(svc.clients, clientId)
			svc.lock.Unlock()
		} else {
			client.buf <- data[4:]
		}
	}
	svc.Reset()
}

func (svc *wsProxyService) handleClient(ws *websocket.Conn) {
	svc.lock.Lock()
	svc.seq += 1
	clientId := svc.seq
	svc.clients[clientId] = newWSSink(ws, 4)
	svc.lock.Unlock()
	defer ws.Close()
	svc.listener.buf <- map[string]interface{}{"connected": clientId}
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !websocket.IsCloseError(err, 1006) {
				log.Printf("ws err: %s", err)
			}
			break
		}
		if len(data) == 0 {
			break
		}
		msg := make([]byte, 4+len(data))
		binary.LittleEndian.PutUint32(msg, clientId)
		copy(msg[4:], data)
		svc.listener.buf <- msg
	}
	svc.closeClient(clientId)
}

func (svc *wsProxyService) closeClient(clientId uint32) {
	svc.lock.Lock()
	defer svc.lock.Unlock()
	if svc.listener != nil {
		msg := make([]byte, 4)
		binary.LittleEndian.PutUint32(msg, clientId)
		svc.listener.buf <- msg
	}
	delete(svc.clients, clientId)
}

var wsProxyList = map[string]*wsProxyService{}
var wsProxyListLock = &sync.Mutex{}

func getWsPrxSvc(name string) *wsProxyService {
	wsProxyListLock.Lock()
	defer wsProxyListLock.Unlock()
	prxSvc, have := wsProxyList[name]
	if !have {
		prxSvc = &wsProxyService{clients: make(map[uint32]*wsSink), lock: &sync.Mutex{}}
		wsProxyList[name] = prxSvc
	}
	return prxSvc
}

type wsProxyHandler struct {
	sc       *serverConfig
	name     string
	opts     map[string]string
	searchRe *regexp.Regexp
}

func (wsprx *wsProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := wsprx.name

	if wsprx.searchRe != nil {
		nameSrc := r.URL.Path
		nameExp := []byte{}
		for _, submatch := range wsprx.searchRe.FindAllStringSubmatchIndex(nameSrc, -1) {
			nameExp = wsprx.searchRe.ExpandString(nameExp, name, nameSrc, submatch)
		}
		name = string(nameExp)
	}
	prxSvc := getWsPrxSvc(name)
	isListener := wsprx.opts["listener"] != ""
	if isListener {
		prxSvc.Reset()
	} else {
		if prxSvc.listener == nil {
			w.WriteHeader(http.StatusBadGateway)
			wsprx.sc.logger.Log(logLevelWarning, "no ws-prx server connected", map[string]interface{}{"name": name})
			w.Write([]byte("no server to connect to"))
			return
		}
	}

	var respHeader http.Header
	for _, subproto := range r.Header.Values("Sec-Websocket-Protocol") {
		if respHeader == nil {
			respHeader = make(http.Header)
		}
		respHeader.Add("Sec-Websocket-Protocol", subproto)
	}
	ws, err := upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		wsprx.sc.logger.Log(logLevelError, "cannot upgrade to websocket", map[string]interface{}{"error": err})
		return
	}
	defer ws.Close()

	if isListener {
		prxSvc.handleListener(ws)
	} else {
		prxSvc.handleClient(ws)
	}
}

func newWSProxyHandler(params string, cfg *serverConfig) (handler *wsProxyHandler, err error) {
	opts, name := parseCurlyParams(params)
	handler = &wsProxyHandler{sc: cfg, name: name, opts: opts}
	if pat, have := opts["re"]; have {
		handler.searchRe, err = regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
	}
	return
}

func init() {
	addProtocolHandler("ws-proxy", func(_, params string, cfg *serverConfig) (http.Handler, error) {
		cfg.logger.Log(logLevelInfo, "new WS proxy handler", map[string]interface{}{"parameters": params})
		return newWSProxyHandler(params, cfg)
	})
}
