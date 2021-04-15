package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
	return true
}}

type execConn struct {
	cmd          *exec.Cmd
	shellCommand string
	rdDeadLine   time.Time
	wrDeadline   time.Time
	stdin        io.WriteCloser
	stdout       io.ReadCloser
	stderr       io.ReadCloser
}

func (e *execConn) Network() string {
	return "exec"
}

func (e *execConn) String() string {
	return e.shellCommand
}

func (e *execConn) Read(b []byte) (n int, err error) {
	return e.stdout.Read(b)
}

func (e *execConn) Write(b []byte) (n int, err error) {
	return e.stdin.Write(b)
}

func (e *execConn) LocalAddr() net.Addr {
	return e
}

func (e *execConn) RemoteAddr() net.Addr {
	return e
}

func (e *execConn) SetDeadline(t time.Time) error {
	log.Printf("not implemented: execConn.SetDeadline(%#v)", t)
	e.rdDeadLine = t
	e.wrDeadline = t
	return nil
}

func (e *execConn) SetReadDeadline(t time.Time) error {
	log.Printf("not implemented: execConn.SetReadDeadline(%#v)", t)
	e.rdDeadLine = t
	return nil
}

func (e *execConn) SetWriteDeadline(t time.Time) error {
	log.Printf("not implemented: execConn.SetWriteDeadline(%#v)", t)
	e.wrDeadline = t
	return nil
}

func newExecConn(name string, arg ...string) (conn *execConn, err error) {
	cmd := exec.Command(name, arg...)
	conn = &execConn{
		cmd:          cmd,
		shellCommand: name,
	}
	if conn.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if conn.stdout, err = cmd.StdoutPipe(); err != nil {
		return nil, err
	}
	if conn.stderr, err = cmd.StderrPipe(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() {
		io.Copy(os.Stderr, conn.stderr)
	}()
	return conn, nil
}

func (e *execConn) Close() error {
	e.stdin.Close()
	return e.cmd.Wait()
}

type webSocketHandler struct {
	connectParams         map[string]string
	handlerParams         string
	readTimeout           time.Duration
	proto                 string
	address               string
	tlsConfig             *tls.Config
	messageType           int
	injectRequestNrHeader string
}

func newWebSocketHandler(params string) *webSocketHandler {
	wsh := &webSocketHandler{
		readTimeout: 60 * time.Second,
		proto:       "tcp",
		messageType: websocket.BinaryMessage,
	}
	wsh.connectParams, wsh.handlerParams = parseCurlyParams(params)
	wsh.chooseProtoAddr(wsh.handlerParams)
	if msgType := wsh.connectParams["type"]; msgType == "text" {
		wsh.messageType = websocket.TextMessage
	}
	wsh.injectRequestNrHeader = wsh.connectParams["injReqNrHdr"]
	return wsh
}

func (wsh *webSocketHandler) chooseProtoAddr(handlerParams string) *webSocketHandler {
	address := handlerParams
	if address[:5] == "unix:" {
		wsh.proto = "unix"
		address = address[5:]
	} else if address[:1] == "/" || address[:1] == "@" {
		wsh.proto = "unix"
	}
	if address[:4] == "tls:" {
		if wsh.tlsConfig == nil {
			wsh.tlsConfig = &tls.Config{}
		}
		if wsh.connectParams["tlsVerify"] == "0" {
			wsh.tlsConfig.InsecureSkipVerify = true
		}
		address = address[4:]
	}
	wsh.address = address
	return wsh
}

func (wsh *webSocketHandler) dialRemote() (conn net.Conn, err error) {
	if strings.HasPrefix(wsh.address, "exec:") {
		execString := wsh.address[5:]
		shCmd := wsh.connectParams["sh"]
		if shCmd == "" {
			shCmd = "/bin/sh"
		}
		shArgs := make([]string, 0)
		if _, ok := wsh.connectParams["no-c"]; !ok {
			shArgs = append(shArgs, "-c")
		}
		shArgs = append(shArgs, execString)
		return newExecConn(shCmd, shArgs...)
	}
	if wsh.tlsConfig != nil {
		return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, wsh.proto, wsh.address, wsh.tlsConfig)
	}
	return net.DialTimeout(wsh.proto, wsh.address, 10*time.Second)
}

func (wsh *webSocketHandler) setReadTimeout(d time.Duration) *webSocketHandler {
	wsh.readTimeout = d
	return wsh
}

func (wsh *webSocketHandler) wsReader(r *http.Request, c *websocket.Conn, dataFromWS chan []byte,
	onceDone *sync.Once, keepRunning *atomic.Value, stopRunning func()) {
	defer logf(r, logLevelDebug, "WSReader finished")
	defer onceDone.Do(stopRunning)
	defer close(dataFromWS)
	injectRequestNrHeader := wsh.injectRequestNrHeader
	for keepRunning.Load().(bool) {
		msgType, data, err := c.ReadMessage()
		if err != nil {
			if err == io.EOF {
				logf(r, logLevelVerbose, "WS EOF")
			} else {
				ll := logLevelWarning
				if !keepRunning.Load().(bool) && strings.Contains(err.Error(), "use of closed network connection") {
					ll = logLevelVerbose
				}
				logf(r, ll, "Failed to read from WS: %#v (%s)", err, err)
			}
			break
		}
		if msgType != wsh.messageType {
			logf(r, logLevelWarning, "Not message type does not match: %#v != ", msgType, wsh.messageType)
		}
		if injectRequestNrHeader != "" {
			if idx := bytes.Index(data, []byte("\r\n")); idx == -1 {
				logf(r, logLevelWarning, "Inject request nr header set(%#v), but no \\r\\n in incoming data: %#v", injectRequestNrHeader, string(data))
			} else {
				data = bytes.Join([][]byte{data[:idx], []byte(fmt.Sprintf("\r\n%s: %v", injectRequestNrHeader, r.Context().Value("request-num"))), data[idx:]}, []byte{})
			}
			injectRequestNrHeader = ""
		}
		dataFromWS <- data
	}
}

func (wsh *webSocketHandler) wsWriter(r *http.Request, c *websocket.Conn, dataFromConn chan []byte,
	onceDone *sync.Once, keepRunning *atomic.Value, stopRunning func()) {
	defer logf(r, logLevelDebug, "WSWriter finished")
	defer onceDone.Do(stopRunning)
loop:
	for keepRunning.Load().(bool) {
		select {
		case data := <-dataFromConn:
			logf(r, logLevelDebug, "data (nil=%#v) from conn", data == nil)
			if data == nil {
				break loop
			}
			if err := c.WriteMessage(wsh.messageType, data); err != nil {
				logf(r, logLevelError, "Error writing to WS: %s", err)
				break loop
			}
		case <-time.After(wsh.readTimeout):
			logf(r, logLevelVerbose, "No input from conn in %s", wsh.readTimeout)
		}
	}
}

func (wsh *webSocketHandler) sockReader(r *http.Request, conn net.Conn, dataFromConn chan []byte,
	onceDone *sync.Once, keepRunning *atomic.Value, stopRunning func()) {
	defer logf(r, logLevelDebug, "SockReader finished")
	defer onceDone.Do(stopRunning)
	defer close(dataFromConn)
	for keepRunning.Load().(bool) {
		data := make([]byte, 8192)
		nRead, err := conn.Read(data)
		if err != nil {
			if err == io.EOF {
				logf(r, logLevelVerbose, "Socket EOF")
			} else {
				logf(r, logLevelWarning, "Cannot read from socket: %s", err)
			}
			break
		}
		dataFromConn <- data[:nRead]
	}
}

func (wsh *webSocketHandler) sockWriter(r *http.Request, c *websocket.Conn, conn net.Conn, dataFromWS chan []byte,
	onceDone *sync.Once, keepRunning *atomic.Value, stopRunning func()) {
	defer logf(r, logLevelVerbose, "SockWriter finished")
	defer onceDone.Do(stopRunning)
	checkingAlive := false
loop:
	for keepRunning.Load().(bool) {
		select {
		case data := <-dataFromWS:
			logf(r, logLevelDebug, "data (nil=%#v) from WS", data == nil)
			if data == nil {
				break loop
			}
			for len(data) > 0 {
				nWrote, err := conn.Write(data)
				if err != nil {
					logf(r, logLevelWarning, "Error writing to socket: %s", err)
					onceDone.Do(stopRunning)
					break
				}
				data = data[nWrote:]
			}
		case <-time.After(wsh.readTimeout):
			logf(r, logLevelVerbose, "No data from WS in %s (checkingAlive=%#v)", wsh.readTimeout, checkingAlive)
			if checkingAlive {
				logf(r, logLevelWarning, "Alive check failed.")
				onceDone.Do(stopRunning)
				break loop
			} else {
				checkingAlive = true
				c.SetPongHandler(func(appData string) error {
					checkingAlive = false
					logf(r, logLevelVerbose, "Alive check succeeded: %#v", appData)
					return nil
				})
				if err := c.WriteControl(websocket.PingMessage, []byte("are you alive?"), time.Now().Add(time.Second)); err != nil {
					logf(r, logLevelError, "Could not send ping.")
					break loop
				} else {
					logf(r, logLevelDebug, "Sent ping.")
				}
			}
		}
	}

}

func (wsh *webSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer logf(r, logLevelVerbose, "WS<->Sock handler finished")
	var respHeader http.Header
	if subproto := r.Header.Get("Sec-Websocket-Protocol"); subproto != "" {
		logf(r, logLevelInfo, "Sec-Websocket-Protocol: %#v", subproto)
		respHeader = http.Header{"Sec-Websocket-Protocol": {subproto}}
	}
	c, err := upgrader.Upgrade(w, r, respHeader)
	if err != nil {
		logf(r, logLevelError, "Could not upgrade websocket: %s", err)
		return
	}
	defer c.Close()
	conn, err := wsh.dialRemote()
	if err != nil {
		logf(r, logLevelError, "Cannot connect to %#v: %s", wsh.address, err)
		return
	}
	defer conn.Close()
	if rl := r.Context().Value(remoteLoggerContext); rl != nil {
		_ = rl.(*RemoteLogger).log("ws-connected", map[string]interface{}{
			"RequestNum": r.Context().Value("request-num"),
			"LocalAddr":  conn.LocalAddr().String(),
			"RemoteAddr": conn.RemoteAddr().String(),
			"Protocol":   wsh.proto,
		})
		log.Printf("remote logger: %#v", rl)
	}

	var onceDone sync.Once
	var keepRunning atomic.Value
	keepRunning.Store(true)
	done := make(chan struct{})
	stopRunning := func() {
		keepRunning.Store(false)
		time.Sleep(100 * time.Millisecond)
		close(done)
	}

	dataFromConn := make(chan []byte)
	dataFromWS := make(chan []byte)

	go wsh.wsWriter(r, c, dataFromConn, &onceDone, &keepRunning, stopRunning)
	go wsh.sockWriter(r, c, conn, dataFromWS, &onceDone, &keepRunning, stopRunning)
	go wsh.sockReader(r, conn, dataFromConn, &onceDone, &keepRunning, stopRunning)
	go wsh.wsReader(r, c, dataFromWS, &onceDone, &keepRunning, stopRunning)
	<-done
}
