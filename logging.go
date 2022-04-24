package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

type logLevel int

const (
	logLevelFatal logLevel = iota
	logLevelError
	logLevelWarning
	logLevelInfo
	logLevelVerbose
	logLevelDebug
)

var logLevelStr = []string{"FATAL", "ERROR", "WARNING", "INFO", "VERBOSE", "DEBUG"}
var currentLogLevel = logLevelDebug

type serverLogger interface {
	Log(level logLevel, message string, args map[string]interface{})
	SetLogLevel(level logLevel)
}

type simpleLogger struct {
	currentLevel logLevel
}

func (l *simpleLogger) Log(level logLevel, msg string, args map[string]interface{}) {
	if level > l.currentLevel {
		return
	}
	log.Output(2, fmt.Sprintf("[%s]: %s: %v", logLevelStr[level], msg, args))
	if level == logLevelFatal {
		os.Exit(1)
	}
}

func (l *simpleLogger) SetLogLevel(level logLevel) {
	l.currentLevel = level
}

// HTTPLogger : HTTP handler which logs requests and replies
type HTTPLogger struct {
	logEntryNumber uint64
	DefaultHandler http.Handler
	remoteLogger   *RemoteLogger
}

// LoggedResponseWriter : http.ResponseWriter which keeps track of status and bytes
type LoggedResponseWriter struct {
	origWriter   http.ResponseWriter
	Status       int
	BytesWritten int
}

// NewLoggedResponseWriter : create new LoggedResponseWriter instance
func NewLoggedResponseWriter(w http.ResponseWriter) *LoggedResponseWriter {
	return &LoggedResponseWriter{origWriter: w}
}

// Header : return headers of original writer
func (lw *LoggedResponseWriter) Header() http.Header {
	return lw.origWriter.Header()
}

// WriteHeader : call original writer's WriteHeader, record status
func (lw *LoggedResponseWriter) WriteHeader(status int) {
	lw.Status = status
	lw.origWriter.WriteHeader(status)
}

func (lw *LoggedResponseWriter) Write(buf []byte) (int, error) {
	lw.BytesWritten += len(buf)
	return lw.origWriter.Write(buf)
}

// Hijack : call original writer's Hijack
func (lw *LoggedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return lw.origWriter.(http.Hijacker).Hijack()
}

// NewHTTPLogger : create new instance of HTTPLogger handler
func NewHTTPLogger(h http.Handler, rl *RemoteLogger) *HTTPLogger {
	if h == nil {
		h = http.DefaultServeMux
	}
	return &HTTPLogger{DefaultHandler: h, remoteLogger: rl}
}

type RemoteLogger struct {
	RemoteLogURL string
	HTTPClient   *http.Client
}

func (rl *RemoteLogger) log(logType string, msg interface{}) error {
	logData, err := json.Marshal(struct {
		Type    string      `json:"type"`
		Stamp   time.Time   `json:"stamp"`
		Message interface{} `json:"message"`
	}{logType, time.Now(), msg})
	if err != nil {
		return err
	}
	go func() {
		if resp, err := rl.HTTPClient.Post(rl.RemoteLogURL, "application/json", bytes.NewBuffer(logData)); err != nil {
			logf(nil, logLevelError, "Cannot submit log[%s]: %s (%#v)", logType, err, resp)
		} else {
			if err := resp.Body.Close(); err != nil {
				logf(nil, logLevelWarning, "Cannot close body of log submit: %s", err)
			}
		}
	}()
	return nil
}

func (hl *HTTPLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	myEntryNr := atomic.AddUint64(&hl.logEntryNumber, 1)
	lw := NewLoggedResponseWriter(w)
	ctx := context.WithValue(r.Context(), requestNumberContext, myEntryNr)
	newReq := r.WithContext(ctx)
	requestLogged := false
	if hl.remoteLogger != nil {
		ctx = context.WithValue(ctx, remoteLoggerContext, hl.remoteLogger)
		newReq = newReq.WithContext(ctx)
		if err := hl.remoteLogger.log("request-start", struct {
			RequestNum uint64
			RemoteAddr string
			Method     string
			URI        string
			Host       string
			Headers    http.Header
		}{myEntryNr, r.RemoteAddr, r.Method, r.RequestURI, r.Host, r.Header}); err != nil {
			logf(newReq, logLevelError, "Could not log request: %s", err)
		} else {
			requestLogged = true
		}
	}
	logf(newReq, logLevelInfo, "src=%s host=%#v method=%#v uri=%#v ua=%#v clen=%d", r.RemoteAddr, r.Host, r.Method, r.RequestURI, r.UserAgent(), r.ContentLength)
	hl.DefaultHandler.ServeHTTP(lw, newReq)
	if requestLogged {
		hl.remoteLogger.log("request-end", struct {
			RequestNum   uint64
			BytesWritten int
			Status       int
		}{myEntryNr, lw.BytesWritten, lw.Status})
	}
	logf(newReq, logLevelInfo, "status=%d clen=%d", lw.Status, lw.BytesWritten)
}

type LoggedListener struct {
	net.Listener
	remoteLogger *RemoteLogger
}

type LoggedConnection struct {
	net.Conn
	remoteLogger *RemoteLogger
}

func (c LoggedConnection) Close() error {
	c.remoteLogger.log("connection-close", struct {
		RemoteAddr string
	}{c.RemoteAddr().String()})
	return c.Conn.Close()
}

type LoggedTlsConnection struct {
	tls.Conn
	remoteLogger *RemoteLogger
}

func (c *LoggedTlsConnection) Close() error {
	c.remoteLogger.log("connection-close", struct {
		RemoteAddr string
	}{c.RemoteAddr().String()})
	return c.Conn.Close()
}

type tlsInfoLogMessage struct {
	Version          uint16
	DidResume        bool
	CipherSuite      uint16
	ServerName       string `json:",omitempty"`
	PeerCertificates [][]byte
}

func (l LoggedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	var tlsInfo interface{}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			tlsInfo = struct {
				HandshakeError string
			}{err.Error()}
		} else {
			cs := tlsConn.ConnectionState()
			tlsInfo = &tlsInfoLogMessage{cs.Version, cs.DidResume, cs.CipherSuite, cs.ServerName, [][]byte{}}
			for _, v := range cs.PeerCertificates {
				tlsInfo.(*tlsInfoLogMessage).PeerCertificates = append(tlsInfo.(*tlsInfoLogMessage).PeerCertificates, v.Raw)
			}
		}
		// TBD: implement logging of closing TLS connections
	} else {
		// TBD: possible failure of conn.(*someType) sometime later..
		conn = LoggedConnection{conn, l.remoteLogger}
	}
	if err := l.remoteLogger.log("connection-accept", struct {
		RemoteAddr string
		LocalAddr  string
		Tls        interface{} `json:",omitempty"`
	}{conn.RemoteAddr().String(), conn.LocalAddr().String(), tlsInfo}); err != nil {
		logf(nil, logLevelError, "Cannot send accept info: %s", err)
	}
	return conn, err
}

func logf(r *http.Request, level logLevel, format string, args ...interface{}) {
	if level > currentLogLevel {
		return
	}
	if r != nil {
		if reqNum := r.Context().Value(requestNumberContext); reqNum != nil {
			format = fmt.Sprintf("#%v %s", reqNum, format)
		}
	}
	logMsg := fmt.Sprintf("["+logLevelStr[level]+"] "+format, args...)
	log.Output(2, logMsg)
	if level == logLevelFatal {
		for _, e := range args {
			if err, ok := e.(error); ok {
				panic(err)
			}
		}
		panic(errors.New(logMsg))
	}
}
