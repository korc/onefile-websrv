// The MIT License
// Copyright 2018 Lauri Korts-Pärn
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/webdav"
)

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
		if resp, err := http.DefaultClient.Post(rl.RemoteLogURL, "application/json", bytes.NewBuffer(logData)); err != nil {
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
	ctx := context.WithValue(r.Context(), "request-num", myEntryNr)
	newReq := r.WithContext(ctx)
	requestLogged := false
	if hl.remoteLogger != nil {
		if err := hl.remoteLogger.log("request-start", struct {
			RequestNum uint64
			RemoteAddr string
			Method     string
			URI        string
			Headers    http.Header
		}{myEntryNr, r.RemoteAddr, r.Method, r.RequestURI, r.Header}); err != nil {
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
	TLSUnique        []byte
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
			tlsInfo = &tlsInfoLogMessage{cs.Version, cs.DidResume, cs.CipherSuite, cs.ServerName, [][]byte{}, cs.TLSUnique}
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

var oidMap = map[string]string{
	"2.5.4.3":              "CN",
	"2.5.4.5":              "SN",
	"2.5.4.6":              "C",
	"2.5.4.7":              "L",
	"2.5.4.8":              "S",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"1.2.840.113549.1.9.1": "eMail",
}

type contextKey int

const (
	authRoleContext contextKey = iota
)

const (
	logLevelFatal int = iota
	logLevelError
	logLevelWarning
	logLevelInfo
	logLevelVerbose
	logLevelDebug
)

var logLevelStr = []string{"FATAL", "ERROR", "WARNING", "INFO", "VERBOSE", "DEBUG"}

// DebugRequest returns debugging information to client
func DebugRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	hdrs := make([]string, 0)
	for k, v := range r.Header {
		for _, vv := range v {
			hdrs = append(hdrs, fmt.Sprintf("%s: %s", k, vv))
		}
	}

	metaInfo := []string{fmt.Sprintf("remote=%v", r.RemoteAddr)}
	if auth := r.Context().Value(authRoleContext); auth != nil {
		metaInfo = append(metaInfo, fmt.Sprintf("auth-role=%#v", auth))
	}
	if r.TLS != nil {
		metaInfo = append(metaInfo, fmt.Sprintf("SSL=0x%04x verified=%d", r.TLS.Version, len(r.TLS.VerifiedChains)))
		for _, crt := range r.TLS.PeerCertificates {
			subjectName := make([]string, 0)
			for _, attr := range crt.Subject.Names {
				attrName := attr.Type.String()
				if s := oidMap[attrName]; s != "" {
					attrName = s
				}
				subjectName = append(subjectName, fmt.Sprintf("%s=%s", attrName, attr.Value))
			}
			h := sha256.New()
			h.Write(crt.Raw)
			metaInfo = append(metaInfo,
				fmt.Sprintf("\n# %s %s", hex.EncodeToString(h.Sum(nil)), strings.Join(subjectName, "/")))
		}
	}
	fmt.Fprintf(w, `# %s
%v %v %v
%v

`, strings.Join(metaInfo, " "), r.Method, r.RequestURI, r.Proto, strings.Join(hdrs, "\n"))
	if r.ContentLength > 0 {
		bodyData := make([]byte, r.ContentLength)
		r.Body.Read(bodyData)
		w.Write(bodyData)
	}
}

// ConnWithDeadline is like net.Conn, but with deadline to read or write data
type ConnWithDeadline struct {
	Conn     net.Conn
	Deadline time.Duration
}

func (c ConnWithDeadline) Read(p []byte) (n int, err error) {
	c.Conn.SetReadDeadline(time.Now().Add(c.Deadline))
	return c.Conn.Read(p)
}

func (c ConnWithDeadline) Write(p []byte) (n int, err error) {
	c.Conn.SetWriteDeadline(time.Now().Add(c.Deadline))
	return c.Conn.Write(p)
}

// DownloadOnlyHandler is like static file handler, but adds Content-Disposition: attachment and optionally a fixed Content-Type
type DownloadOnlyHandler struct {
	ContentType string
	http.Handler
}

func (dh DownloadOnlyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET", "POST", "HEAD":
		wdHandler := dh.Handler.(*webdav.Handler)
		if fs, ok := wdHandler.FileSystem.(webdav.Dir); ok {
			name := strings.TrimPrefix(r.URL.Path, wdHandler.Prefix)
			if fi, err := fs.Stat(r.Context(), name); err == nil && fi.IsDir() {
				http.ServeFile(w, r, filepath.Join(string(fs), name))
				return
			}
		}
		w.Header().Set("Content-Disposition", "attachment")
		if dh.ContentType != "" {
			w.Header().Set("Content-Type", dh.ContentType)
		}
	}
	dh.Handler.ServeHTTP(w, r)
}

type corsACL struct {
	path   *regexp.Regexp
	domain *regexp.Regexp
}

// CORSHandler adds "Access-Control-Allow-Origin" header to response if specified Origin is in request
type CORSHandler struct {
	http.Handler
	allowed []corsACL
}

// AddRecord make path accessible from origin
func (ch *CORSHandler) AddRecord(path, origin string) error {
	if ch.allowed == nil {
		ch.allowed = make([]corsACL, 0)
	}
	pathRe, err := regexp.Compile(path)
	if err != nil {
		return err
	}
	originRe, err := regexp.Compile(origin)
	if err != nil {
		return err
	}
	logf(nil, logLevelInfo, "CORS: Adding origin %#v on %#v", origin, path)
	ch.allowed = append(ch.allowed, corsACL{pathRe, originRe})
	return nil
}

func (ch *CORSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next := ch.Handler
	if next == nil {
		next = http.DefaultServeMux
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		matched := false
		for _, acl := range ch.allowed {
			if acl.path.MatchString(r.URL.Path) && acl.domain.MatchString(origin) {
				matched = true
				w.Header().Add("Access-Control-Allow-Origin", origin)
				varyHeaders := []string{"Origin"}
				if method := r.Header.Get("Access-Control-Request-Method"); method != "" {
					w.Header().Add("Access-Control-Allow-Methods", "*")
				}
				if header := r.Header.Get("Access-Control-Request-Headers"); header != "" {
					w.Header().Add("Access-Control-Allow-Headers", header)
					varyHeaders = append(varyHeaders, header)
				}
				if r.Method == "OPTIONS" {
					w.Header().Add("Vary", strings.Join(varyHeaders, ", "))
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		if !matched {
			logf(r, logLevelWarning, "CORS: Could not match origin %#v on %#v, passing to backend", origin, r.URL.Path)
		}
	}
	next.ServeHTTP(w, r)
}

// ACLRecord maps path regexp to required roles
type ACLRecord struct {
	Expr     *regexp.Regexp
	Roles    map[string]bool
	Methods  map[string]bool
	MatchURI bool
}

// AuthHandler passes request to next http.Handler if authorization allows
type AuthHandler struct {
	http.Handler
	DefaultHandler http.Handler
	Auths          map[string]map[string]string
	ACLs           []ACLRecord
}

// AddAuth : add authentication method to identify role(s)
func (ah *AuthHandler) AddAuth(method, check, name string) {
	if ah.Auths == nil {
		ah.Auths = make(map[string]map[string]string)
	}

	switch method {
	case "Cert", "CertBy":
		if strings.HasPrefix(check, "file:") {
			data, err := ioutil.ReadFile(check[5:])
			if err != nil {
				logf(nil, logLevelFatal, "Cannot read file %#v: %s", check[5:], err)
			}
			pemBlock, rest := pem.Decode(data)
			logf(nil, logLevelDebug, "Read pem type %s (%d bytes of data)", pemBlock.Type, len(pemBlock.Bytes))
			if len(rest) > 0 {
				logf(nil, logLevelInfo, "Extra %d bytes after pem", len(rest))
			}
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				logf(nil, logLevelFatal, "Could not load certificate: %s", err)
			}
			if method == "Cert" {
				h := sha256.New()
				h.Write(cert.Raw)
				check = hex.EncodeToString(h.Sum(nil))
			} else {
				check = hex.EncodeToString(cert.Raw)
			}
		}
	case "Basic", "JWTSecret", "IPRange", "JWTFilePat":
	default:
		logf(nil, logLevelFatal, "Supported mechanisms: Basic, Cert, CertBy, JWTSecret, JWTFilePat, IPRange. Basic auth is base64 string, certs can use file:<file.crt>")
	}
	if ah.Auths[method] == nil {
		ah.Auths[method] = make(map[string]string)
	}
	ah.Auths[method][check] = name
}

// AddACL : add roles constraint to matching path regexp
func (ah *AuthHandler) AddACL(reExpr string, roles []string) error {
	var methods map[string]bool
	matchURI := false
	if strings.HasPrefix(reExpr, "?") {
		matchURI = true
		reExpr = reExpr[1:]
	}
	if strings.HasPrefix(reExpr, "{") {
		clidx := strings.Index(reExpr, "}")
		methods = make(map[string]bool)
		for _, v := range strings.Split(reExpr[1:clidx], ",") {
			methods[v] = true
		}
		reExpr = reExpr[clidx+1:]
	}
	re, err := regexp.Compile(reExpr)
	if err != nil {
		return err
	}
	if ah.ACLs == nil {
		ah.ACLs = make([]ACLRecord, 0)
	}
	rec := ACLRecord{re, make(map[string]bool), methods, matchURI}
	for _, r := range roles {
		rec.Roles[r] = true
	}
	ah.ACLs = append(ah.ACLs, rec)
	return nil
}

func (ah *AuthHandler) checkAuthPass(r *http.Request) (*http.Request, error) {
	if ah.Auths == nil {
		return r, nil
	}

	neededRoles := make(map[string]bool)
	for _, acl := range ah.ACLs {
		methodMatch := true
		if acl.Methods != nil {
			if _, ok := acl.Methods[r.Method]; !ok {
				methodMatch = false
			}
		}
		testString := r.URL.Path
		if acl.MatchURI {
			testString = r.RequestURI
		}
		if methodMatch && acl.Expr.MatchString(testString) {
			neededRoles = acl.Roles
			break
		}
	}

	haveRoles := make(map[string]bool)

	if ipRanges, ok := ah.Auths["IPRange"]; ok {
		remoteHostName, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			logf(r, logLevelError, "Cannot parse remote host address: %s", err)
			return r, err
		}
		remoteHost := net.ParseIP(remoteHostName)
		for ipRange := range ipRanges {
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				logf(r, logLevelError, "IP range %#v parse error: %s", ipRange, err)
				return r, err
			}
			if ipNet.Contains(remoteHost) {
				for _, gotRole := range strings.Split(ah.Auths["IPRange"][ipRange], "+") {
					haveRoles[gotRole] = ah.ACLs == nil
				}
			}
		}
	}

	if authHdr := r.Header.Get("Authorization"); authHdr != "" {
		authFields := strings.SplitN(authHdr, " ", 2)
		if len(authFields) < 2 {
			return nil, errors.New("bad auth")
		}
		authMethod := authFields[0]
		authValue := authFields[1]
		switch authMethod {
		case "Basic":
			if gotRoles, ok := ah.Auths["Basic"][authValue]; ok {
				for _, gotRole := range strings.Split(gotRoles, "+") {
					haveRoles[gotRole] = ah.ACLs == nil
				}
			}
		case "Bearer":
			for signer := range ah.Auths["JWTSecret"] {
				token, err := jwt.Parse(authValue, func(token *jwt.Token) (interface{}, error) {
					return []byte(signer), nil
				})
				if err != nil {
					logf(r, logLevelWarning, "Failed with secret: %#v: %s", signer, err)
					continue
				}
				if token.Valid {
					for _, gotRole := range strings.Split(ah.Auths["JWTSecret"][signer], "+") {
						haveRoles[gotRole] = ah.ACLs == nil
					}
				}
			}
			for fpath := range ah.Auths["JWTFilePat"] {
				// authValue is file path. '**' in filename will be tested in order of:
				// URL, URL without file extension, without filename, with all path components removed one by one
				haveStars := strings.Index(fpath, "**") != -1
				if haveStars && len(neededRoles) == 0 {
					break
				}
				testUrl := r.URL.Path
				testList := []string{strings.Replace(fpath, "**", testUrl[1:], 1)}
				if haveStars {
					slashIdx := strings.LastIndex(testUrl, "/")
					for {
						dotIdx := strings.LastIndex(testUrl, ".")
						if dotIdx <= slashIdx {
							break
						}
						testUrl = testUrl[:dotIdx]
						testList = append(testList, strings.Replace(fpath, "**", testUrl[1:], 1))
					}
					for slashIdx > 0 {
						testUrl = testUrl[:slashIdx]
						testList = append(testList, strings.Replace(fpath, "**", testUrl[1:], 1))
						slashIdx = strings.LastIndex(testUrl, "/")
					}
				}
				for _, testPath := range testList {
					logf(r, logLevelDebug, "Testing JWT auth file at %#v", testPath)
					if file, err := os.Open(testPath); err == nil {
						defer file.Close()
						tkn, err := jwt.Parse(authValue, func(token *jwt.Token) (i interface{}, e error) {
							linescanner := bufio.NewScanner(file)
							for linescanner.Scan() {
								line := strings.SplitN(linescanner.Text(), ":", 2)
								if line[0][:1] == "#" {
									continue
								}
								if len(line) < 2 {
									logf(r, logLevelError, "Line in JWT file %#v does not contain ':'", testPath)
									continue
								}
								decodedVal, err := base64.RawURLEncoding.DecodeString(line[1])
								if err != nil {
									logf(r, logLevelError, "Cannot decode base64 of value in %#v", testPath)
									continue
								}
								switch line[0] {
								case "hmac":
									if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
										return []byte(decodedVal), nil
									}
								case "rsa":
									if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
										return &rsa.PublicKey{N: (&big.Int{}).SetBytes(decodedVal), E: 0x10001}, nil
									}
								default:
									logf(r, logLevelWarning, "unsupported mechanism %#v in JWT keyfile", line[0])
								}
							}
							return
						})
						if err != nil {
							logf(r, logLevelWarning, "Could not parse auth token: %s", err)
							break
						}
						if tkn.Valid {
							for _, gotRole := range strings.Split(ah.Auths["JWTFilePat"][fpath], "+") {
								haveRoles[gotRole] = ah.ACLs == nil
							}
						}
						break
						logf(r, logLevelDebug, "Searching for JWT file from %#v for URL %#v (authvalue=%#v)",
							testPath, r.URL.Path, authValue)
					}
				}
			}
		default:
			return nil, errors.New("unsupported method")
		}
	}

	if r.TLS != nil {
		for _, crt := range r.TLS.PeerCertificates {
			h := sha256.New()
			h.Write(crt.Raw)
			peerHash := hex.EncodeToString(h.Sum(nil))
			if authCerts, ok := ah.Auths["Cert"]; ok {
				if gotRoles, ok := authCerts[peerHash]; ok {
					for _, role := range strings.Split(gotRoles, "+") {
						haveRoles[role] = ah.ACLs == nil
					}
				}
			}
			if parentCerts, ok := ah.Auths["CertBy"]; ok {
				for pCertHex, gotRoles := range parentCerts {
					pRaw, err := hex.DecodeString(pCertHex)
					if err != nil {
						logf(r, logLevelError, "Could not parse parent hex: %s", err)
						return r, err
					}
					parentCert, err := x509.ParseCertificate(pRaw)
					if err != nil {
						logf(r, logLevelError, "Could not parse parent bytes: %s", err)
						return r, err
					}
					if err := crt.CheckSignatureFrom(parentCert); err == nil {
						for _, role := range strings.Split(gotRoles, "+") {
							haveRoles[role] = ah.ACLs == nil
						}
					}
				}
			}
		}
	}

	ctx := context.WithValue(r.Context(), authRoleContext, haveRoles)
	retReq := r.WithContext(ctx)

	if ah.ACLs == nil {
		if len(haveRoles) > 0 {
			return retReq, nil
		}
		return nil, errors.New("need auth")
	}

	if len(neededRoles) == 0 {
		return retReq, nil
	}

	for role := range neededRoles {
		reqRoles := strings.Split(role, "+")
		findRoleCount := len(reqRoles)
		for _, reqRole := range reqRoles {
			if _, ok := haveRoles[reqRole]; ok {
				findRoleCount--
			}
		}
		if findRoleCount == 0 {
			return retReq, nil
		}
	}
	return nil, errors.New("need proper auth")
}

func (ah *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next := ah.DefaultHandler
	if next == nil {
		next = http.DefaultServeMux
	}

	if authenticatedRequest, err := ah.checkAuthPass(r); err == nil {
		next.ServeHTTP(w, authenticatedRequest)
	} else {
		for k := range ah.Auths {
			switch k {
			case "JWTSecret", "JWTFilePat":
				w.Header().Add("WWW-Authenticate", "Bearer realm=\"Authentication required\"")
			case "Cert", "CertBy":
			default:
				w.Header().Add("WWW-Authenticate", fmt.Sprintf("%s realm=\"auth-required\"", k))
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
	}
}

type arrayFlag []string

func (f *arrayFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *arrayFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
	return true
}}

var currentLogLevel = logLevelDebug

func logf(r *http.Request, level int, format string, args ...interface{}) {
	if level > currentLogLevel {
		return
	}
	if r != nil {
		if reqNum := r.Context().Value("request-num"); reqNum != nil {
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

func parseCurlyParams(handlerParams string) (map[string]string, string) {
	connectParams := make(map[string]string)
	if strings.HasPrefix(handlerParams, "{") {
		ebIndex := strings.Index(handlerParams, "}")
		if ebIndex < 0 {
			log.Fatal("Invalid parameter syntax, missing '}'")
		}
		for _, s := range strings.Split(handlerParams[1:ebIndex], ",") {
			kv := strings.SplitN(s, "=", 2)
			connectParams[kv[0]] = kv[1]
		}
		handlerParams = handlerParams[ebIndex+1:]
	}
	return connectParams, handlerParams
}

func main() {
	var (
		listenAddr    = flag.String("listen", ":80", "Listen ip:port")
		chroot        = flag.String("chroot", "", "chroot() to directory after start")
		userName      = flag.String("user", "", "Switch to user (NOT RECOMMENDED)")
		certFile      = flag.String("cert", "", "SSL certificate file or autocert cache dir")
		keyFile       = flag.String("key", "", "SSL key file")
		wdCType       = flag.String("wdctype", "", "Fix content-type for Webdav GET/POST requests")
		acmeHTTP      = flag.String("acmehttp", ":80", "Listen address for ACME http-01 challenge")
		wsReadTimeout = flag.Int("wstmout", 60, "Websocket alive check timer in seconds")
		loglevelFlag  = flag.String("loglevel", "info", "Max log level (one of "+strings.Join(logLevelStr, ", ")+")")
		reqlog        = flag.String("reqlog", "", "URL to log request details to")
		acmeHosts     = flag.String("acmehost", "",
			"Autocert hostnames (comma-separated), -cert will be cache dir")
	)
	var authFlag, aclFlag, urlMaps, corsMaps arrayFlag
	flag.Var(&authFlag, "auth", "[<role>[+<role2>]=]<method>:<auth> (multi-arg)")
	flag.Var(&aclFlag, "acl", "<path_regexp>=<role>[+<role2..>]:<role..> (multi-arg)")
	flag.Var(&urlMaps, "map", "<path>=<handler>:[<params>] (multi-arg, default '/=file:')")
	flag.Var(&corsMaps, "cors", "<path>=<allowed_origin> (multi-arg)")

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	currentLogLevel = logLevelInfo
	for ll, lstr := range logLevelStr {
		if strings.ToLower(lstr) == strings.ToLower(*loglevelFlag) {
			currentLogLevel = ll
		}
	}

	wsReadTimeoutDuration := time.Duration(*wsReadTimeout) * time.Second

	if len(urlMaps) == 0 {
		urlMaps.Set("/=file:")
	}

	var switchToUser *user.User
	if *userName != "" {
		var err error
		logf(nil, logLevelWarning, "Switch to user is discouraged, cf. https://github.com/golang/go/issues/1435")
		if switchToUser, err = user.Lookup(*userName); err != nil {
			logf(nil, logLevelFatal, "Looking up user %#v failed: %s", *userName, err)
		}
	}

	var defaultHandler http.Handler
	haveCertAuth := false

	if len(authFlag) > 0 {
		defaultHandler = &AuthHandler{}
		for _, auth := range authFlag {
			methodIdx := strings.Index(auth, ":")
			tagIdx := strings.Index(auth, "=")
			role := ""
			if tagIdx != -1 && tagIdx < methodIdx {
				role = auth[:tagIdx]
			} else {
				tagIdx = -1
			}
			authMethod := auth[tagIdx+1 : methodIdx]
			switch authMethod {
			case "Cert", "CertBy":
				haveCertAuth = true
			}
			defaultHandler.(*AuthHandler).AddAuth(authMethod, auth[methodIdx+1:], role)
		}
		if len(aclFlag) > 0 {
			for _, acl := range aclFlag {
				pathIdx := strings.LastIndex(acl, "=")
				err := defaultHandler.(*AuthHandler).AddACL(acl[:pathIdx], strings.Split(acl[pathIdx+1:], ":"))
				if err != nil {
					logf(nil, logLevelFatal, "Cannot add ACL: %s", err)
				}
			}
		}
	}

	if len(corsMaps) > 0 {
		defaultHandler = &CORSHandler{Handler: defaultHandler}
		for _, cors := range corsMaps {
			pathIdx := strings.Index(cors, "=")
			defaultHandler.(*CORSHandler).AddRecord(cors[:pathIdx], cors[pathIdx+1:])
		}
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logf(nil, logLevelFatal, "Listen on %#v failed: %s", *listenAddr, err)
	}
	logf(nil, logLevelInfo, "Listening on %s", *listenAddr)
	if *certFile != "" {
		if *keyFile == "" {
			*keyFile = *certFile
		}
		var tlsConfig *tls.Config
		if *acmeHosts == "" {
			crt, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				logf(nil, logLevelFatal, "Loading X509 cert from %#v and %#v failed: %s", *certFile, *keyFile, err)
			}
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{crt}}
		} else {
			acmeManager := autocert.Manager{
				Cache:      autocert.DirCache(*certFile),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(strings.Split(*acmeHosts, ",")...),
			}
			tlsConfig = &tls.Config{GetCertificate: acmeManager.GetCertificate}
			if *acmeHTTP != "" {
				go http.ListenAndServe(*acmeHTTP, acmeManager.HTTPHandler(nil))
			}
		}
		if haveCertAuth {
			tlsConfig.ClientAuth = tls.RequestClientCert
			logf(nil, logLevelInfo, "X509 auth enabled")
		}
		ln = tls.NewListener(ln, tlsConfig)
		logf(nil, logLevelInfo, "SSL enabled, cert=%s", *certFile)
	} else {
		logf(nil, logLevelWarning, "SSL not enabled")
	}
	if *chroot != "" {
		if err := os.Chdir(*chroot); err != nil {
			logf(nil, logLevelFatal, "Cannot chdir to %#v: %v", *chroot, err)
		}
		if err := syscall.Chroot("."); err != nil {
			logf(nil, logLevelFatal, "Changing root to %#v failed: %s", *chroot, err)
		}
		logf(nil, logLevelInfo, "Changed root to %#v", *chroot)
	}
	if switchToUser != nil {
		gid, _ := strconv.Atoi(switchToUser.Gid)
		uid, _ := strconv.Atoi(switchToUser.Uid)
		if err := syscall.Setregid(gid, gid); err != nil {
			logf(nil, logLevelFatal, "Could not switch to gid %v: %v", gid, err)
		}
		if err := syscall.Setreuid(uid, uid); err != nil {
			logf(nil, logLevelFatal, "Could not switch to uid %v: %v", uid, err)
		}
		logf(nil, logLevelInfo, "Changed to user %v/%v", uid, gid)
	}

	for _, urlMap := range urlMaps {
		pathSepIdx := strings.Index(urlMap, "=")
		if pathSepIdx == -1 {
			logf(nil, logLevelFatal, "Url map %#v does not contain '='", urlMap)
		}
		urlPath := urlMap[:pathSepIdx]
		urlHandler := urlMap[pathSepIdx+1:]
		handlerTypeIdx := strings.Index(urlHandler, ":")
		if handlerTypeIdx == -1 {
			logf(nil, logLevelFatal, "Handler %#v does not contain ':'", urlHandler)
		}
		handlerParams := urlHandler[handlerTypeIdx+1:]
		logf(nil, logLevelInfo, "Handling %#v as %#v (%#v)", urlPath, urlHandler[:handlerTypeIdx], handlerParams)
		switch urlHandler[:handlerTypeIdx] {
		case "debug":
			http.HandleFunc(urlPath, DebugRequest)
		case "file":
			http.Handle(urlPath, http.StripPrefix(urlPath, http.FileServer(http.Dir(handlerParams))))
		case "webdav":
			if !strings.HasSuffix(urlPath, "/") {
				urlPath += "/"
			}
			var wdFS webdav.FileSystem
			if handlerParams == "" {
				wdFS = webdav.NewMemFS()
			} else {
				wdFS = webdav.Dir(handlerParams)
			}
			wdHandler := webdav.Handler{
				FileSystem: wdFS,
				LockSystem: webdav.NewMemLS(),
				Prefix:     urlPath,
			}
			http.Handle(urlPath, DownloadOnlyHandler{ContentType: *wdCType, Handler: &wdHandler})
		case "websocket", "ws":
			connectParams, handlerParams := parseCurlyParams(handlerParams)
			http.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
				defer logf(r, logLevelVerbose, "WS<->Sock handler finished")
				var respHeader http.Header
				wsMessageType := websocket.BinaryMessage
				if msgType, ok := connectParams["type"]; ok && msgType == "text" {
					wsMessageType = websocket.TextMessage
				}
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
				proto := "tcp"
				address := handlerParams
				if strings.HasPrefix(handlerParams, "unix:") {
					proto = "unix"
					address = handlerParams[strings.Index(handlerParams, ":")+1:]
				}
				var conn net.Conn
				if strings.HasPrefix(handlerParams, "tls:") {
					conn, err = tls.Dial("tcp", handlerParams[strings.Index(handlerParams, ":")+1:], &tls.Config{})
					if err != nil {
						logf(r, logLevelError, "Connect with TLS to %#v failed: %s", handlerParams, err)
						return
					}
				} else {
					conn, err = net.DialTimeout(proto, address, 10*time.Second)
					if err != nil {
						logf(r, logLevelError, "Connect to %#v failed: %s", handlerParams, err)
						return
					}
				}
				defer conn.Close()

				var onceDone sync.Once
				var keepRunning atomic.Value
				keepRunning.Store(true)
				done := make(chan struct{})
				stopRunning := func() {
					keepRunning.Store(false)
					close(done)
				}

				dataFromConn := make(chan []byte)
				dataFromWS := make(chan []byte)

				go func() {
					defer logf(r, logLevelDebug, "WSWriter finished")
					defer onceDone.Do(stopRunning)
					for keepRunning.Load().(bool) {
						select {
						case data := <-dataFromConn:
							logf(r, logLevelDebug, "data (nil=%#v) from conn", data == nil)
							if data == nil {
								break
							}
							if err := c.WriteMessage(wsMessageType, data); err != nil {
								logf(r, logLevelError, "Error writing to WS: %s", err)
								break
							}
						case <-time.After(wsReadTimeoutDuration):
							logf(r, logLevelVerbose, "No input from conn in %s", wsReadTimeoutDuration)
						}
					}
				}()
				go func() {
					defer logf(r, logLevelVerbose, "SockWriter finished")
					defer onceDone.Do(stopRunning)
					checkingAlive := false
					for keepRunning.Load().(bool) {
						select {
						case data := <-dataFromWS:
							logf(r, logLevelDebug, "data (nil=%#v) from WS", data == nil)
							if data == nil {
								break
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
						case <-time.After(wsReadTimeoutDuration):
							logf(r, logLevelVerbose, "No data from WS in %s (checkingAlive=%#v)", wsReadTimeoutDuration, checkingAlive)
							if checkingAlive {
								logf(r, logLevelWarning, "Alive check failed.")
								onceDone.Do(stopRunning)
								break
							} else {
								checkingAlive = true
								c.SetPongHandler(func(appData string) error {
									checkingAlive = false
									logf(r, logLevelVerbose, "Alive check succeeded: %#v", appData)
									return nil
								})
								if err := c.WriteControl(websocket.PingMessage, []byte("are you alive?"), time.Now().Add(time.Second)); err != nil {
									logf(r, logLevelError, "Could not send ping.")
									break
								} else {
									logf(r, logLevelDebug, "Sent ping.")
								}
							}
						}
					}
				}()
				go func() {
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
				}()
				go func() {
					defer logf(r, logLevelDebug, "WSReader finished")
					defer onceDone.Do(stopRunning)
					defer close(dataFromWS)
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
						if msgType != wsMessageType {
							logf(r, logLevelWarning, "Not message type does not match: %#v != ", msgType, wsMessageType)
						}
						dataFromWS <- data
					}
				}()
				<-done
			})
		case "http":
			connectParams := make(map[string]string)
			if strings.HasPrefix(handlerParams, "{") {
				ebIndex := strings.Index(handlerParams, "}")
				if ebIndex < 0 {
					log.Fatal("Cannot find parameters before URL")
				}
				for _, s := range strings.Split(handlerParams[1:ebIndex], ",") {
					kv := strings.SplitN(s, "=", 2)
					connectParams[kv[0]] = kv[1]
				}
				handlerParams = handlerParams[ebIndex+1:]
			}
			httpURL, err := url.Parse(handlerParams)
			if err != nil {
				logf(nil, logLevelFatal, "Cannot parse %#v as URL: %v", handlerParams, err)
			}
			prxHandler := httputil.NewSingleHostReverseProxy(httpURL)

			defaultDirector := prxHandler.Director
			prxHandler.Director = func(request *http.Request) {
				defaultDirector(request)
				if *certFile != "" {
					request.Header.Set("X-Forwarded-Proto", "https")
				} else {
					request.Header.Set("X-Forwarded-Proto", "http")
				}
			}

			if certFile, ok := connectParams["cert"]; ok {
				keyFile := connectParams["key"]
				if keyFile == "" {
					keyFile = certFile
				}
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					log.Fatalf("Cannot load cert/key from %#v and %#v: %s", certFile, keyFile, err)
				}
				prxHandler.Transport = &http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates: []tls.Certificate{cert},
					},
				}
			}
			http.Handle(urlPath, http.StripPrefix(urlPath, prxHandler))
		case "cgi":
			var env, inhEnv, args []string
			if strings.HasPrefix(handlerParams, "{") {
				ebIndex := strings.Index(handlerParams, "}")
				if ebIndex < 0 {
					logf(nil, logLevelFatal, "No end brace")
				}
				for _, v := range strings.Split(handlerParams[1:ebIndex], ",") {
					if strings.HasPrefix(v, "arg:") {
						if args == nil {
							args = make([]string, 0)
						}
						args = append(args, v[4:])
					} else if eqIndex := strings.Index(v, "="); eqIndex < 0 {
						if inhEnv == nil {
							inhEnv = make([]string, 0)
						}
						inhEnv = append(inhEnv, v)
					} else {
						if env == nil {
							env = make([]string, 0)
						}
						env = append(env, v)
					}
				}
				handlerParams = handlerParams[ebIndex+1:]
			}
			http.Handle(urlPath, &cgi.Handler{Path: handlerParams, Root: strings.TrimRight(urlPath, "/"), Env: env, InheritEnv: inhEnv, Args: args})
		default:
			logf(nil, logLevelFatal, "Handler type %#v unknown, available: debug file webdav websocket(ws) http cgi", urlHandler[:handlerTypeIdx])
		}
	}

	var rl *RemoteLogger

	if *reqlog != "" {
		rl = &RemoteLogger{*reqlog}
		ln = LoggedListener{ln, rl}
		rl.log("server-start", struct {
			ListenAddress string
		}{*listenAddr})
	}

	if err := http.Serve(ln, NewHTTPLogger(defaultHandler, rl)); err != nil {
		logf(nil, logLevelFatal, "Cannot serve: %s", err)
	}
}
