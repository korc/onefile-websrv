// The MIT License
// Copyright 2018 Lauri Korts-Pärn
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
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
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/webdav"
	"golang.org/x/net/websocket"
)

// HTTPLogger : HTTP handler which logs requests and replies
type HTTPLogger struct {
	logEntryNumber uint64
	DefaultHandler http.Handler
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
func NewHTTPLogger(h http.Handler) *HTTPLogger {
	if h == nil {
		h = http.DefaultServeMux
	}
	return &HTTPLogger{DefaultHandler: h}
}

func (hl *HTTPLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	myEntryNr := atomic.AddUint64(&hl.logEntryNumber, 1)
	log.Printf("#%d src=%s host=%#v method=%#v path=%#v ua=%#v clen=%d", myEntryNr, r.RemoteAddr, r.Host, r.Method, r.URL.Path, r.UserAgent(), r.ContentLength)
	lw := NewLoggedResponseWriter(w)
	hl.DefaultHandler.ServeHTTP(lw, r)
	log.Printf("#%d status=%d clen=%d", myEntryNr, lw.Status, lw.BytesWritten)
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

// ACLRecord maps path regexp to required roles
type ACLRecord struct {
	Expr  *regexp.Regexp
	Roles map[string]bool
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
				log.Fatalf("Cannot read file %#v: %s", check[5:], err)
			}
			pemBlock, rest := pem.Decode(data)
			log.Printf("Read pem type %s (%d bytes of date)", pemBlock.Type, len(pemBlock.Bytes))
			if len(rest) > 0 {
				log.Printf("Extra %d bytes after pem", len(rest))
			}
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				log.Fatalf("Could not load certificate: %s", err)
			}
			if method == "Cert" {
				h := sha256.New()
				h.Write(cert.Raw)
				check = hex.EncodeToString(h.Sum(nil))
			} else {
				check = hex.EncodeToString(cert.Raw)
			}
		}
	case "Basic", "JWTSecret":
	default:
		log.Fatalf("Supported mechanisms: Basic, Cert, CertBy, JWTSecret. Basic auth is base64 string, certs can use file:<file.crt>")
	}
	if ah.Auths[method] == nil {
		ah.Auths[method] = make(map[string]string)
	}
	ah.Auths[method][check] = name
}

// AddACL : add roles constraint to matching path regexp
func (ah *AuthHandler) AddACL(reExpr string, roles []string) error {
	re, err := regexp.Compile(reExpr)
	if err != nil {
		return err
	}
	if ah.ACLs == nil {
		ah.ACLs = make([]ACLRecord, 0)
	}
	rec := ACLRecord{re, make(map[string]bool)}
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

	haveRoles := make(map[string]bool)
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
					log.Printf("Failed with secret: %#v: %s", signer, err)
					continue
				}
				if token.Valid {
					for _, gotRole := range strings.Split(ah.Auths["JWTSecret"][signer], "+") {
						haveRoles[gotRole] = ah.ACLs == nil
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
						log.Fatalf("Could not parse parent hex: %s", err)
					}
					parentCert, err := x509.ParseCertificate(pRaw)
					if err != nil {
						log.Fatalf("Could not parse parent bytes: %s", err)
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

	neededRoles := make(map[string]bool)
	for _, acl := range ah.ACLs {
		if acl.Expr.MatchString(r.URL.Path) {
			neededRoles = acl.Roles
			break
		}
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
			case "Cert", "CertBy", "JWTSecret":
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

func main() {
	var (
		listenAddr = flag.String("listen", ":80", "Listen ip:port")
		chroot     = flag.String("chroot", "", "chroot() to directory after start")
		userName   = flag.String("user", "", "Switch to user (NOT RECOMMENDED)")
		certFile   = flag.String("cert", "", "SSL certificate file or autocert cache dir")
		keyFile    = flag.String("key", "", "SSL key file")
		wdCType    = flag.String("wdctype", "", "Fix content-type for Webdav GET/POST requests")
		acmeHTTP   = flag.String("acmehttp", ":80", "Listen address for ACME http-01 challenge")
		acmeHosts  = flag.String("acmehost", "",
			"Autocert hostnames (comma-separated), -cert will be cache dir")
	)
	var authFlag, aclFlag, urlMaps arrayFlag
	flag.Var(&authFlag, "auth", "[<role>[+<role2>]=]<method>:<auth> (multi-arg)")
	flag.Var(&aclFlag, "acl", "<path_regexp>=<role>[+<role2..>]:<role..> (multi-arg)")
	flag.Var(&urlMaps, "map", "<path>=<handler>:[<params>] (multi-arg, default '/=file:')")

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	if len(urlMaps) == 0 {
		urlMaps.Set("/=file:")
	}

	var switchToUser *user.User
	if *userName != "" {
		var err error
		if switchToUser, err = user.Lookup(*userName); err != nil {
			log.Fatal(err)
		}
	}

	var defaultHandler http.Handler

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
			defaultHandler.(*AuthHandler).AddAuth(auth[tagIdx+1:methodIdx], auth[methodIdx+1:], role)
		}
		if len(aclFlag) > 0 {
			for _, acl := range aclFlag {
				pathIdx := strings.LastIndex(acl, "=")
				err := defaultHandler.(*AuthHandler).AddACL(acl[:pathIdx], strings.Split(acl[pathIdx+1:], ":"))
				if err != nil {
					log.Fatal("Cannot add ACL: ", err)
				}
			}
		}
	}

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s", *listenAddr)
	if *certFile != "" {
		if *keyFile == "" {
			*keyFile = *certFile
		}
		var tlsConfig *tls.Config
		if *acmeHosts == "" {
			crt, err := tls.LoadX509KeyPair(*certFile, *keyFile)
			if err != nil {
				log.Fatal(err)
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
		tlsConfig.ClientAuth = tls.RequestClientCert
		ln = tls.NewListener(ln, tlsConfig)
		log.Printf("SSL enabled, cert=%s", *certFile)
	} else {
		log.Printf("SSL not enabled")
	}
	if *chroot != "" {
		if err := os.Chdir(*chroot); err != nil {
			log.Fatalf("Cannot chdir to %#v: %v", *chroot, err)
		}
		if err := syscall.Chroot("."); err != nil {
			log.Fatal(err)
		}
		log.Printf("Changed root to %#v", *chroot)
	}
	if switchToUser != nil {
		gid, _ := strconv.Atoi(switchToUser.Gid)
		uid, _ := strconv.Atoi(switchToUser.Uid)
		if err := syscall.Setregid(gid, gid); err != nil {
			log.Fatalf("Could not switch to gid %v: %v", gid, err)
		}
		if err := syscall.Setreuid(uid, uid); err != nil {
			log.Fatalf("Could not switch to uid %v: %v", uid, err)
		}
		log.Printf("Changed to user %v/%v", uid, gid)
	}

	for _, urlMap := range urlMaps {
		pathSepIdx := strings.Index(urlMap, "=")
		if pathSepIdx == -1 {
			log.Fatalf("Url map %#v does not contain '='", urlMap)
		}
		urlPath := urlMap[:pathSepIdx]
		urlHandler := urlMap[pathSepIdx+1:]
		handlerTypeIdx := strings.Index(urlHandler, ":")
		if handlerTypeIdx == -1 {
			log.Fatalf("Handler %#v does not contain ':'", urlHandler)
		}
		handlerParams := urlHandler[handlerTypeIdx+1:]
		log.Printf("Handling %#v as %#v (%#v)", urlPath, urlHandler[:handlerTypeIdx], handlerParams)
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
		case "websocket":
			http.Handle(urlPath, websocket.Handler(func(ws *websocket.Conn) {
				defer ws.Close()
				conn, err := net.DialTimeout("tcp", handlerParams, 10*time.Second)
				if err != nil {
					log.Printf("Connect to %#v failed: %s", handlerParams, err)
					return
				}
				defer conn.Close()
				wg := sync.WaitGroup{}
				copyIn := 0
				copyOut := 0
				wg.Add(2)
				go func() {
					defer wg.Done()
					defer ws.Close()
					defer conn.(*net.TCPConn).CloseRead()
					copyIn, err := io.Copy(
						ConnWithDeadline{ws, time.Minute},
						ConnWithDeadline{conn, time.Minute})
					if err != nil && err != io.EOF {
						log.Printf("copyIn failed after %v bytes: %v", copyIn, err)
					}
				}()
				go func() {
					defer wg.Done()
					defer conn.(*net.TCPConn).CloseWrite()
					defer ws.Close()
					copyOut, err := io.Copy(
						ConnWithDeadline{conn, time.Minute},
						ConnWithDeadline{ws, time.Minute})
					if err != nil && err != io.EOF {
						log.Printf("copyOut failed after %v bytes: %v", copyOut, err)
					}
				}()
				wg.Wait()
				log.Printf("Finished websocket %v <-> %v <-> %v <-> %v (in=%v out=%v)",
					ws.Request().RemoteAddr, ws.RemoteAddr(), urlPath, handlerParams, copyIn, copyOut)
			}))
		case "http":
			httpURL, err := url.Parse(handlerParams)
			if err != nil {
				log.Fatalf("Cannot parse %#v as URL: %v", handlerParams, err)
			}
			http.Handle(urlPath, http.StripPrefix(urlPath, httputil.NewSingleHostReverseProxy(httpURL)))
		default:
			log.Fatalf("Handler type %#v unknown, available: debug file webdav websocket http", urlHandler[:handlerTypeIdx])
		}
	}

	if err := http.Serve(ln, NewHTTPLogger(defaultHandler)); err != nil {
		log.Fatal(err)
	}
}
