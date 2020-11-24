// The MIT License
// Copyright 2018-2020 Lauri Korts-Pärn
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httputil"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/webdav"
)

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

type arrayFlag []string

func (f *arrayFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *arrayFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
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
		tls12Max      = flag.Bool("tls12max", false, "Use TLS1.2 as maximum supported version")
		acmeHosts     = flag.String("acmehost", "",
			"Autocert hostnames (comma-separated), -cert will be cache dir")
	)
	var authFlag, aclFlag, urlMaps, corsMaps arrayFlag
	flag.Var(&authFlag, "auth", "[<role>[+<role2>]=]<method>:<auth> (multi-arg)")
	flag.Var(&aclFlag, "acl", "[{host:<vhost..>|<method..>}]<path_regexp>=<role>[+<role2..>]:<role..> (multi-arg)")
	flag.Var(&urlMaps, "map", "[<vhost>]/<path>=<handler>:[<params>] (multi-arg, default '/=file:')")
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
			var hostnamePolicy autocert.HostPolicy
			if (*acmeHosts)[:1] == "^" {
				hostNameRe, err := regexp.Compile(*acmeHosts)
				if err != nil {
					log.Fatalf("Cannot compile acme hosts name %#v as regular expression: %s", *acmeHosts, err)
				}
				hostnamePolicy = func(_ context.Context, host string) error {
					if !hostNameRe.MatchString(host) {
						return fmt.Errorf("Hostname %#v does not match pattern %#v", host, *acmeHosts)
					}
					return nil
				}
			} else {
				hostnamePolicy = autocert.HostWhitelist(strings.Split(*acmeHosts, ",")...)
			}
			acmeManager := autocert.Manager{
				Cache:      autocert.DirCache(*certFile),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: hostnamePolicy,
			}
			tlsConfig = &tls.Config{GetCertificate: acmeManager.GetCertificate}
			if *acmeHTTP != "" {
				go http.ListenAndServe(*acmeHTTP, acmeManager.HTTPHandler(nil))
			}
		}
		if *tls12Max {
			tlsConfig.MaxVersion = tls.VersionTLS12
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
		if !strings.Contains(urlPath, "/") {
			logf(nil, logLevelFatal, "URL path does not contain '/' (format: [<vhost>]/[<subpath>])")
		}
		urlPathNoHost := urlPath[strings.Index(urlPath, "/"):]
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
			http.Handle(urlPath, http.StripPrefix(urlPathNoHost, http.FileServer(http.Dir(handlerParams))))
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
				Prefix:     urlPathNoHost,
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
				} else if strings.HasPrefix(handlerParams, "exec:") {
					execString := handlerParams[strings.Index(handlerParams, ":")+1:]
					shCmd := connectParams["sh"]
					if shCmd == "" {
						shCmd = "/bin/sh"
					}
					shArgs := []string{}
					if _, ok := connectParams["no-c"]; !ok {
						shArgs = append(shArgs, "-c")
					}
					shArgs = append(shArgs, execString)
					conn, err = newExecConn(shCmd, shArgs...)
					if err != nil {
						logf(r, logLevelError, "Cannot start %#v: %s", execString, err)
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
			connectParams, handlerParams := parseCurlyParams(handlerParams)
			httpURL, err := url.Parse(handlerParams)
			if err != nil {
				logf(nil, logLevelFatal, "Cannot parse %#v as URL: %v", handlerParams, err)
			}
			prxHandler := httputil.NewSingleHostReverseProxy(httpURL)

			defaultDirector := prxHandler.Director
			prxHandler.Director = func(request *http.Request) {
				defaultDirector(request)
				for _, hdr := range []string{"fp-hdr", "cn-hdr", "cert-hdr", "subj-hdr"} {
					if hdrName, ok := connectParams[hdr]; ok {
						// Scrub possible auth-related headers from request
						request.Header.Del(hdrName)
					}
				}
				if *certFile != "" {
					request.Header.Set("X-Forwarded-Proto", "https")
					if request.TLS != nil {
						if fpHeader, ok := connectParams["fp-hdr"]; ok {
							for _, crt := range request.TLS.PeerCertificates {
								h := sha256.New()
								h.Write(crt.Raw)
								request.Header.Add(fpHeader, hex.EncodeToString(h.Sum(nil)))
							}
						}
						if subjHeader, ok := connectParams["subj-hdr"]; ok {
							for _, crt := range request.TLS.PeerCertificates {
								request.Header.Add(subjHeader, crt.Subject.String())
							}
						}
						if cnHeader, ok := connectParams["cn-hdr"]; ok {
							for _, crt := range request.TLS.PeerCertificates {
								request.Header.Add(cnHeader, crt.Subject.CommonName)
							}
						}
						if crtHdr, ok := connectParams["cert-hdr"]; ok {
							for _, crt := range request.TLS.PeerCertificates {
								request.Header.Add(crtHdr, hex.EncodeToString(crt.Raw))
							}
						}
					}
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
			http.Handle(urlPath, http.StripPrefix(urlPathNoHost, prxHandler))
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
			http.Handle(urlPath, &cgi.Handler{Path: handlerParams, Root: strings.TrimRight(urlPathNoHost, "/"), Env: env, InheritEnv: inhEnv, Args: args})
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
