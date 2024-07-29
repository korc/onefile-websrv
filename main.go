// The MIT License
// Copyright 2018-2021 Lauri Korts-Pärn
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	cfg := &serverConfig{
		logger: &simpleLogger{currentLevel: logLevelWarning},
	}
	var (
		listenAddr    = flag.String("listen", ":80", "Listen ip:port or /path/to/unix-socket")
		certFile      = flag.String("cert", "", "SSL certificate file or autocert cache dir")
		certFileFb    = flag.String("cert-fallback", "", "Certificate file to use if ACME fails")
		keyFile       = flag.String("key", "", "SSL key file")
		acmeHTTP      = flag.String("acmehttp", ":80", "Listen address for ACME http-01 challenge")
		wsReadTimeout = flag.Duration("wstmout", 60*time.Second, "Websocket alive check timer in seconds")
		loglevelFlag  = flag.String("loglevel", "info", "Max log level (one of "+strings.Join(logLevelStr, ", ")+")")
		reqlog        = flag.String("reqlog", "", "URL to log request details to (supports also unix:///dir/unix-socket:/path URLs)")
		tls12Max      = flag.Bool("tls12max", false, "Use TLS1.2 as maximum supported version")
		acmeHosts     = flag.String("acmehost", "",
			"Autocert hostnames (comma-separated), -cert will be cache dir")
		argsEnvPrefix = flag.String("args-env", "WEBSRV_ARG", "read arguments from environment <prefix>1..<prefix>N")
	)
	var chroot *string
	if canChroot {
		chroot = flag.String("chroot", "", "chroot() to directory after start")
	}
	var userName *string
	if canSetregid && canSetreuid {
		userName = flag.String("user", "", "Switch to user (NOT RECOMMENDED)")
	}

	var authFlag, aclFlag, urlMaps, corsMaps, argsFiles, addHeaders ArrayFlag
	var x509Pat AuthX509PatFlag
	flag.Var(&authFlag, "auth", "alias to 'role'")
	flag.Var(&authFlag, "role", "[<role>[+<role2>]=]<method>:<auth> (multi-arg)")
	flag.Var(&x509Pat, "x509-pat", "{'*'|'*.'<sni_domain>|<sni>}=['require:']{'none'|'any'|'file:'<ca.pem>|'dn:A=B/C=D/1.2.3=XXX/...'} (multi-arg, default '*=any' if have cert auth roles and '*=none' otherwise)")
	flag.Var(&aclFlag, "acl", "[{host:<vhost..>|<method..>}]<path_regexp>=<role>[+<role2..>]:<role..> (multi-arg)")
	flag.Var(&urlMaps, "map", "[<vhost>]/<path>=<handler>:[<params>] (multi-arg, default '/=file:')")
	flag.Var(&corsMaps, "cors", "<path>=<allowed_origin> (multi-arg)")
	flag.Var(&argsFiles, "args-file", "files to read arguments from (multi-arg)")
	flag.Var(&addHeaders, "add-hdr", "add header ['*']<path_re>=<header_name>:<value_req_p> (multi-arg)")

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	if *argsEnvPrefix != "" {
		envArgs := []string{}
		envArgsIdx := 1
		for {
			value, have := os.LookupEnv(fmt.Sprintf("%s%d", *argsEnvPrefix, envArgsIdx))
			if !have {
				break
			}
			envArgs = append(envArgs, value)
			envArgsIdx++
		}
		flag.CommandLine.Parse(envArgs)
	}

	includedFiles := map[string]interface{}{}
	for i := 0; i < len(argsFiles); i++ {
		argsFile := argsFiles[i]
		if _, have := includedFiles[argsFile]; have {
			log.Printf("WARNING: cyclic inclusion: %#v", argsFile)
			continue
		}
		includedFiles[argsFile] = true
		if data, err := os.ReadFile(argsFile); err != nil {
			log.Fatalf("cannot open args file %#v: %s", argsFile, err)
		} else {
			flag.CommandLine.Parse(strings.Split(string(data), "\n"))
		}
	}

	currentLogLevel = logLevelInfo
	for ll, lstr := range logLevelStr {
		if strings.EqualFold(lstr, *loglevelFlag) {
			currentLogLevel = logLevel(ll)
		}
	}
	cfg.logger.SetLogLevel(currentLogLevel)
	cfg.certFile = *certFile

	if len(urlMaps) == 0 {
		_ = urlMaps.Set("/=file:")
	}

	var switchToUser *user.User
	if userName != nil && *userName != "" {
		var err error
		logf(nil, logLevelWarning, "Switch to user is discouraged, cf. https://github.com/golang/go/issues/1435")
		if switchToUser, err = user.Lookup(*userName); err != nil {
			logf(nil, logLevelFatal, "Looking up user %#v failed: %s", *userName, err)
		}
	}

	var defaultHandler http.Handler
	var authHandler *AuthHandler

	if len(addHeaders) > 0 {
		defaultHandler = &ModifyHeaderHandler{NextHandler: defaultHandler}
		for _, opt := range addHeaders {
			if err := defaultHandler.(*ModifyHeaderHandler).ParseAddHdr(opt); err != nil {
				logf(nil, logLevelFatal, "cannot add header option: %s", err)
			}
		}
	}

	if len(authFlag) > 0 {
		authHandler = &AuthHandler{DefaultHandler: defaultHandler}
		defaultHandler = authHandler
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
			if err := defaultHandler.(*CORSHandler).AddRecord(cors[:pathIdx], cors[pathIdx+1:]); err != nil {
				log.Fatalf("Could not add CORS record: %s", err)
			}
		}
	}

	listenProto := "tcp"
	if (*listenAddr)[:1] == "/" || (*listenAddr)[:1] == "@" || (*listenAddr)[:2] == "./" {
		listenProto = "unix"
		if (*listenAddr)[:1] != "@" {
			_ = os.Remove(*listenAddr)
		}
	}

	ln, err := net.Listen(listenProto, *listenAddr)
	if err != nil {
		logf(nil, logLevelFatal, "Listen on %#v failed: %s", *listenAddr, err)
	}
	logf(nil, logLevelInfo, "Listening on %s", ln.Addr().String())
	if *certFile != "" {
		var tlsConfig *tls.Config
		if *acmeHosts == "" {
			if *keyFile == "" {
				*keyFile = *certFile
			}
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
						return fmt.Errorf("hostname %#v does not match pattern %#v", host, *acmeHosts)
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
			getCert := acmeManager.GetCertificate
			if *certFileFb != "" {
				if *keyFile == "" {
					*keyFile = *certFileFb
				}
				crt, err := tls.LoadX509KeyPair(*certFileFb, *keyFile)
				if err != nil {
					logf(nil, logLevelFatal, "Loading X509 cert from %#v and %#v failed: %s",
						*certFileFb, *keyFile, err)
				}
				getCert = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if autoCert, err := acmeManager.GetCertificate(hello); err != nil {
						logf(nil, logLevelInfo, "using fallback, %#v autocert failed: %s",
							hello.ServerName, err)
						return &crt, nil
					} else {
						return autoCert, nil
					}
				}
			}
			tlsConfig = &tls.Config{GetCertificate: getCert}
			if *acmeHTTP != "" {
				go func() {
					if err := http.ListenAndServe(*acmeHTTP, acmeManager.HTTPHandler(nil)); err != nil {
						logf(nil, logLevelWarning, "cannot start ACME HTTP server at %s: %s", *acmeHTTP, err)
					}
				}()
			}
		}
		if *tls12Max {
			tlsConfig.MaxVersion = tls.VersionTLS12
		}
		if len(x509Pat) == 0 {
			if authHandler != nil && authHandler.HaveCertAuth {
				x509Pat.Set("*=any")
			} else {
				x509Pat.Set("*=none")
			}
		}

		if len(x509Pat) == 1 && x509Pat[0].SType == SNIPatternAny {
			tlsConfig.ClientAuth = x509Pat[0].ClientAuth
			tlsConfig.ClientCAs = x509Pat[0].ClientCAs
		} else {
			tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				pat := x509Pat.FindPat(chi)
				logf(nil, logLevelInfo, "x509 auth for %s: %v", chi.ServerName, pat)
				if pat.ClientAuth == tls.NoClientCert {
					return nil, nil
				}
				newConf := tlsConfig.Clone()
				newConf.ClientAuth = pat.ClientAuth
				newConf.ClientCAs = pat.ClientCAs
				return newConf, nil
			}
		}
		ln = tls.NewListener(ln, tlsConfig)
		logf(nil, logLevelInfo, "SSL enabled, cert=%s", *certFile)
	} else {
		logf(nil, logLevelWarning, "SSL not enabled")
	}
	if chroot != nil && *chroot != "" {
		if err := os.Chdir(*chroot); err != nil {
			logf(nil, logLevelFatal, "Cannot chdir to %#v: %v", *chroot, err)
		}
		if err := Chroot("."); err != nil {
			logf(nil, logLevelFatal, "Changing root to %#v failed: %s", *chroot, err)
		}
		logf(nil, logLevelInfo, "Changed root to %#v", *chroot)
	}
	if switchToUser != nil {
		gid, _ := strconv.Atoi(switchToUser.Gid)
		uid, _ := strconv.Atoi(switchToUser.Uid)
		if err := Setregid(gid, gid); err != nil {
			logf(nil, logLevelFatal, "Could not switch to gid %v: %v", gid, err)
		}
		if err := Setreuid(uid, uid); err != nil {
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
		case "file":
			http.Handle(urlPath, http.StripPrefix(urlPathNoHost, http.FileServer(http.Dir(handlerParams))))
		case "websocket", "ws":
			http.Handle(urlPath, newWebSocketHandler(handlerParams).setReadTimeout(*wsReadTimeout))
		default:
			if createHandler, have := protocolHandlers[urlHandler[:handlerTypeIdx]]; have {
				handler, err := createHandler(urlPath, handlerParams, cfg)
				if err != nil {
					log.Fatalf("could not create protocol handler for %#v: %s", urlHandler[:handlerTypeIdx], err)
				}
				http.Handle(urlPath, handler)
			} else {
				keys := []string{}
				for k := range protocolHandlers {
					keys = append(keys, k)
				}

				logf(nil, logLevelFatal, "Handler type %#v unknown, available: file, websocket(ws), %s",
					urlHandler[:handlerTypeIdx], strings.Join(keys, ", "))
			}
		}
	}

	var rl *RemoteLogger

	if *reqlog != "" {
		logTransport := http.DefaultTransport.(*http.Transport).Clone()
		for name, rt := range customHttpSchemas {
			logTransport.RegisterProtocol(name, rt())
		}
		rl = &RemoteLogger{*reqlog, &http.Client{Transport: logTransport}}
		ln = LoggedListener{ln, rl}
		_ = rl.log("server-start", struct {
			ListenAddress string
		}{*listenAddr})
	}

	if err := http.Serve(ln, NewHTTPLogger(defaultHandler, rl)); err != nil {
		logf(nil, logLevelFatal, "Cannot serve: %s", err)
	}
}
