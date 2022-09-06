package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/ssh"
)

type ErrNeedAuthRedirected struct {
	RedirectTo string
	Err        error
}

func (e ErrNeedAuthRedirected) Unwrap() error {
	return e.Err
}

func (e ErrNeedAuthRedirected) Error() string {
	return e.Err.Error() + "[redirect to: " + e.RedirectTo + "]"
}

var ErrNeedAuth = errors.New("need auth")

var redirectVarRe = regexp.MustCompile("@.*?@")

// ACLRecord maps path regexp to required roles
type ACLRecord struct {
	Expr         *regexp.Regexp
	Roles        map[string]bool
	RolesToCheck map[string]interface{}
	Methods      map[string]bool
	Hosts        map[string]bool
	MatchURI     bool
	OnFail       string
}

type Authenticator interface {
	GetRoles(req *http.Request, rolesToCheck map[string]interface{}) ([]string, error)
}

type AuthNFactory func(check string, roles []string) (Authenticator, error)

// AuthHandler passes request to next http.Handler if authorization allows
type AuthHandler struct {
	http.Handler
	DefaultHandler http.Handler
	Auths          map[string]map[string]string
	Authenticators []Authenticator
	ACLs           []ACLRecord
}

const jwtParams = `(cookie|header|query)=([A-Za-z0-9_-]+)`

var (
	authEnvDef      = regexp.MustCompile(`\$\{[a-zA-Z0-9_]+\}`)
	jwtParamDetect  = regexp.MustCompile(`^\{` + jwtParams + `(?:,` + jwtParams + `)*\}`)
	jwtParamExtract = regexp.MustCompile(jwtParams)
	subgroupMatchRe = regexp.MustCompile(`\$[0-9]+`)

	sshKeyRe = regexp.MustCompile("(ssh-rsa)[[:space:]]+([^[:space:]]+)")

	authMethods = make(map[string]AuthNFactory)
)

func addAuthMethod(name string, authFactory AuthNFactory) {
	authMethods[name] = authFactory
}

func sshKeysToPEM(in []byte) (out []byte) {
	out = make([]byte, 0)
	for st := 0; st >= 0 && st < len(in); {
		i := bytes.IndexByte(in[st:], '\n')
		if i < 0 {
			out = append(out, in[st:]...)
			break
		}
		line := in[st : st+i]
		st = st + i + 1
		if match := sshKeyRe.FindSubmatch(line); match != nil {
			keyData, err := base64.StdEncoding.DecodeString(string(match[2]))
			if err != nil {
				logf(nil, logLevelFatal, "Cannot b64decode SSH key data: %s", err)
			}
			typeStrLen := binary.BigEndian.Uint32(keyData)
			if typeString := keyData[4 : 4+typeStrLen]; !bytes.Equal(typeString, match[1]) {
				logf(nil, logLevelWarning, "wrong key type: %v != %v", string(typeString), string(match[1]))
				continue
			}
			var keyStruct struct {
				E    *big.Int
				N    *big.Int
				Rest []byte `ssh:"rest"`
			}
			if err := ssh.Unmarshal(keyData[4+typeStrLen:], &keyStruct); err != nil {
				logf(nil, logLevelFatal, "could not parse rsa key structure: %s", err)
			}
			pubKey := &rsa.PublicKey{E: int(keyStruct.E.Int64()), N: keyStruct.N}
			pemBytes, err := x509.MarshalPKIXPublicKey(pubKey)
			if err != nil {
				logf(nil, logLevelFatal, "could not marshal key: %s", err)
			}
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{}, Bytes: pemBytes})...)
		} else {
			out = append(append(out, line...), '\n')
		}
	}
	return
}

// AddAuth : add authentication method to identify role(s)
func (ah *AuthHandler) AddAuth(method, check, name string) {
	if ah.Auths == nil {
		ah.Auths = make(map[string]map[string]string)
	}

	if ah.Authenticators == nil {
		ah.Authenticators = make([]Authenticator, 0)
	}

	check = authEnvDef.ReplaceAllStringFunc(check, func(s string) string {
		if val, ok := os.LookupEnv(s[2 : len(s)-1]); ok {
			return val
		}
		logf(nil, logLevelFatal, "Cannot find variable in environment: %#v", s)
		return ""
	})

	switch method {
	case "CertKeyHash":
		if strings.HasPrefix(check, "file:") {
			fileName := check[5:]
			data, err := os.ReadFile(fileName)
			if err != nil {
				logf(nil, logLevelFatal, "Cannot read file %#v: %s", fileName, err)
			}
			nrDone := 0
			if len(data) > 0 {
				data = sshKeysToPEM(data)
			}
			for len(data) > 0 {
				var pemBlock *pem.Block
				pemBlock, data = pem.Decode(data)
				if pemBlock == nil {
					break
				}
				switch pemBlock.Type {
				case "PUBLIC KEY":
					if _, err := x509.ParsePKIXPublicKey(pemBlock.Bytes); err != nil {
						logf(nil, logLevelFatal, "Cannot parse public key: %s", err)
					}
				case "CERTIFICATE":
					crt, err := x509.ParseCertificate(pemBlock.Bytes)
					if err != nil {
						logf(nil, logLevelFatal, "Cannot parse certificate: %s", err)
					}
					pemBlock = &pem.Block{Bytes: crt.RawSubjectPublicKeyInfo}
				default:
					logf(nil, logLevelInfo, "Skipping %#v pem data", pemBlock.Type)
					continue
				}
				h := sha256.New()
				h.Write(pemBlock.Bytes)
				ah.AddAuth(method, hex.EncodeToString(h.Sum(nil)), name)
				nrDone += 1

			}
			if nrDone == 0 {
				logf(nil, logLevelFatal, "No public keys or certificates found in %#v", fileName)
			}
			logf(nil, logLevelInfo, "Got %d public keys from %#v for role %#v", nrDone, fileName, name)
			return
		}
	case "Cert", "CertBy":
		if strings.HasPrefix(check, "file:") {
			fileName := check[5:]
			data, err := ioutil.ReadFile(fileName)
			if err != nil {
				logf(nil, logLevelFatal, "Cannot read file %#v: %s", fileName, err)
			}
			nrDone := 0
			var pemBlock *pem.Block
			for len(data) > 0 {
				pemBlock, data = pem.Decode(data)
				if pemBlock == nil {
					break
				}
				if pemBlock.Type != "CERTIFICATE" {
					continue
				}
				cert, err := x509.ParseCertificate(pemBlock.Bytes)
				if err != nil {
					logf(nil, logLevelFatal, "Could not load certificate: %s", err)
				}
				if method == "Cert" {
					h := sha256.New()
					h.Write(cert.Raw)
					ah.AddAuth(method, hex.EncodeToString(h.Sum(nil)), name)
				} else {
					ah.AddAuth(method, hex.EncodeToString(cert.Raw), name)
				}
				nrDone += 1
			}
			if nrDone == 0 {
				logf(nil, logLevelFatal, "No certificates found in %#v", fileName)
			}
			logf(nil, logLevelInfo, "Read %d certificates from %#v for role %#v", nrDone, fileName, name)
			return
		}
	case "JWTSecret", "JWTFilePat":
		logf(nil, logLevelWarning, "DEPRECATED: please use JWT auth method instead of %#v", method)
		if m1 := jwtParamDetect.FindString(check); m1 != "" {
			// TODO Caveat: overwrites previous role of same check
			check = check[len(m1):]
			for _, v := range strings.Split(m1[1:len(m1)-1], ",") {
				m2 := jwtParamExtract.FindStringSubmatch(v)
				jwtCheckLoc := "JWTCheck:" + m2[1]
				jwtCheckParam := m2[2]
				if ah.Auths[jwtCheckLoc] == nil {
					ah.Auths[jwtCheckLoc] = make(map[string]string)
				}
				// TODO: find more elegant solution
				ah.Auths[jwtCheckLoc][jwtCheckParam] = method + ":" + check
			}
		}
	case "Basic", "IPRange":
	default:
		if creator, have := authMethods[method]; have {
			authn, err := creator(check, strings.Split(name, "+"))
			if err != nil {
				logf(nil, logLevelFatal, "Could not create %s authenticator for %s: %s", check, name, err)
			}
			ah.Authenticators = append(ah.Authenticators, authn)
		} else {
			available := []string{"Basic", "Cert", "CertBy", "CertKeyHash", "JWTSecret", "JWTFilePat", "IPRange"}
			for m := range authMethods {
				available = append(available, m)
			}
			logf(nil, logLevelFatal, "Supported mechanisms: %s. Basic auth is base64 string, certs can use file:<file.crt>", strings.Join(available, ", "))
		}
	}
	if ah.Auths[method] == nil {
		ah.Auths[method] = make(map[string]string)
	}
	ah.Auths[method][check] = name
}

// AddACL : add roles constraint to matching path regexp
func (ah *AuthHandler) AddACL(reExpr string, roles []string) error {
	var methods map[string]bool
	var hosts map[string]bool
	var onFail string
	matchURI := false
	if strings.HasPrefix(reExpr, "?") {
		matchURI = true
		reExpr = reExpr[1:]
	}
	if strings.HasPrefix(reExpr, "{") {
		clidx := strings.Index(reExpr, "}")
		for _, v := range strings.Split(reExpr[1:clidx], ",") {
			if strings.HasPrefix(v, "host:") {
				if hosts == nil {
					hosts = make(map[string]bool)
				}
				hosts[v[5:]] = true
			} else if strings.HasPrefix(v, "onfail:") {
				onFail = v[7:]
			} else {
				if methods == nil {
					methods = make(map[string]bool)
				}
				methods[v] = true
			}
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
	rec := ACLRecord{re, make(map[string]bool), make(map[string]interface{}), methods, hosts, matchURI, onFail}
	for _, r := range roles {
		rec.Roles[r] = true
		for _, singleRole := range strings.Split(r, "+") {
			rec.RolesToCheck[singleRole] = true
		}
	}
	ah.ACLs = append(ah.ACLs, rec)
	return nil
}

func (ah *AuthHandler) checkAuthPass(r *http.Request) (*http.Request, error) {
	if ah.Auths == nil {
		return r, nil
	}

	neededRoles := make(map[string]bool)
	var rolesToCheck map[string]interface{}
	var errNoAuth = ErrNeedAuth
	for _, acl := range ah.ACLs {
		methodMatch := true
		hostMatch := true
		if acl.Methods != nil {
			if _, ok := acl.Methods[r.Method]; !ok {
				methodMatch = false
			}
		}
		if acl.Hosts != nil {
			host := r.Host
			if strings.Contains(host, ":") {
				var err error
				host, _, err = net.SplitHostPort(host)
				if err != nil {
					return nil, err
				}
			}
			if _, ok := acl.Hosts[host]; !ok {
				hostMatch = false
			}
		}
		testString := r.URL.Path
		if acl.MatchURI {
			testString = r.RequestURI
		}
		if methodMatch && hostMatch && acl.Expr.MatchString(testString) {
			neededRoles = acl.Roles
			rolesToCheck = acl.RolesToCheck
			if acl.OnFail != "" {
				errNoAuth = ErrNeedAuthRedirected{
					RedirectTo: redirectVarRe.ReplaceAllStringFunc(acl.OnFail, func(varName string) string {
						if varName == "@@" {
							return "@"
						}
						value, solved, err := GetRequestParam(varName[1:len(varName)-1], r)
						if !solved {
							logf(r, logLevelWarning, "cannot solve %#v: %s", varName, err)
							if err == nil {
								return varName
							}
							return ""
						}
						return url.QueryEscape(value)
					}),
					Err: errNoAuth,
				}
			}
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
			ah.checkAuthPassBearer(authValue, r, haveRoles, neededRoles)
		default:
			return nil, errors.New("unsupported method")
		}
	}

	if jwtCheckCookies, ok := ah.Auths["JWTCheck:cookie"]; ok {
		for cookieName, typeAndCheck := range jwtCheckCookies {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				continue
			}
			ah.checkAuthJWTParams(cookie.Value, typeAndCheck, r, haveRoles, neededRoles)
		}
	}

	if jwtCheckQuery, ok := ah.Auths["JWTCheck:query"]; ok {
		for qpName, typeAndCheck := range jwtCheckQuery {
			if qp := r.URL.Query().Get(qpName); qp != "" {
				ah.checkAuthJWTParams(qp, typeAndCheck, r, haveRoles, neededRoles)
			}
		}
	}

	if jwtCheckHeader, ok := ah.Auths["JWTCheck:header"]; ok {
		for hdrName, typeAndCheck := range jwtCheckHeader {
			if hdr := r.Header.Get(hdrName); hdr != "" {
				ah.checkAuthJWTParams(hdr, typeAndCheck, r, haveRoles, neededRoles)
			}
		}
	}

	if r.TLS != nil {
		var lastPeerCert *x509.Certificate
		for i, crt := range r.TLS.PeerCertificates {
			h := sha256.New()
			h.Write(crt.Raw)
			peerHash := hex.EncodeToString(h.Sum(nil))
			if lastPeerCert != nil {
				if err := lastPeerCert.CheckSignatureFrom(crt); err != nil {
					logf(r, logLevelWarning, "Client certificate chain broken at %d'th cert[%s]: %s", i, peerHash, err)
					break
				}
			}
			lastPeerCert = crt
			if certKeyHashes, ok := ah.Auths["CertKeyHash"]; ok {
				h := sha256.New()
				h.Write(crt.RawSubjectPublicKeyInfo)
				hashCheck := hex.EncodeToString(h.Sum(nil))
				if gotRoles, ok := certKeyHashes[hashCheck]; ok {
					for _, role := range strings.Split(gotRoles, "+") {
						haveRoles[role] = ah.ACLs == nil
					}
				}
			}
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

	for _, authn := range ah.Authenticators {
		addRoles, err := authn.GetRoles(r, rolesToCheck)
		if err != nil {
			logf(r, logLevelError, "Could not authenticate with %#v: %s", authn, err)
			return r, err
		}
		for _, role := range addRoles {
			haveRoles[role] = ah.ACLs == nil
		}
	}

	ctx := context.WithValue(r.Context(), authRoleContext, haveRoles)
	retReq := r.WithContext(ctx)

	if ah.ACLs == nil {
		if len(haveRoles) > 0 {
			return retReq, nil
		}
		return nil, errNoAuth
	}

	if len(neededRoles) == 0 {
		return retReq, nil
	}

	for role := range neededRoles {
		reqRoles := strings.Split(role, "+")
		findRoleCount := len(reqRoles)
		for _, reqRole := range reqRoles {
			if _, ok := haveRoles[reqRole]; ok {
				haveRoles[reqRole] = true
				findRoleCount--
			}
		}
		if findRoleCount == 0 {
			if rl := r.Context().Value(remoteLoggerContext); rl != nil {
				_ = rl.(*RemoteLogger).log("auth-ok", map[string]interface{}{
					"RequestNum": r.Context().Value(requestNumberContext),
					"Roles":      haveRoles,
				})
			}
			return retReq, nil
		}
	}

	if os.Getenv("LOG_AUTH_ROLES") != "" {
		logf(retReq, logLevelInfo, "auth NG, have=%v needed=%v", haveRoles, neededRoles)
	}

	return nil, errNoAuth
}

func (ah *AuthHandler) checkAuthPassJWTSecret(jwtString, signer string, r *http.Request, haveRoles, neededRoles map[string]bool) {
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		return []byte(signer), nil
	})
	if err != nil {
		return
	}
	if token.Valid {
		for _, gotRole := range strings.Split(ah.Auths["JWTSecret"][signer], "+") {
			haveRoles[gotRole] = ah.ACLs == nil
		}
	}
}

func (ah *AuthHandler) checkAuthPassJWTFilePat(jwtString, fpath string, r *http.Request, haveRoles, neededRoles map[string]bool) {
	// authValue is file path. '**' in filename will be tested in order of:
	// URL, URL without file extension, without filename, with all path components removed one by one
	haveStars := strings.Contains(fpath, "**")
	if haveStars && len(neededRoles) == 0 {
		// if we exactly don't require any roles, skip some-what expensive file search altogether
		return
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
			tkn, err := jwt.Parse(jwtString, func(token *jwt.Token) (i interface{}, e error) {
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
							return decodedVal, nil
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
			//logf(r, logLevelDebug, "Searching for JWT file from %#v for URL %#v (authvalue=%#v)",
			//	testPath, r.URL.Path, authValue)
		}
	}
}

func (ah *AuthHandler) checkAuthJWTParams(authValue, jwtTypeWithCheck string, r *http.Request, haveRoles, neededRoles map[string]bool) {
	tcSplit := strings.SplitN(jwtTypeWithCheck, ":", 2)
	jwtType, jwtCheck := tcSplit[0], tcSplit[1]
	if ah.Auths[jwtType] != nil && ah.Auths[jwtType][jwtCheck] != "" {
		switch jwtType {
		case "JWTSecret":
			ah.checkAuthPassJWTSecret(authValue, jwtCheck, r, haveRoles, neededRoles)
		case "JWTFilePat":
			ah.checkAuthPassJWTFilePat(authValue, jwtCheck, r, haveRoles, neededRoles)
		}
	}
}

func (ah *AuthHandler) checkAuthPassBearer(authValue string, r *http.Request, haveRoles, neededRoles map[string]bool) {
	for signer := range ah.Auths["JWTSecret"] {
		ah.checkAuthPassJWTSecret(authValue, signer, r, haveRoles, neededRoles)
	}
	for fpath := range ah.Auths["JWTFilePat"] {
		ah.checkAuthPassJWTFilePat(authValue, fpath, r, haveRoles, neededRoles)
	}
}

func (ah *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next := ah.DefaultHandler
	if next == nil {
		next = http.DefaultServeMux
	}

	if authenticatedRequest, err := ah.checkAuthPass(r); err == nil {
		if os.Getenv("LOG_AUTH_ROLES") != "" {
			if roles, ok := authenticatedRequest.Context().Value(authRoleContext).(map[string]bool); ok {
				logf(authenticatedRequest, logLevelInfo, "auth OK, roles=%v", roles)
			}
		}
		next.ServeHTTP(w, authenticatedRequest)
	} else if errRedirect, ok := err.(ErrNeedAuthRedirected); ok {
		w.Header().Set("Location", errRedirect.RedirectTo)
		w.WriteHeader(http.StatusFound)
		w.Write([]byte(err.Error()))
	} else {
		logf(r, logLevelInfo, "auth failed: %s", err)
		for k := range ah.Auths {
			switch k {
			case "JWTSecret", "JWTFilePat":
				w.Header().Add("WWW-Authenticate", "Bearer realm=\"Authentication required\"")
			case "Cert", "CertBy", "CertKeyHash":
			default:
				w.Header().Add("WWW-Authenticate", fmt.Sprintf("%s realm=\"auth-required\"", k))
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(err.Error()))
	}
}
