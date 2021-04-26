package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// ACLRecord maps path regexp to required roles
type ACLRecord struct {
	Expr     *regexp.Regexp
	Roles    map[string]bool
	Methods  map[string]bool
	Hosts    map[string]bool
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
	case "CertKeyHash":
		if strings.HasPrefix(check, "file:") {
			pemFileData, err := os.ReadFile(check[5:])
			if err != nil {
				logf(nil, logLevelFatal, "Cannot read file %#v: %s", check[5:], err)
			}
			nrDone := 0
			for len(pemFileData) > 0 {
				var pemBlock *pem.Block
				pemBlock, pemFileData = pem.Decode(pemFileData)
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
				logf(nil, logLevelFatal, "No public keys or certificates found in %#v", check[5:])
			}
			logf(nil, logLevelInfo, "Got %d public keys from %#v for role %#v", nrDone, check[5:], name)
			return
		}
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
	var hosts map[string]bool
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
	rec := ACLRecord{re, make(map[string]bool), methods, hosts, matchURI}
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
		hostMatch := true
		if acl.Methods != nil {
			if _, ok := acl.Methods[r.Method]; !ok {
				methodMatch = false
			}
		}
		if acl.Hosts != nil {
			if _, ok := acl.Hosts[r.Host]; !ok {
				hostMatch = false
			}
		}
		testString := r.URL.Path
		if acl.MatchURI {
			testString = r.RequestURI
		}
		if methodMatch && hostMatch && acl.Expr.MatchString(testString) {
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
						//noinspection GoDeferInLoop
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
		default:
			return nil, errors.New("unsupported method")
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
				haveRoles[reqRole] = true
				findRoleCount--
			}
		}
		if findRoleCount == 0 {
			if rl := r.Context().Value(remoteLoggerContext); rl != nil {
				_ = rl.(*RemoteLogger).log("auth-ok", map[string]interface{}{
					"RequestNum": r.Context().Value("request-num"),
					"Roles":      haveRoles,
				})
			}
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
			case "Cert", "CertBy", "CertKeyHash":
			default:
				w.Header().Add("WWW-Authenticate", fmt.Sprintf("%s realm=\"auth-required\"", k))
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(err.Error()))
	}
}
