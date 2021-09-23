package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

type jwtHandler struct {
	options map[string]string
	method  jwt.SigningMethod
	key     interface{}
	claims  map[string]string
}

func (j *jwtHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	claims := make(jwt.MapClaims)
	if j.claims != nil {
		for key, vstr := range j.claims {
			var val interface{} = vstr
			if strings.HasPrefix(vstr, "str:") {
				val = vstr[4:]
			} else if strings.HasPrefix(vstr, "crt:") {
				if req.TLS == nil {
					logf(req, logLevelError, "JWT wants X509 info from non-TLS request")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if req.TLS.PeerCertificates == nil || len(req.TLS.PeerCertificates) == 0 {
					logf(req, logLevelError, "JWT wants to set %#v from X509 %s, but there are no client certificate", key, vstr[4:])
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				crt := req.TLS.PeerCertificates[0]
				switch vstr[4:] {
				case "cn":
					val = crt.Subject.CommonName
				case "subj":
					val = crt.Subject.String()
				case "fp":
					h := sha256.New()
					h.Write(crt.Raw)
					val = hex.EncodeToString(h.Sum(nil))
				case "crt":
					val = base64.StdEncoding.EncodeToString(crt.Raw)
				default:
					logf(req, logLevelWarning, "crt param %#v not in: cn, subj, fp, crt", vstr[4:])
				}
			} else if strings.HasPrefix(vstr, "q:") {
				if !req.URL.Query().Has(vstr[2:]) {
					continue
				}
				val = req.URL.Query().Get(vstr[2:])
			} else if strings.HasPrefix(vstr, "post:") {
				val = req.PostFormValue(vstr[5:])
			} else if strings.HasPrefix(vstr, "hdr:") {
				val = req.Header.Get(vstr[4:])
			} else if strings.HasPrefix(vstr, "env:") {
				val = os.Getenv(vstr[4:])
			} else if strings.HasPrefix(vstr, "req:") {
				switch vstr[4:] {
				case "raddr":
					val = req.RemoteAddr
				case "rip":
					val, _, _ = net.SplitHostPort(req.RemoteAddr)
				case "host":
					val = req.Host
				default:
					logf(req, logLevelWarning, "req param %#v not in: host, rip, raddr", vstr[4:])
					continue
				}
			} else if strings.HasPrefix(vstr, "ts:") {
				vstr = vstr[3:]
				st := time.Now()
				if strings.HasPrefix(vstr, "q:") {
					q := req.URL.Query().Get(vstr[2:])
					if q == "" {
						q = "0"
					}
					if dur, err := time.ParseDuration(q); err != nil {
						logf(req, logLevelError, "cannot parse ts duration from query %#v = %#v: %s", vstr[2:], q, err)
						w.WriteHeader(http.StatusBadRequest)
						return
					} else {
						st = st.Add(dur)
						vstr = ""
					}
				} else if strings.HasPrefix(vstr, "today") {
					st = time.Date(st.Year(), st.Month(), st.Day(), 0, 0, 0, 0, st.Location())
					vstr = vstr[5:]
				}
				if vstr != "" {
					if !strings.HasPrefix(vstr, "-") && !strings.HasPrefix(vstr, "+") {
						logf(req, logLevelError, "ts duration needs to prefixed with '+' or '-', is %#v", vstr)
						continue
					}
					if dur, err := time.ParseDuration(vstr); err != nil {
						logf(req, logLevelError, "cannot parse ts duration %#v: %s", vstr, err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					} else {
						st = st.Add(dur)
					}
				}
				val = st.Unix()
			}
			claims[key] = val
		}
	}
	token := jwt.NewWithClaims(j.method, claims)
	jwtStr, err := token.SignedString(j.key)
	if err != nil {
		logf(req, logLevelError, "Could not sign: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/jwt")
	w.Write([]byte(jwtStr))
}

func loadPEMType(pemType string, data []byte) []byte {
	for len(data) > 0 {
		var pemBlock *pem.Block
		pemBlock, data = pem.Decode(data)
		if pemBlock == nil {
			return nil
		}
		if pemBlock.Type == pemType {
			return pemBlock.Bytes
		}
	}
	return nil
}

func newJWTHandler(params string) (handler *jwtHandler) {
	options, args := parseCurlyParams(params)
	signingSource := []byte(args)
	handler = &jwtHandler{options: options, claims: map[string]string{"exp": "ts:+5m"}}
	if strings.HasPrefix(args, "str:") {
		signingSource = []byte(os.Getenv(args[4:]))
	} else if strings.HasPrefix(args, "file:") {
		var err error
		signingSource, err = os.ReadFile(args[5:])
		if err != nil {
			logf(nil, logLevelFatal, "Cannot read JWT data: %s", err)
		}
	} else if strings.HasPrefix(args, "env:") {
		signingSource = []byte(os.Getenv(args[4:]))
	}
	for opt, val := range options {
		switch opt {
		case "exp":
			if val == "" {
				delete(handler.claims, "exp")
				continue
			} else {
				handler.claims[opt] = val
			}
		case "b64", "alg":
		default:
			if strings.HasSuffix(opt, "_claim") {
				opt = opt[:len(opt)-6]
			}
			handler.claims[opt] = val
		}
	}
	if v, _ := strconv.ParseBool(options["b64"]); v {
		dstBuf := make([]byte, base64.StdEncoding.DecodedLen(len(signingSource)))
		if n, err := base64.StdEncoding.Decode(dstBuf, signingSource); err != nil {
			logf(nil, logLevelFatal, "Could not decode b64: %s", err)
		} else {
			signingSource = dstBuf[:n]
		}
	}

	signAlgo, haveAlgSet := options["alg"]
	if !haveAlgSet {
		signAlgo = "HS256"
	}

	handler.method = jwt.GetSigningMethod(signAlgo)
	switch signAlgo {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		keyData := loadPEMType("RSA PRIVATE KEY", signingSource)
		if keyData == nil {
			logf(nil, logLevelFatal, "Could not find 'RSA PRIVATE KEY' PEM data in %#v", args)
		}
		var err error
		handler.key, err = x509.ParsePKCS1PrivateKey(keyData)
		if err != nil {
			logf(nil, logLevelFatal, "Could not load RSA key from %#v: %s", args, err)
		}
	case "ES256", "ES384", "ES512":
		keyData := loadPEMType("EC PRIVATE KEY", signingSource)
		if keyData == nil {
			logf(nil, logLevelFatal, "Could not find 'EC PRIVATE KEY' PEM data in %#v", args)
		}
		var err error
		handler.key, err = x509.ParseECPrivateKey(keyData)
		if err != nil {
			logf(nil, logLevelFatal, "Could not load RSA key from %#v: %s", args, err)
		}
	case "HS256", "HS384", "HS512":
		handler.key = signingSource
	default:
		logf(nil, logLevelFatal, "Unknown key type: %#v", signAlgo)
	}
	return
}
