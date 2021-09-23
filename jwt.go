package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
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

var ErrCantSolve = errors.New("impossible to solve claim value")
var ErrWontSet = errors.New("conditions make it skip the claim")
var ErrNoPEMKey = errors.New("no RSA/EC/PUBLIC PEM data found")
var ErrNoEnvVar = errors.New("environment variable not set")

func parsePEMKey(data []byte) (key interface{}, err error) {
	var block *pem.Block
	for len(data) > 0 {
		block, data = pem.Decode(data)
		if block == nil {
			return nil, ErrNoPEMKey
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		case "PUBLIC KEY":
			return x509.ParsePKIXPublicKey(block.Bytes)
		}
	}
	return
}

func parseJWTKeyString(keyString string) (data []byte, err error) {
	data = []byte(keyString)
	if strings.HasPrefix(keyString, "str:") {
		data = []byte(os.Getenv(keyString[4:]))
	} else if strings.HasPrefix(keyString, "file:") {
		data, err = os.ReadFile(keyString[5:])
		if err != nil {
			return
		}
	} else if strings.HasPrefix(keyString, "env:") {
		if s, ok := os.LookupEnv(keyString[4:]); ok {
			data = []byte(s)
		} else {
			return nil, ErrNoEnvVar
		}
	}
	return
}

func solveClaimStringValue(vstr string, req *http.Request) (string, bool, error) {
	if strings.HasPrefix(vstr, "str:") {
		return vstr[4:], true, nil
	} else if strings.HasPrefix(vstr, "crt:") {
		if req.TLS == nil {
			logf(req, logLevelError, "JWT wants X509 info from non-TLS request")
			return "", false, ErrCantSolve
		}
		if req.TLS.PeerCertificates == nil || len(req.TLS.PeerCertificates) == 0 {
			logf(req, logLevelError, "want set claim from X509 %s, but there are no client certificate", vstr[4:])
			return "", false, ErrCantSolve
		}
		crt := req.TLS.PeerCertificates[0]
		switch vstr[4:] {
		case "cn":
			return crt.Subject.CommonName, true, nil
		case "subj":
			return crt.Subject.String(), true, nil
		case "fp":
			h := sha256.New()
			h.Write(crt.Raw)
			return hex.EncodeToString(h.Sum(nil)), true, nil
		case "crt":
			return base64.StdEncoding.EncodeToString(crt.Raw), true, nil
		default:
			logf(req, logLevelWarning, "crt param %#v not in: cn, subj, fp, crt", vstr[4:])
		}
	} else if strings.HasPrefix(vstr, "q:") {
		if !req.URL.Query().Has(vstr[2:]) {
			return "", false, ErrWontSet
		}
		return req.URL.Query().Get(vstr[2:]), true, nil
	} else if strings.HasPrefix(vstr, "post:") {
		return req.PostFormValue(vstr[5:]), true, nil
	} else if strings.HasPrefix(vstr, "hdr:") {
		return req.Header.Get(vstr[4:]), true, nil
	} else if strings.HasPrefix(vstr, "env:") {
		return os.Getenv(vstr[4:]), true, nil
	} else if strings.HasPrefix(vstr, "req:") {
		switch vstr[4:] {
		case "raddr":
			return req.RemoteAddr, true, nil
		case "rip":
			val, _, _ := net.SplitHostPort(req.RemoteAddr)
			return val, true, nil
		case "host":
			return req.Host, true, nil
		default:
			logf(req, logLevelWarning, "req param %#v not in: host, rip, raddr", vstr[4:])
			return "", false, ErrWontSet
		}
	}
	return "", false, nil
}

func (j *jwtHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	claims := make(jwt.MapClaims)
	if j.claims != nil {
		for key, vstr := range j.claims {
			var val interface{} = vstr
			if newVal, solved, err := solveClaimStringValue(vstr, req); solved {
				val = newVal
			} else if err != nil {
				if err == ErrWontSet {
					continue
				}
				w.WriteHeader(http.StatusBadRequest)
				return
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
