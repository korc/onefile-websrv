package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type claimRepl struct {
	re   *regexp.Regexp
	repl string
}

type jwtHandler struct {
	options      map[string]string
	method       jwt.SigningMethod
	key          interface{}
	claims       map[string]string
	claimReplMap map[string]*claimRepl
}

var ErrNoPEMKey = errors.New("no RSA/EC/PUBLIC PEM data found")
var ErrNoEnvVar = errors.New("environment variable not set")
var ErrBadResponse = errors.New("bad HTTP response code")

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

type storedToken struct {
	storedFor   string
	storedAt    time.Time
	accessToken string
}

var storedTokens = map[string]storedToken{}
var storedTokensMutex = sync.Mutex{}

func (j *jwtHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	claims := make(jwt.MapClaims)
	if j.claims != nil {
		for key, vstr := range j.claims {
			var val interface{} = vstr
			if newVal, solved, err := GetRequestParam(vstr, req); solved {
				if subst, have := j.claimReplMap[key]; have {
					val = subst.re.ReplaceAllString(newVal, subst.repl)
				} else {
					val = newVal
				}
			} else if err != nil {
				if err == ErrValueNotSet {
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
	if kid, hasKid := j.options["kid"]; hasKid {
		token.Header["kid"] = kid
	}
	jwtStr, err := token.SignedString(j.key)
	if err != nil {
		logf(req, logLevelError, "Could not sign: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if j.options["store-for"] != "" {
		storeOAuthToken(w, req, j.options["store-for"], jwtStr)
	} else {
		w.Header().Add("Content-Type", "application/jwt")
		w.Write([]byte(jwtStr))
	}
}

func writeOAuthError(w http.ResponseWriter, r *http.Request, errorCode, errorDescription string) {
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusBadRequest)
	errorData := map[string]interface{}{
		"error": errorCode,
	}
	if errorDescription != "" {
		errorData["error_description"] = errorDescription
	}
	if err := json.NewEncoder(w).Encode(errorData); err != nil {
		logf(r, logLevelError, "cannot encode error: %s", err)
	}
}

func storeOAuthToken(w http.ResponseWriter, r *http.Request, storeFor, value string) {
	logf(r, logLevelInfo, "storing token")

	codeBytes := make([]byte, 20)
	rand.Reader.Read(codeBytes)
	code := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").EncodeToString(codeBytes)
	storeForValue, solved, err := GetRequestParam(storeFor, r)
	if !solved {
		logf(r, logLevelError, "cannot get store-for parameter %#v: %s", storeFor, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("cannot solve store-for"))
		return
	}
	storedTokensMutex.Lock()
	storedTokens[code] = storedToken{
		accessToken: value,
		storedAt:    time.Now(),
		storedFor:   storeForValue,
	}
	storedTokensMutex.Unlock()
	w.Header().Add("Content-Type", "application/oauth-code")
	w.Write([]byte(code))
}

func retrieveStoredOAuthCode(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PUT" {
		storeOAuthToken(w, r, "str:"+r.PostFormValue("redirect_uri"), r.PostFormValue("jwt"))
		return
	}
	if r.Method != "POST" {
		logf(r, logLevelError, "using method %#v instead 'POST'", r.Method)
		writeOAuthError(w, r, "invalid_request", "wrong method")
		return
	}

	if os.Getenv("DEBUG_RETRIEVE_OAUTH") != "" {
		r.ParseForm()
		logf(r, logLevelInfo, "POST parameters: %#v", r.PostForm)
		u, p, ok := r.BasicAuth()
		logf(r, logLevelInfo, "Basic auth: ok=%#v username=%#v password=%#v", ok, u, p)
	}

	if grantType := r.PostFormValue("grant_type"); grantType != "authorization_code" {
		logf(r, logLevelError, "invalid grant type %#v", grantType)
		if grantType == "" {
			writeOAuthError(w, r, "invalid_request", "missing grant_type")
		} else {
			writeOAuthError(w, r, "unsupported_grant_type", "")
		}
		return
	}
	code := r.PostFormValue("code")
	if code == "" {
		logf(r, logLevelError, "no code")
		writeOAuthError(w, r, "invalid_request", "no code")
		return
	}
	redirectUri := r.PostFormValue("redirect_uri")
	if redirectUri == "" {
		logf(r, logLevelError, "no redirect_uri")
		writeOAuthError(w, r, "invalid_request", "no redirect_uri")
		return
	}
	storedTokensMutex.Lock()
	token, have := storedTokens[code]
	if have {
		delete(storedTokens, code)
	}
	storedTokensMutex.Unlock()
	if !have {
		logf(r, logLevelError, "no code %#v in storage", code)
		writeOAuthError(w, r, "invalid_grant", "no code in storage")
		return
	}
	if redirectUri != token.storedFor {
		logf(r, logLevelError, "code %#v redirect_uri %#v does not match stored-for %#v", code, redirectUri, token.storedFor)
		writeOAuthError(w, r, "invalid_grant", "bad redirect_uri")
		return
	}
	w.Header().Add("Content-Type", "application/json;charset=UTF-8")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"id_token":   token.accessToken,
		"token_type": "bearer",
	}); err != nil {
		logf(r, logLevelError, "cannot encode response: %s", err)
	}
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
	handler = &jwtHandler{
		options:      options,
		claims:       map[string]string{"exp": "ts:+5m"},
		claimReplMap: make(map[string]*claimRepl),
	}
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
		case "b64", "alg", "kid", "store-for":
		default:
			if strings.HasSuffix(opt, "_repl") {
				parts := strings.Split(val, val[:1])
				if len(parts) != 4 {
					logf(nil, logLevelFatal, "claim replacement does not follow ^regexp^repl^ pattern")
				}
				if re, err := regexp.Compile(parts[1]); err == nil {
					handler.claimReplMap[opt[:len(opt)-5]] = &claimRepl{
						re:   re,
						repl: parts[2],
					}
				} else {
					logf(nil, logLevelFatal, "cannot compile %#v claim substitution regexp: %#s", opt, err)
				}
				continue
			}
			handler.claims[strings.TrimSuffix(opt, "_claim")] = val
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

	if signAlgo == "jwk" {
		var err error
		var kid string
		signAlgo, signingSource, kid, err = parseJWK(signingSource)
		if err != nil {
			logf(nil, logLevelFatal, "Could not read JWK data from %s", err)
		}
		if _, have := options["kid"]; kid != "" && !have {
			options["kid"] = kid
		}
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

func parseJWK(data []byte) (signAlgo string, asnData []byte, kid string, err error) {
	jwk := map[string]interface{}{}

	err = json.Unmarshal(data, &jwk)
	if err != nil {
		return "", nil, "", err
	}
	if kidVal, has := jwk["kid"]; has {
		kid = kidVal.(string)
	}
	signAlgo = jwk["alg"].(string)
	switch signAlgo {
	case "ES256", "ES384", "ES512":
		key := ecdsa.PrivateKey{}
		switch jwk["crv"].(string) {
		case "P-224":
			key.Curve = elliptic.P224()
		case "P-256":
			key.Curve = elliptic.P256()
		case "P-384":
			key.Curve = elliptic.P384()
		case "P-521":
			key.Curve = elliptic.P521()
		default:
			return "", nil, "", fmt.Errorf("unknown %s curve: %s", signAlgo, jwk["crv"].(string))
		}
		var data []byte
		data, err = base64.RawURLEncoding.DecodeString(jwk["d"].(string))
		if err != nil {
			logf(nil, logLevelFatal, "cannot decode 'd': %s", err)
			return "", nil, "", err
		}
		key.D = big.NewInt(0).SetBytes(data)

		data, err = base64.RawURLEncoding.DecodeString(jwk["x"].(string))
		if err != nil {
			logf(nil, logLevelFatal, "cannot decode 'x': %s", err)
			return "", nil, "", err
		}
		key.X = big.NewInt(0).SetBytes(data)

		data, err = base64.RawURLEncoding.DecodeString(jwk["y"].(string))
		if err != nil {
			logf(nil, logLevelFatal, "cannot decode 'y': %s", err)
			return "", nil, "", err
		}
		key.Y = big.NewInt(0).SetBytes(data)

		asnData, err = x509.MarshalECPrivateKey(&key)
		asnData = pem.EncodeToMemory(&pem.Block{Bytes: asnData, Type: "EC PRIVATE KEY"})
		return
	default:
		return "", nil, "", fmt.Errorf("unknown signing algorithm: %s", signAlgo)
	}
}

func init() {
	addProtocolHandler("jwt", func(_, s string, sc *serverConfig) (http.Handler, error) {
		sc.logger.Log(logLevelInfo, "new JWT handler", map[string]interface{}{"parameters": s})
		return newJWTHandler(s), nil
	})
	addProtocolHandler("oauth-token", func(urlPath, params string, cfg *serverConfig) (http.Handler, error) {
		cfg.logger.Log(logLevelInfo, "new OAuth token retriever", map[string]interface{}{"parameters": params})
		return http.HandlerFunc(retrieveStoredOAuthCode), nil
	})
}
