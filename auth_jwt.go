package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
)

func init() {
	addAuthMethod("JWT", func(check string, roles []string) (Authenticator, error) {
		return NewJWTAuthenticator(check, roles)
	})
}

type JWTAuthenticator struct {
	roles     []string
	jwtCookie string
	jwtQuery  string
	jwtHeader string
	key       interface{}
	isSecret  bool
}

func (jka *JWTAuthenticator) GetRoles(req *http.Request, rolesToCheck map[string]interface{}) (roles []string, err error) {
	sources := [][]string{}
	if authHdr := req.Header.Get("Authorization"); authHdr != "" {
		if strings.HasPrefix(authHdr, "Bearer ") {
			sources = append(sources, []string{authHdr[7:], "auth-hdr", "Bearer"})
		}
	}
	if jka.jwtCookie != "" {
		if cookie, err := req.Cookie(jka.jwtCookie); err == nil {
			sources = append(sources, []string{cookie.Value, "cookie", jka.jwtCookie})
		}
	}
	if jka.jwtHeader != "" {
		if hdr := req.Header.Get(jka.jwtHeader); hdr != "" {
			sources = append(sources, []string{hdr, "header", jka.jwtHeader})
		}
	}
	if jka.jwtQuery != "" {
		if q := req.URL.Query().Get(jka.jwtQuery); q != "" {
			sources = append(sources, []string{q, "query", jka.jwtHeader})
		}
	}

	for _, src := range sources {
		tokenString, srcType, srcName := src[0], src[1], src[2]
		if _, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return jka.key, nil
		}); err == nil {
			return jka.roles, nil
		} else if _, ok := err.(*jwt.ValidationError); !ok {
			logf(req, logLevelError, "Could not parse JWT from %s %#v=%#v: %s", srcType, srcName, tokenString, err)
			return nil, err
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

func NewJWTAuthenticator(check string, roles []string) (jka *JWTAuthenticator, err error) {
	options, jwtKey := parseCurlyParams(check)
	jka = &JWTAuthenticator{
		roles:     roles,
		jwtCookie: options["cookie"],
		jwtQuery:  options["query"],
		jwtHeader: options["header"],
	}

	signingSource, err := parseJWTKeyString(jwtKey)
	if err != nil {
		logf(nil, logLevelFatal, "Cannot read JWT data from %s: %s", jwtKey, err)
	}
	if v, _ := strconv.ParseBool(options["b64"]); v {
		dstBuf := make([]byte, base64.StdEncoding.DecodedLen(len(signingSource)))
		if n, err := base64.StdEncoding.Decode(dstBuf, signingSource); err != nil {
			logf(nil, logLevelFatal, "Could not decode b64: %s", err)
		} else {
			signingSource = dstBuf[:n]
		}
	}

	if v, _ := strconv.ParseBool(options["hs"]); v {
		jka.key = signingSource
		jka.isSecret = true
	} else {
		jka.key, err = parsePEMKey(signingSource)
		if err != nil {
			logf(nil, logLevelFatal, "could not read PEM key from %#v, use {hs=1} for HMAC signatures: %s", jwtKey, err)
		}
	}
	return
}
