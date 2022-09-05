package main

import (
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

var ErrUknAud = errors.New("unknown audience target")

func init() {
	addAuthMethod("JWT", func(check string, roles []string) (Authenticator, error) {
		return NewJWTAuthenticator(check, roles)
	})
}

type JWTAuthenticator struct {
	roles      []string
	jwtSources []string
	keyFunc    jwt.Keyfunc
	isSecret   bool
	audRe      *regexp.Regexp
	audTarget  string
}

type jwtTokenWithSource struct {
	tkn string
	src string
}

func (jka *JWTAuthenticator) GetRoles(req *http.Request, rolesToCheck map[string]interface{}) (roles []string, err error) {
	sources := []jwtTokenWithSource{}

	for _, param := range jka.jwtSources {
		if tkn, got, err := GetRequestParam(param, req); got {
			sources = append(sources, jwtTokenWithSource{tkn, param})
		} else if err == nil {
			logf(req, logLevelWarning, "unknown source: %#v", param)
		}
	}

	for _, src := range sources {
		if tkn, err := jwt.Parse(src.tkn, jka.keyFunc); err == nil {
			if jka.audTarget != "" {
				var thisAud string
				if jka.audTarget == "path" {
					thisAud = req.URL.Path
				} else if val, solved, err := GetRequestParam(jka.audTarget, req); solved {
					thisAud = val
				} else if err != nil {
					return nil, err
				} else {
					logf(req, logLevelWarning, "Unknown aud target: %#v", jka.audTarget)
					return nil, ErrUknAud
				}

				if jka.audRe != nil {
					match := jka.audRe.FindStringSubmatch(thisAud)
					if match == nil {
						continue
					}
					if len(match) > 1 {
						thisAud = match[1]
					} else {
						thisAud = match[0]
					}
				}

				if !tkn.Claims.(jwt.MapClaims).VerifyAudience(thisAud, true) {
					if os.Getenv("LOG_AUD_CHECK") != "" {
						logf(req, logLevelWarning, "audience check failed: not match %#v = %#v (re=%#v)", jka.audTarget, thisAud, jka.audRe)
					}
					continue
				}
			}
			return jka.roles, nil
		} else if _, ok := err.(*jwt.ValidationError); !ok {
			logf(req, logLevelError, "Could not parse JWT from %#v: %s", src, err)
			return nil, err
		}
	}
	return
}

func NewJWTAuthenticator(check string, roles []string) (jka *JWTAuthenticator, err error) {
	options, jwtKey := parseCurlyParams(check)
	jka = &JWTAuthenticator{
		roles:     roles,
		audTarget: options["aud"],
	}

	if noBearer, _ := strconv.ParseBool(options["no-bearer"]); !noBearer {
		jka.jwtSources = append(jka.jwtSources, "auth:bearer")
	}

	for k, v := range options {
		switch k {
		case "cookie":
			k = "src_cookie"
			v = "cookie:" + v
			logf(nil, logLevelInfo, "DEPRECATED: use src_xxx=cookie:name instead of cookie= as JWT source")
		case "query":
			k = "src_query"
			v = "q:" + v
			logf(nil, logLevelInfo, "DEPRECATED: use src_xxx=q:name instead of query= as JWT source")
		case "header":
			k = "src_header"
			v = "hdr:" + v
			logf(nil, logLevelInfo, "DEPRECATED: use src_xxx=hdr:name instead of header= as JWT source")
		}
		if !strings.HasPrefix(k, "src_") {
			continue
		}
		jka.jwtSources = append(jka.jwtSources, v)
	}

	if audRe, haveOpt := options["aud-re"]; haveOpt {
		jka.audRe, err = regexp.Compile(audRe)
		if err != nil {
			return nil, err
		}
		if jka.audTarget == "" {
			jka.audTarget = "path"
		}
	}

	if jka.audTarget != "" {
		if strings.HasPrefix(jka.audTarget, "env:") {
			if s, have := os.LookupEnv(jka.audTarget[4:]); have {
				jka.audTarget = "str:" + s
			} else {
				return nil, ErrNoEnvVar
			}
		} else if !strings.ContainsRune(jka.audTarget, ':') && jka.audTarget != "path" {
			logf(nil, logLevelFatal, "unknown aud target %#v, can be 'path', '<type>:<value>', or 'env:<varname>'", jka.audTarget)
		}
	}

	signingSource, err := parseJWTKeyString(jwtKey)
	if err != nil {
		logf(nil, logLevelFatal, "Cannot read JWT key data from %s: %s", jwtKey, err)
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
		jka.keyFunc = func(t *jwt.Token) (interface{}, error) {
			return signingSource, nil
		}
		jka.isSecret = true
	} else if v, _ := strconv.ParseBool(options["jwks"]); v {
		var jwks *keyfunc.JWKS
		var err error
		if strings.HasPrefix(jwtKey, "http:") {
			jwks, err = keyfunc.Get(jwtKey[5:], keyfunc.Options{})
		} else {
			jwks, err = keyfunc.NewJSON(signingSource)
		}
		if err != nil {
			logf(nil, logLevelFatal, "could not read parse JWKS from %s -> %#v: %s", jwtKey, string(signingSource), err)
		}
		jka.keyFunc = jwks.Keyfunc
	} else {
		key, err := parsePEMKey(signingSource)
		if err != nil {
			logf(nil, logLevelFatal, "could not read PEM key from %#v, use {hs=1} for HMAC or {jwks=1} for JWKS: %s", jwtKey, err)
		}
		jka.keyFunc = func(t *jwt.Token) (interface{}, error) {
			return key, nil
		}
	}
	return
}
