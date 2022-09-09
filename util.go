package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/golang-jwt/jwt/v4"
)

var ErrCantSolve = errors.New("cannot to solve request param")
var ErrValueNotSet = errors.New("parameter value not set")

var tmplCache = map[string]*template.Template{}

func GetRequestParam(param string, req *http.Request) (value string, solved bool, err error) {
	if strings.HasPrefix(param, "str:") {
		return param[4:], true, nil
	} else if strings.HasPrefix(param, "auth:") {
		authHeaders := req.Header.Values("Authorization")
		if len(authHeaders) == 0 {
			return "", false, ErrValueNotSet
		}
		switch param[5:] {
		case "bearer":
			for _, v := range authHeaders {
				if strings.HasPrefix(v, "Bearer ") {
					return v[7:], true, nil
				}
			}
		case "basic-pwd", "basic-usr":
			usr, pwd, ok := req.BasicAuth()
			if !ok {
				return "", false, ErrValueNotSet
			}
			switch param[5+6:] {
			case "pwd":
				return pwd, true, nil
			case "usr":
				return usr, true, nil
			}
		}
		return "", false, ErrValueNotSet
	} else if strings.HasPrefix(param, "crt:") {
		if req.TLS == nil {
			logf(req, logLevelError, "cannot get X.509 data from non-TLS request")
			return "", false, ErrCantSolve
		}
		if req.TLS.PeerCertificates == nil || len(req.TLS.PeerCertificates) == 0 {
			logf(req, logLevelError, "want set claim from X509 %s, but there are no client certificate", param[4:])
			return "", false, ErrCantSolve
		}
		crt := req.TLS.PeerCertificates[0]
		switch param[4:] {
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
			logf(req, logLevelWarning, "crt param %#v not in: cn, subj, fp, crt", param[4:])
		}
	} else if strings.HasPrefix(param, "q:") {
		if !req.URL.Query().Has(param[2:]) {
			return "", false, ErrValueNotSet
		}
		return req.URL.Query().Get(param[2:]), true, nil
	} else if strings.HasPrefix(param, "post:") {
		req.ParseForm()
		if !req.PostForm.Has(param[5:]) {
			return "", false, ErrValueNotSet
		}
		return req.PostFormValue(param[5:]), true, nil
	} else if strings.HasPrefix(param, "hdr:") {
		if len(req.Header.Values(param[4:])) == 0 {
			return "", false, ErrValueNotSet
		}
		return req.Header.Get(param[4:]), true, nil
	} else if strings.HasPrefix(param, "env:") {
		v, have := os.LookupEnv(param[4:])
		if !have {
			return "", false, ErrValueNotSet
		}
		return v, true, nil
	} else if strings.HasPrefix(param, "cookie:") {
		cookie, err := req.Cookie(param[7:])
		if err != nil {
			return "", false, ErrValueNotSet
		}
		return cookie.Value, true, nil
	} else if strings.HasPrefix(param, "req:") {
		switch param[4:] {
		case "query":
			return req.URL.RawQuery, true, nil
		case "path":
			return req.URL.Path, true, nil
		case "raddr":
			return req.RemoteAddr, true, nil
		case "rip":
			val, _, _ := net.SplitHostPort(req.RemoteAddr)
			return val, true, nil
		case "host":
			return req.Host, true, nil
		default:
			logf(req, logLevelWarning, "unknown req: param %#v", param[4:])
			return "", false, ErrValueNotSet
		}
	} else if strings.HasPrefix(param, "jwt:") {
		claimEndIdx := strings.Index(param[4:], ":") + 4
		tokenString, solved, err := GetRequestParam(param[claimEndIdx+1:], req)
		if !solved {
			return "", solved, err
		}
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(tokenString, claims); err != nil {
			logf(req, logLevelWarning, "cannot parse jwt from %#v: %s", param[claimEndIdx+1:], err)
			return "", false, err
		}
		claimName, err := url.QueryUnescape(param[4:claimEndIdx])
		if err != nil {
			logf(req, logLevelError, "cannot unescape claim name %#v: %s", param[4:claimEndIdx], err)
			return "", false, err
		}
		claim, have := claims[claimName]
		if !have {
			return "", false, ErrValueNotSet
		}
		return fmt.Sprintf("%s", claim), true, nil
	} else if strings.HasPrefix(param, "unescape:") {
		unescapeStr := param[9:]
		if strings.Contains(unescapeStr, ":") {
			unescapeStr, solved, err = GetRequestParam(unescapeStr, req)
			if !solved {
				return "", solved, err
			}
		}
		unesc, err := url.QueryUnescape(unescapeStr)
		if err != nil {
			return "", false, err
		}
		return unesc, true, nil
	} else if strings.HasPrefix(param, "tmpl:") {
		tmplSrc, solved, err := GetRequestParam(param[5:], req)
		if !solved {
			return "", solved, err
		}
		h := sha256.New()
		name := base64.StdEncoding.EncodeToString(h.Sum([]byte(tmplSrc)))
		tmpl, have := tmplCache[name]
		if !have {
			tmpl, err = template.New(name).Funcs(template.FuncMap{
				"rp": func(n string, req *http.Request) (ret string, err error) {
					ret, _, err = GetRequestParam(n, req)
					return
				},
			}).Parse(string(tmplSrc))
			if err != nil {
				logf(req, logLevelError, "Error parsing template %#v: %s", tmplSrc, err)
				return "", false, err
			}
			tmplCache[name] = tmpl
		}
		buf := bytes.NewBuffer([]byte{})
		if err := tmpl.Execute(buf, map[string]interface{}{"req": req}); err != nil {
			return "", false, err
		}
		return buf.String(), true, nil
	}
	return "", false, nil
}
