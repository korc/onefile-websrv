package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
)

var ErrCantSolve = errors.New("cannot to solve request param")
var ErrValueNotSet = errors.New("parameter value not set")

func GetRequestParam(param string, req *http.Request) (value string, solved bool, err error) {
	if strings.HasPrefix(param, "str:") {
		return param[4:], true, nil
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
	}
	return "", false, nil
}
