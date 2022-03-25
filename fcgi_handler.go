package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	fcgiclient "github.com/alash3al/go-fastcgi-client"
)

type FastCGIHandler struct {
	dialAddress   string
	dialNetwork   string
	fastCGIParams map[string]string
	cfg           *serverConfig
}

func NewFastCGIHandler(params string, cfg *serverConfig) *FastCGIHandler {
	ret := &FastCGIHandler{cfg: cfg}
	fcgiParams, params := parseCurlyParams(params)
	if strings.HasPrefix(params, "/") {
		ret.dialNetwork = "unix"
	} else {
		ret.dialNetwork = "tcp"
	}
	ret.dialAddress = params
	ret.fastCGIParams = fcgiParams
	return ret
}

func (fh *FastCGIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fcgiClient, err := fcgiclient.Dial(fh.dialNetwork, fh.dialAddress)
	if err != nil {
		fh.cfg.logger.Log(logLevelWarning, "Cannot connect to FCGI server", map[string]interface{}{"address": fh.dialAddress, "error": err})
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Error connecting to backend"))
		return
	}
	params := make(map[string]string)
	params["QUERY_STRING"] = r.URL.RawQuery
	params["REQUEST_METHOD"] = r.Method
	if cType := r.Header.Get("Content-Type"); cType != "" {
		params["CONTENT_TYPE"] = cType
	}
	if r.ContentLength >= 0 {
		params["CONTENT_LENGTH"] = fmt.Sprintf("%d", r.ContentLength)
	}
	for k := range r.Header {
		params["HTTP_"+strings.ReplaceAll(strings.ToUpper(k), "-", "_")] = r.Header.Get(k)
	}
	if r.TLS != nil {
		params["HTTPS"] = "on"
	}
	for k, v := range fh.fastCGIParams {
		params[k] = v
	}
	resp, err := fcgiClient.Request(params, r.Body)
	if err != nil {
		fh.cfg.logger.Log(logLevelError, "fcgi request error", map[string]interface{}{"error": err})
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("something went wrong"))
		return
	}

	resp.Write(w)
	for n, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(n, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if resp.Body != nil {
		io.Copy(w, resp.Body)
	}
}

func init() {
	protocolHandlers["fcgi"] = func(p string, cfg *serverConfig) http.Handler {
		return NewFastCGIHandler(p, cfg)
	}
}
