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
	fastCGIParams map[string]interface{}
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

	ret.fastCGIParams = map[string]interface{}{}
	for name, val := range fcgiParams {
		if strings.HasPrefix(val, "~") {
			ret.fastCGIParams[name] = NewReSubst(val[1:])
		} else {
			ret.fastCGIParams[name] = val
		}
	}
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
		if rs, ok := v.(*ReSubst); ok {
			params[k] = rs.SubstReq(r)
		} else if s, ok := v.(string); ok {
			params[k] = s
		} else {
			fh.cfg.logger.Log(logLevelError, "Unknown fcgi param type",
				map[string]interface{}{"type": fmt.Sprintf("%t", v)})
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("bad config"))
			return
		}
	}
	resp, err := fcgiClient.Request(params, r.Body)
	if err != nil {
		fh.cfg.logger.Log(logLevelError, "fcgi request error", map[string]interface{}{"error": err})
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("something went wrong"))
		return
	}

	for n, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(n, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if resp.Body != nil {
		if wr, err := io.Copy(w, resp.Body); err != nil {
			fh.cfg.logger.Log(logLevelWarning, "could not copy fcgi body", map[string]interface{}{
				"error":  err,
				"copied": wr,
			})
		}
		resp.Body.Close()
	}
}

func init() {
	addProtocolHandler("fcgi", func(_, p string, cfg *serverConfig) (http.Handler, error) {
		return NewFastCGIHandler(p, cfg), nil
	})
}
