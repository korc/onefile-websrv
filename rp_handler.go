package main

import "net/http"

type rpHandler struct {
	opts     map[string]string
	reqParam string
}

func (t *rpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	output, solved, err := GetRequestParam(t.reqParam, r)
	if err != nil {
		logf(r, logLevelError, "rp handler can't solve %#v: %s", t.reqParam, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("error creating response"))
		return
	} else if !solved {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("no response"))
		return
	}
	for name := range t.opts {
		value, solved, err := GetRequestParam(t.opts[name], r)
		if err != nil {
			logf(r, logLevelWarning, "cannot get header param %#v -> %#v: %s", name, t.opts[name], err)
			continue
		}
		if solved {
			w.Header().Add(name, value)
		}
	}
	w.Write([]byte(output))
}

func newRPHandler(params string) http.Handler {
	opts, reqParam := parseCurlyParams(params)
	return &rpHandler{
		opts:     opts,
		reqParam: reqParam,
	}
}

func init() {
	addProtocolHandler("rp", func(_, s string, sc *serverConfig) (http.Handler, error) {
		sc.logger.Log(logLevelInfo, "new request parameter handler", map[string]any{"parameters": s})
		return newRPHandler(s), nil
	})
}
