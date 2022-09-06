package main

import (
	"io"
	"net/http"
	"net/http/cgi"
	"os"
	"strings"
)

type UnChunkHandler struct {
	next http.Handler
}

func (h *UnChunkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked" {
		tempFile, err := os.CreateTemp("", "cgi-input-")
		if err != nil {
			logf(r, logLevelError, "cannot create temp file for cgi input: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("input data error"))
			return
		}
		defer os.Remove(tempFile.Name())
		n, err := io.Copy(tempFile, r.Body)
		if err != nil {
			logf(r, logLevelError, "cannot copy cgi input to temp file: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("input data error"))
			return
		}
		if _, err := tempFile.Seek(0, 0); err != nil {
			logf(r, logLevelError, "cannot seek to start of temp file: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("input data error"))
			return
		}
		r.Body = tempFile
		r.ContentLength = n
		r.TransferEncoding = r.TransferEncoding[1:]
	}
	h.next.ServeHTTP(w, r)
}

func NewCGIHandler(urlPath, handlerParams string, cfg *serverConfig) (http.Handler, error) {
	var env, inhEnv, args []string
	if strings.HasPrefix(handlerParams, "{") {
		ebIndex := strings.Index(handlerParams, "}")
		if ebIndex < 0 {
			logf(nil, logLevelFatal, "No end brace")
		}
		for _, v := range strings.Split(handlerParams[1:ebIndex], ",") {
			if strings.HasPrefix(v, "arg:") {
				args = append(args, v[4:])
			} else if eqIndex := strings.Index(v, "="); eqIndex < 0 {
				inhEnv = append(inhEnv, v)
			} else {
				env = append(env, v)
			}
		}
		handlerParams = handlerParams[ebIndex+1:]
	}
	urlPathNoHost := urlPath[strings.Index(urlPath, "/"):]
	return &UnChunkHandler{next: &cgi.Handler{
		Path:       handlerParams,
		Root:       strings.TrimRight(urlPathNoHost, "/"),
		Env:        env,
		InheritEnv: inhEnv,
		Args:       args,
	}}, nil
}

func init() {
	addProtocolHandler("cgi", NewCGIHandler)
}
