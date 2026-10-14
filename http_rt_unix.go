package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type UnixRoundTripper struct {
}

var unixTransportCache sync.Map

func unixTransport(unixPath string) *http.Transport {
	if v, ok := unixTransportCache.Load(unixPath); ok {
		return v.(*http.Transport)
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 30 * time.Second}
			return dialer.DialContext(ctx, "unix", unixPath)
		},
		IdleConnTimeout: 10 * time.Minute,
	}
	actual, loaded := unixTransportCache.LoadOrStore(unixPath, tr)
	if loaded {
		tr.CloseIdleConnections()
	}
	return actual.(*http.Transport)
}

func (u UnixRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request.URL.Scheme = "http"

	sepIdx := strings.Index(request.URL.Path, ":")
	if sepIdx < 0 {
		logf(request, logLevelError, "Unix endpoint %#v does not contain ':'", request.URL.Path)
		return nil, errors.New("server configuration error")
	}
	unixPath := request.URL.Path[:sepIdx]
	request.URL.Path = request.URL.Path[sepIdx+1:]

	if request.URL.Host == "" {
		request.URL.Host = "localhost"
	}
	return unixTransport(unixPath).RoundTrip(request)
}

func init() {
	customHttpSchemas["unix"] = func() http.RoundTripper { return &UnixRoundTripper{} }
}
