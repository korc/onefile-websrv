package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

type UnixRoundTripper struct {
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
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	return (&http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", unixPath)
		},
	}).RoundTrip(request)
}
