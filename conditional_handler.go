package main

import (
	"net/http"
	"regexp"
)

type regexpAndHandler struct {
	re      *regexp.Regexp
	handler http.Handler
}

type ConditionalHandler struct {
	defaultNext http.Handler
	onStatus    map[int]http.Handler
	onPathRegex []regexpAndHandler
}

type statusCheckingWriter struct {
	orig       http.ResponseWriter
	onStatus   map[int]http.Handler
	request    *http.Request
	newHandler http.Handler
	headers    http.Header
	statusCode int
}

// Header implements http.ResponseWriter.
func (s *statusCheckingWriter) Header() http.Header {
	return s.orig.Header()
}

// Write implements http.ResponseWriter.
func (s *statusCheckingWriter) Write(data []byte) (int, error) {
	if s.newHandler != nil {
		logf(s.request, logLevelInfo, "status %v handled by other, throwing away response from previous handler: %#v", s.statusCode, string(data))
		return len(data), nil
	}
	return s.orig.Write(data)
}

func (s *statusCheckingWriter) restoreHeaders() {
	headers := s.orig.Header()
	for k := range headers {
		headers.Del(k)
	}
	for k := range s.headers {
		for _, v := range s.headers.Values(k) {
			headers.Add(k, v)
		}
	}
}

// WriteHeader implements http.ResponseWriter.
func (s *statusCheckingWriter) WriteHeader(statusCode int) {
	s.statusCode = statusCode
	if handler, haveMatch := s.onStatus[statusCode]; haveMatch {
		s.newHandler = handler
		s.restoreHeaders()
		s.newHandler.ServeHTTP(s.orig, s.request)
	} else {
		s.orig.WriteHeader(statusCode)
	}
}

// ServeHTTP implements http.Handler.
func (c *ConditionalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, rh := range c.onPathRegex {
		if rh.re.MatchString(r.URL.Path) {
			rh.handler.ServeHTTP(w, r)
			return
		}
	}
	if c.onStatus != nil {
		w = &statusCheckingWriter{orig: w, onStatus: c.onStatus, request: r, headers: w.Header().Clone()}
	}
	c.defaultNext.ServeHTTP(w, r)
}

func NewConditionalHandler(defaultNext http.Handler) http.Handler {
	return &ConditionalHandler{defaultNext: defaultNext}
}

func (c *ConditionalHandler) OnStatus(statusCode int, handler http.Handler) *ConditionalHandler {
	if c.onStatus == nil {
		c.onStatus = map[int]http.Handler{statusCode: handler}
	} else {
		c.onStatus[statusCode] = handler
	}
	return c
}

func (c *ConditionalHandler) OnPathRegex(re *regexp.Regexp, handler http.Handler) *ConditionalHandler {
	if handler == nil {
		logf(nil, logLevelFatal, "empty handler for %#v", re.String())
	}
	c.onPathRegex = append(c.onPathRegex, regexpAndHandler{re: re, handler: handler})
	return c
}
