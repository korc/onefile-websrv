package main

import (
	"net/http"
	"regexp"
	"strings"
)

type corsAllowOrigin int

const (
	corsAllowOriginAll corsAllowOrigin = iota
	corsAllowOriginSource
	corsAllowOriginNull
)

type corsACL struct {
	hostRe           *regexp.Regexp
	pathRe           *regexp.Regexp
	originRe         *regexp.Regexp
	allowOrigin      corsAllowOrigin
	allowMethods     string
	allowHeaders     []string
	allowCredentials string
}

// CORSHandler adds "Access-Control-Allow-Origin" header to response if specified Origin is in request
type CORSHandler struct {
	http.Handler
	acls []corsACL
}

// AddRecord make path accessible from origin
func (ch *CORSHandler) AddRecord(path, origin string, opts map[string]string) error {
	if ch.acls == nil {
		ch.acls = make([]corsACL, 0)
	}
	acl := corsACL{
		allowOrigin:  corsAllowOriginSource,
		allowMethods: "*",
		pathRe:       regexp.MustCompile(path),
		originRe:     regexp.MustCompile(origin),
	}

	if hostReStr, have := opts["host_re"]; have {
		acl.hostRe = regexp.MustCompile(hostReStr)
	}

	if methodsStr, have := opts["methods"]; have {
		acl.allowMethods = strings.Join(strings.Split(methodsStr, ":"), ", ")
	}

	if hdrString, have := opts["headers"]; have {
		acl.allowHeaders = strings.Split(hdrString, ":")
	}

	if creds, have := opts["creds"]; have {
		acl.allowCredentials = creds
	}

	logf(nil, logLevelInfo,
		"CORS: Adding origin host=%s %#v on %#v (methods %#v)",
		acl.hostRe, origin, path, acl.allowMethods)
	ch.acls = append(ch.acls, acl)
	return nil
}

func (ch *CORSHandler) handlePreflight(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	acrMethod := r.Header.Get("Access-Control-Request-Method")
	acrHeaders := r.Header.Get("Access-Control-Request-Headers")

	for _, acl := range ch.acls {
		if (acl.hostRe != nil && !acl.hostRe.MatchString(r.Host)) ||
			!acl.pathRe.MatchString(r.URL.Path) ||
			!acl.originRe.MatchString(origin) {
			continue
		}

		varyHeaders := []string{}

		// allowed origin
		switch acl.allowOrigin {
		case corsAllowOriginAll:
			w.Header().Add("Access-Control-Allow-Origin", "*")
		case corsAllowOriginSource:
			w.Header().Add("Access-Control-Allow-Origin", origin)
			varyHeaders = append(varyHeaders, "Origin")
		case corsAllowOriginNull:
			w.Header().Add("Access-Control-Allow-Origin", "null")
		}

		// allowed methods
		if acl.allowMethods == "" {
			w.Header().Add("Access-Control-Allow-Methods", acrMethod)
		} else {
			w.Header().Add("Access-Control-Allow-Methods", acl.allowMethods)
		}

		// allowed headers
		if acrHeaders != "" {
			acaHeaders := []string{}
			if acl.allowHeaders != nil {
				acaHeaders = acl.allowHeaders
			} else {
				for _, header := range strings.Split(acrHeaders, ",") {
					acaHeaders = append(acaHeaders, http.CanonicalHeaderKey(strings.Trim(header, " ")))
				}
			}

			w.Header().Add("Access-Control-Allow-Headers", strings.Join(acaHeaders, ", "))
			if len(acaHeaders) >= 1 && acaHeaders[0] != "*" {
				varyHeaders = append(varyHeaders, acaHeaders...)
			}
		}

		// allowed credentials
		if acl.allowCredentials != "" {
			w.Header().Add("Access-Control-Allow-Credentials", acl.allowCredentials)
		}

		// vary headers
		if len(varyHeaders) > 0 {
			w.Header().Add("Vary", strings.Join(varyHeaders, ", "))
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	logf(r, logLevelWarning,
		"CORS: Could not match origin %#v on %#v, passing to backend",
		origin, r.URL.Path)

	next := ch.Handler
	if next == nil {
		next = http.DefaultServeMux
	}
	next.ServeHTTP(w, r)
}

type headerModifyingResponseWriter struct {
	next http.ResponseWriter
	add  http.Header
}

// Header implements http.ResponseWriter.
func (h *headerModifyingResponseWriter) Header() http.Header {
	return h.next.Header()
}

// Write implements http.ResponseWriter.
func (h *headerModifyingResponseWriter) Write([]byte) (int, error) {
	panic("unimplemented")
}

// WriteHeader implements http.ResponseWriter.
func (h *headerModifyingResponseWriter) WriteHeader(statusCode int) {
	panic("unimplemented")
}

func (ch *CORSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next := ch.Handler
	if next == nil {
		next = http.DefaultServeMux
	}

	if r.Method == "OPTIONS" &&
		r.Header.Get("Access-Control-Request-Method") != "" &&
		r.Header.Get("Origin") != "" {
		ch.handlePreflight(w, r)
		return
	}
	for _, acl := range ch.acls {
		origin := r.Header.Get("Origin")
		if origin == "" {
			continue
		}
		if acl.originRe.MatchString(origin) &&
			(acl.hostRe == nil || acl.hostRe.MatchString(r.Host)) &&
			acl.pathRe.MatchString(r.URL.Path) {
			w.Header().Add("Access-Control-Allow-Origin", origin)
			break
		}
	}
	next.ServeHTTP(w, r)
}
