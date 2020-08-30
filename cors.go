package main

import (
	"net/http"
	"regexp"
	"strings"
)

type corsACL struct {
	path   *regexp.Regexp
	domain *regexp.Regexp
}

// CORSHandler adds "Access-Control-Allow-Origin" header to response if specified Origin is in request
type CORSHandler struct {
	http.Handler
	allowed []corsACL
}

// AddRecord make path accessible from origin
func (ch *CORSHandler) AddRecord(path, origin string) error {
	if ch.allowed == nil {
		ch.allowed = make([]corsACL, 0)
	}
	pathRe, err := regexp.Compile(path)
	if err != nil {
		return err
	}
	originRe, err := regexp.Compile(origin)
	if err != nil {
		return err
	}
	logf(nil, logLevelInfo, "CORS: Adding origin %#v on %#v", origin, path)
	ch.allowed = append(ch.allowed, corsACL{pathRe, originRe})
	return nil
}

func (ch *CORSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	next := ch.Handler
	if next == nil {
		next = http.DefaultServeMux
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		matched := false
		for _, acl := range ch.allowed {
			if acl.path.MatchString(r.URL.Path) && acl.domain.MatchString(origin) {
				matched = true
				w.Header().Add("Access-Control-Allow-Origin", origin)
				varyHeaders := []string{"Origin"}
				if method := r.Header.Get("Access-Control-Request-Method"); method != "" {
					w.Header().Add("Access-Control-Allow-Methods", "*")
				}
				if header := r.Header.Get("Access-Control-Request-Headers"); header != "" {
					w.Header().Add("Access-Control-Allow-Headers", header)
					varyHeaders = append(varyHeaders, header)
				}
				if r.Method == "OPTIONS" {
					w.Header().Add("Vary", strings.Join(varyHeaders, ", "))
					w.WriteHeader(http.StatusOK)
					return
				}
			}
		}
		if !matched {
			logf(r, logLevelWarning, "CORS: Could not match origin %#v on %#v, passing to backend", origin, r.URL.Path)
		}
	}
	next.ServeHTTP(w, r)
}
