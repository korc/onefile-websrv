package main

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
)

type modHeaderOption struct {
	re          *regexp.Regexp
	includeHost bool
	name        string
	value       string
}

type ModifyHeaderHandler struct {
	NextHandler http.Handler
	options     []modHeaderOption
}

func (h *ModifyHeaderHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	next := h.NextHandler
	if next == nil {
		next = http.DefaultServeMux
	}
	for _, opt := range h.options {
		testString := req.URL.Path
		if opt.includeHost {
			testString = req.Host + testString
		}
		if opt.re.MatchString(testString) {
			value, solved, err := GetRequestParam(opt.value, req)
			if err != nil {
				logf(req, logLevelError, "cannot solve parameter: %#v: %s", opt.value, err)
			}
			if solved {
				w.Header().Add(opt.name, value)
			}
		}
	}
	next.ServeHTTP(w, req)
}

func (h *ModifyHeaderHandler) ParseAddHdr(opt string) error {
	includeHost := false
	if strings.HasPrefix(opt, "*") {
		includeHost = true
		opt = opt[1:]
	}

	eqIdx := strings.Index(opt, "=")
	if eqIdx < 0 {
		return errors.New("no '=' in option")
	}

	re, err := regexp.Compile(opt[:eqIdx])
	if err != nil {
		return err
	}
	opt = opt[eqIdx+1:]

	var headerValue string

	nameIdx := strings.Index(opt, ":")
	if nameIdx < 0 {
		return errors.New("no ':' in option value")
	}
	headerValue = opt[nameIdx+1:]

	h.options = append(h.options, modHeaderOption{
		re:          re,
		includeHost: includeHost,
		name:        opt[:nameIdx],
		value:       headerValue,
	})
	return nil
}
