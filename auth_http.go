package main

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	addAuthMethod("HTTP", func(check string, roles []string) (Authenticator, error) {
		return NewHTTPAuthenticator(check, roles)
	})
}

type HTTPAuthenticator struct {
	url         string
	method      string
	successCode int
	roles       []string
	copyHeaders []string
	setHeaders  map[string]string
	needHeaders []string
	client      *http.Client
}

func (ha *HTTPAuthenticator) GetRoles(req *http.Request, rolesToCheck map[string]interface{}) ([]string, error) {
	for _, header := range ha.needHeaders {
		if _, have := req.Header[header]; !have {
			return nil, nil
		}
	}

	url := ha.url
	if strings.HasPrefix(url, "tmpl:") {
		var err error
		url, _, err = GetRequestParam(url, req)
		if err != nil {
			return nil, err
		}
	}

	authReq, err := http.NewRequest(ha.method, url, nil)
	if err != nil {
		return nil, err
	}

	for _, header := range ha.copyHeaders {
		if header == "Host" {
			authReq.Host = req.Host
		} else {
			authReq.Header[header] = req.Header.Values(header)
		}
	}

	for header := range ha.setHeaders {
		value := ha.setHeaders[header]
		if strings.HasPrefix(value, "tmpl:") {
			var err error
			value, _, err = GetRequestParam(value, req)
			if err != nil {
				logf(req, logLevelError, "could not parse header %s: %s", value, err)
			}
		}
		authReq.Header.Set(header, value)
	}

	resp, err := ha.client.Do(authReq)
	if err != nil {
		logf(req, logLevelError, "could not make auth request %s %s: %s", ha.method, url, err)
		return nil, errors.New("cannot check auth")
	}
	if resp.StatusCode != ha.successCode {
		respBody, _ := io.ReadAll(resp.Body)
		logf(req, logLevelWarning, "auth %s to %s failed with %s: %#q", ha.method, url, resp.Status, string(respBody))
		return nil, nil
	}
	return ha.roles, nil
}

func NewHTTPAuthenticator(check string, roles []string) (Authenticator, error) {
	options, url := parseCurlyParams(check)
	ret := &HTTPAuthenticator{
		url:        url,
		roles:      roles,
		setHeaders: make(map[string]string),
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	if ret.method = options["method"]; ret.method == "" {
		ret.method = "GET"
	}

	if needHeaders := options["need-hdr"]; needHeaders != "" {
		ret.needHeaders = append(ret.needHeaders, strings.Split(needHeaders, ":")...)
	}
	if copyHeaders := options["cp-hdr"]; copyHeaders != "" {
		ret.copyHeaders = append(ret.copyHeaders, strings.Split(copyHeaders, ":")...)
	}
	for opt := range options {
		if !strings.HasPrefix(opt, "set-hdr:") {
			continue
		}
		ret.setHeaders[opt[8:]] = options[opt]
	}
	if successCode := options["success"]; successCode != "" {
		if code, err := strconv.Atoi(successCode); err != nil {
			logf(nil, logLevelFatal, "Cannot parse success code %#v: %s", successCode, err)
		} else {
			ret.successCode = code
		}
	} else {
		ret.successCode = http.StatusOK
	}
	return ret, nil
}
