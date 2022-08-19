package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

func NewHttpHandler(urlPath, params string, cfg *serverConfig) http.Handler {
	connectParams, handlerParams := parseCurlyParams(params)
	urlPathNoHost := urlPath[strings.Index(urlPath, "/"):]
	httpURL, err := url.Parse(handlerParams)
	if err != nil {
		logf(nil, logLevelFatal, "Cannot parse %#v as URL: %v", handlerParams, err)
	}
	prxHandler := httputil.NewSingleHostReverseProxy(httpURL)
	var pathRe *regexp.Regexp
	if rePat, ok := connectParams["re"]; ok {
		pathRe = regexp.MustCompile(rePat)
	}

	defaultDirector := prxHandler.Director
	prxHandler.Director = func(request *http.Request) {
		reqPath := request.URL.Path
		defaultDirector(request)
		if pathRe != nil {
			request.URL.Path = string(pathRe.ExpandString([]byte{}, httpURL.Path, reqPath,
				pathRe.FindStringSubmatchIndex(reqPath)))
		}
		for _, hdr := range []string{"fp-hdr", "cn-hdr", "cert-hdr", "subj-hdr"} {
			if hdrName, ok := connectParams[hdr]; ok {
				// Scrub possible auth-related headers from request
				request.Header.Del(hdrName)
			}
		}
		if delHdrs, have := connectParams["del-hdr"]; have {
			for _, hdr := range strings.Split(delHdrs, ":") {
				request.Header.Del(hdr)
			}
		}
		for k := range connectParams {
			if !strings.HasPrefix(k, "set-hdr:") {
				continue
			}
			request.Header.Set(k[8:], connectParams[k])
		}
		if noXFF := connectParams["no-xff"]; noXFF != "" {
			request.Header["X-Forwarded-For"] = nil
		}
		if cfg.certFile != "" {
			request.Header.Set("X-Forwarded-Proto", "https")
			if request.TLS != nil {
				if fpHeader, ok := connectParams["fp-hdr"]; ok {
					for _, crt := range request.TLS.PeerCertificates {
						h := sha256.New()
						h.Write(crt.Raw)
						request.Header.Add(fpHeader, hex.EncodeToString(h.Sum(nil)))
					}
				}
				if subjHeader, ok := connectParams["subj-hdr"]; ok {
					for _, crt := range request.TLS.PeerCertificates {
						request.Header.Add(subjHeader, crt.Subject.String())
					}
				}
				if cnHeader, ok := connectParams["cn-hdr"]; ok {
					for _, crt := range request.TLS.PeerCertificates {
						request.Header.Add(cnHeader, crt.Subject.CommonName)
					}
				}
				if crtHdr, ok := connectParams["cert-hdr"]; ok {
					for _, crt := range request.TLS.PeerCertificates {
						request.Header.Add(crtHdr, hex.EncodeToString(crt.Raw))
					}
				}
			}
		} else {
			request.Header.Set("X-Forwarded-Proto", "http")
		}
	}

	if certFile, ok := connectParams["cert"]; ok {
		keyFile := connectParams["key"]
		if keyFile == "" {
			keyFile = certFile
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			cfg.logger.Log(logLevelFatal, "Cannot load cert/key", map[string]interface{}{
				"cert":  certFile,
				"key":   keyFile,
				"error": err,
			})
		}
		prxHandler.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
	}
	if prxHandler.Transport == nil {
		prxHandler.Transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	for name, rt := range customHttpSchemas {
		prxHandler.Transport.(*http.Transport).RegisterProtocol(name, rt())
	}
	return http.StripPrefix(urlPathNoHost, prxHandler)
}

func init() {
	addProtocolHandler("http", func(urlPath, p string, cfg *serverConfig) (http.Handler, error) {
		cfg.logger.Log(logLevelInfo, "new HTTP handler", map[string]interface{}{"path": urlPath, "params": p})
		return NewHttpHandler(urlPath, p, cfg), nil
	})
}
