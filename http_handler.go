package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type fixWSHeadersTransport struct {
	http.RoundTripper
}

func (dtr *fixWSHeadersTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	for header := range request.Header {
		if strings.HasPrefix(header, "Sec-Websocket-") {
			request.Header[strings.Replace(header, "Websocket", "WebSocket", 1)] = request.Header[header]
			delete(request.Header, header)
		}
	}
	return dtr.RoundTripper.RoundTrip(request)
}

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

	pathReWithHost, _ := strconv.ParseBool(connectParams["re-host"])
	debugPathRe, _ := strconv.ParseBool(connectParams["debug-re"])

	defaultDirector := prxHandler.Director
	prxHandler.Director = func(request *http.Request) {
		origPath := request.URL.Path
		origRequest := request.Clone(request.Context())
		defaultDirector(request)
		if pathRe != nil {
			if origPath == "" {
				origPath = "/"
			} else if origPath[0] != '/' {
				origPath = "/" + origPath
			}
			orig := origPath
			if pathReWithHost {
				orig = origRequest.Host + orig
			}
			matches := pathRe.FindAllStringSubmatchIndex(orig, -1)
			if matches == nil {
				logf(request, logLevelError, "re %#v does not match host=%#v url=%#v -> %#v",
					pathRe.String(), origRequest.Host, origRequest.URL, orig)
			}
			dst := []byte{}
			for _, submatch := range matches {
				dst = pathRe.ExpandString(dst, handlerParams, orig, submatch)
			}
			if pathReWithHost {
				if dstUrl, err := url.Parse(string(dst)); err != nil {
					logf(request, logLevelError, "cannot parse result as URL %#v: %s", string(dst), err)
				} else {
					request.URL.Host = dstUrl.Host
					request.URL.Path = dstUrl.Path
				}
			} else {
				request.URL.Path = string(dst)
			}
			if debugPathRe {
				log.Printf("request.URL[re-host=%v]: dst%#v orig=%#v req=%#v params=%#v",
					pathReWithHost, request.URL.String(), orig, origRequest, handlerParams)
			}
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
		noXFF := false
		if noXFFStr, have := connectParams["no-xff"]; have {
			noXFF, err = strconv.ParseBool(noXFFStr)
			if err != nil {
				cfg.logger.Log(logLevelFatal, "cannot parse no-xff= value", map[string]interface{}{"no-xff": noXFFStr, "error": err})
			}
			if noXFF {
				request.Header["X-Forwarded-For"] = nil
			}
		}
		if cfg.certFile != "" {
			if !noXFF {
				request.Header.Set("X-Forwarded-Proto", "https")
			}
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
			if !noXFF {
				request.Header.Set("X-Forwarded-Proto", "http")
			}
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

	prxTransport := prxHandler.Transport.(*http.Transport)
	if noGzipFlag, ok := connectParams["no-gzip"]; ok {
		if v, err := strconv.ParseBool(noGzipFlag); err == nil && v {
			prxTransport.DisableCompression = true
		} else if err != nil {
			cfg.logger.Log(logLevelFatal, "cannot parse no-gzip= value", map[string]interface{}{"no-gzip": noGzipFlag, "error": err})
		}
	}

	if verifyFlag, ok := connectParams["verify"]; ok {
		if v, err := strconv.ParseBool(verifyFlag); err == nil && !v {
			if prxTransport.TLSClientConfig == nil {
				prxTransport.TLSClientConfig = &tls.Config{}
			}
			prxTransport.TLSClientConfig.InsecureSkipVerify = true
		} else if err != nil {
			cfg.logger.Log(logLevelFatal, "cannot parse verify= value", map[string]interface{}{"verify": verifyFlag, "error": err})
		}
	}
	if caCertFlag, ok := connectParams["ca"]; ok {
		pemData, err := os.ReadFile(caCertFlag)
		if err != nil {
			cfg.logger.Log(logLevelFatal, "cannot read ca file", map[string]interface{}{"filename": caCertFlag, "error": err})
		}
		if prxTransport.TLSClientConfig == nil {
			prxTransport.TLSClientConfig = &tls.Config{}
		}
		prxTransport.TLSClientConfig.RootCAs = x509.NewCertPool()
		if !prxTransport.TLSClientConfig.RootCAs.AppendCertsFromPEM(pemData) {
			cfg.logger.Log(logLevelFatal, "failed adding any root CAs", map[string]interface{}{"filename": caCertFlag})
		}
	}

	for name, rt := range customHttpSchemas {
		prxHandler.Transport.(*http.Transport).RegisterProtocol(name, rt())
	}
	if connectParams["fix-ws-hdr"] != "" {
		prxHandler.Transport = &fixWSHeadersTransport{prxHandler.Transport}
	}
	return http.StripPrefix(urlPathNoHost, prxHandler)
}

func init() {
	addProtocolHandler("http", func(urlPath, p string, cfg *serverConfig) (http.Handler, error) {
		cfg.logger.Log(logLevelInfo, "new HTTP handler", map[string]interface{}{"path": urlPath, "params": p})
		return NewHttpHandler(urlPath, p, cfg), nil
	})
}
