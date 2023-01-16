package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

var oidMap = map[string]string{
	"2.5.4.3":              "CN",
	"2.5.4.5":              "SN",
	"2.5.4.6":              "C",
	"2.5.4.7":              "L",
	"2.5.4.8":              "S",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"1.2.840.113549.1.9.1": "eMail",
}

var (
	errNotMap   = errors.New("value not a Map")
	errNotSlice = errors.New("value not a Slice")
)

func parseJSONPath(s string) (path []interface{}) {
	for _, p := range strings.Split(s, ".") {
		if strings.HasSuffix(p, "]") {
			if idx := strings.LastIndex(p, "["); idx != -1 {
				if arrayIdx, err := strconv.Atoi(p[idx+1 : len(p)-1]); err == nil {
					path = append(path, p[:idx])
					path = append(path, arrayIdx)
					continue
				}
			}
		}
		path = append(path, p)
	}
	return path
}

func extractJSONPath(source interface{}, path []interface{}) (out interface{}, err error) {
	out = source
	for _, p := range path {
		switch pt := p.(type) {
		case string:
			switch reflect.TypeOf(out).Kind() {
			case reflect.Map:
				out = reflect.ValueOf(out).MapIndex(reflect.ValueOf(pt)).Interface()
			default:
				return source, errNotMap
			}
		case int:
			switch reflect.TypeOf(out).Kind() {
			case reflect.Slice:
				out = reflect.ValueOf(out).Index(pt).Interface()
			default:
				return source, errNotSlice
			}
		}
		if out == nil {
			break
		}
	}
	return out, nil
}

func init() {
	addProtocolHandler("debug", newDebugHandler)
}

func newDebugHandler(urlPath, params string, cfg *serverConfig) (http.Handler, error) {
	opts := parseOptString(params)
	if opts.IsTrue("json", false) {
		var path []interface{}
		if pathStr, have := opts["path"]; have {
			path = parseJSONPath(pathStr)
		}
		return &JSONDebugHandler{
			tlsCS:     opts.IsTrue("tls-cs", false),
			headers:   opts.IsTrue("hdr", true),
			authRoles: opts.IsTrue("auth", true),
			path:      path,
		}, nil
	}
	return &DebugHandler{}, nil
}

type JSONDebugHandler struct {
	tlsCS     bool
	headers   bool
	authRoles bool
	path      []interface{}
}

func (jDbg *JSONDebugHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var out interface{}
	out = map[string]interface{}{}
	outMap := out.(map[string]interface{})

	if r.TLS != nil {
		outMap["tls"] = map[string]interface{}{
			"version": r.TLS.Version,
			"cipher":  r.TLS.CipherSuite,
			"resumed": r.TLS.DidResume,
			"sni":     r.TLS.ServerName,
		}
		if len(r.TLS.PeerCertificates) > 0 {
			peers := make([]interface{}, 0)
			for _, cert := range r.TLS.PeerCertificates {
				h := sha256.New()
				h.Write(cert.Raw)
				peerInfo := map[string]interface{}{
					"sub": cert.Subject.ToRDNSequence().String(),
					"iss": cert.Issuer.ToRDNSequence().String(),
					"fp":  hex.EncodeToString(h.Sum(nil)),
					"sig": cert.Signature,
				}
				if cert.Subject.CommonName != "" {
					peerInfo["cn"] = cert.Subject.CommonName
				}
				for _, attr := range cert.Subject.Names {
					if oidName := attr.Type.String(); oidMap[oidName] == "eMail" {
						peerInfo["email"] = attr.Value
					}
				}
				peerInfo["exp"] = cert.NotAfter.Unix()
				peerInfo["iat"] = cert.NotBefore.Unix()
				peers = append(peers, peerInfo)
			}
			outMap["tls"].(map[string]interface{})["peers"] = peers
		}
		if jDbg.tlsCS {
			outMap["tls"].(map[string]interface{})["cs"] = r.TLS
		}
	}
	outMap["remote"] = r.RemoteAddr
	if jDbg.headers {
		outMap["headers"] = r.Header
	}

	if jDbg.authRoles {
		if auth := r.Context().Value(authRoleContext); auth != nil {
			outMap["auth-role"] = auth
		}
	}

	if jDbg.path != nil {
		var err error
		if out, err = extractJSONPath(out, jDbg.path); err != nil {
			logf(r, logLevelWarning, "cannot extract path %#v from %#v: %s", jDbg.path, out, err)
			out = nil
		}
	}
	outBytes, err := json.Marshal(out)
	if err != nil {
		logf(r, logLevelError, "could not marshal debug request (%#v): %s", out, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write(outBytes)
}

type DebugHandler struct {
}

// DebugRequest returns debugging information to client
func (dbg *DebugHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	hdrs := make([]string, 0)
	for k, v := range r.Header {
		for _, vv := range v {
			hdrs = append(hdrs, fmt.Sprintf("%s: %s", k, vv))
		}
	}

	metaInfo := []string{fmt.Sprintf("remote=%v", r.RemoteAddr)}
	if auth := r.Context().Value(authRoleContext); auth != nil {
		metaInfo = append(metaInfo, fmt.Sprintf("auth-role=%#v", auth))
	}
	if r.TLS != nil {
		metaInfo = append(metaInfo, fmt.Sprintf("SSL=0x%04x verified=%d", r.TLS.Version, len(r.TLS.VerifiedChains)))
		for _, crt := range r.TLS.PeerCertificates {
			subjectName := make([]string, 0)
			for _, attr := range crt.Subject.Names {
				attrName := attr.Type.String()
				if s := oidMap[attrName]; s != "" {
					attrName = s
				}
				subjectName = append(subjectName, fmt.Sprintf("%s=%s", attrName, attr.Value))
			}
			h := sha256.New()
			h.Write(crt.Raw)
			metaInfo = append(metaInfo,
				fmt.Sprintf("\n# %s %s", hex.EncodeToString(h.Sum(nil)), strings.Join(subjectName, "/")))
		}
	}
	fmt.Fprintf(w, `# %s
%v %v %v
%v

`, strings.Join(metaInfo, " "), r.Method, r.RequestURI, r.Proto, strings.Join(hdrs, "\n"))
	if r.ContentLength > 0 {
		bodyData := make([]byte, r.ContentLength)
		r.Body.Read(bodyData)
		w.Write(bodyData)
	}
}
