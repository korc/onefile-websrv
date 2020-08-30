package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
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

// DebugRequest returns debugging information to client
func DebugRequest(w http.ResponseWriter, r *http.Request) {
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
