package main

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

func init() {
	addAuthMethod("GeoIP", func(check string, roles []string) (Authenticator, error) {
		return NewGeoIPAuthenticator(check, roles)
	})
}

func NewGeoIPAuthenticator(check string, roles []string) (Authenticator, error) {
	options, code := parseCurlyParams(check)
	ah := &GeoIPAuthenticator{code: code, roles: roles}

	if options["file"] != "" {
		var err error
		ah.db, err = maxminddb.Open(options["file"])
		if err != nil {
			logf(nil, logLevelFatal, "cannot open database from %#v: %s", options["file"], err)
		}
	} else {
		logf(nil, logLevelFatal, "need file= option")
	}
	if rProxies := options["rprx"]; rProxies != "" {
		ah.rProxies = strings.Split(rProxies, ":")
	}
	if lookupKey := options["key"]; lookupKey != "" {
		ah.lookup = strings.Split(lookupKey, ":")
	} else {
		ah.lookup = append(ah.lookup, "country", "iso_code")
	}

	return ah, nil
}

type GeoIPAuthenticator struct {
	db       *maxminddb.Reader
	code     string
	roles    []string
	rProxies []string
	lookup   []string
}

// GetRoles implements Authenticator
func (ah *GeoIPAuthenticator) GetRoles(req *http.Request, rolesToCheck map[string]interface{}) ([]string, error) {
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		logf(req, logLevelError, "cannot parse remote address %#v: %s", req.RemoteAddr, err)
		return nil, errors.New("cannot parse address")
	}

	if xff := req.Header.Get("X-Forwarded-For"); xff != "" && len(ah.rProxies) > 0 {
		clientIP = ResolveXForwardedFor(append(strings.Split(xff, ", "), clientIP), ah.rProxies)
	}
	var record interface{}
	if err := ah.db.Lookup(net.ParseIP(clientIP), &record); err != nil {
		logf(req, logLevelError, "cannot lookup address %#v: %s", req.RemoteAddr, err)
		return nil, errors.New("cannot lookup address")
	}
	if v, ok := LookupMapPath(record, ah.lookup).(string); ok && v == ah.code {
		return ah.roles, nil
	}
	return nil, nil
}

func LookupMapPath(record interface{}, path []string) interface{} {
	for i, key := range path {
		if recMap, ok := record.(map[string]interface{}); ok {
			if val, have := recMap[key]; have {
				if i == len(path)-1 {
					return val
				} else {
					record = val
				}
			} else {
				break
			}
		} else {
			break
		}
	}
	return nil
}

func ResolveXForwardedFor(xFwdFor, rProxies []string) string {
	var lastIP string
	for i := 0; i < len(xFwdFor); i++ {
		lastIP = xFwdFor[len(xFwdFor)-i-1]
		if i >= len(rProxies) || lastIP != rProxies[i] {
			return lastIP
		}
	}
	return lastIP
}
