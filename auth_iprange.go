package main

import (
	"net"
	"net/http"
	"os"
	"strings"
)

func init() {
	addAuthMethod("IPRange", NewIPRangeAuthenticator)
}

type IPRangeAuthenticator struct {
	roles []string
	xff   []string
	ipNet []*net.IPNet
}

func NewIPRangeAuthenticator(check string, roles []string) (Authenticator, error) {
	options, params := parseCurlyParams(check)
	ah := &IPRangeAuthenticator{roles: roles}
	if strings.HasPrefix(params, "file:") {
		data, err := os.ReadFile(params[5:])
		if err != nil {
			return nil, err
		}
		for _, s := range strings.Split(string(data), "\n") {
			s = strings.TrimSpace(s)
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			if err := ah.addIPNet(s); err != nil {
				return nil, err
			}
		}
	} else if err := ah.addIPNet(params); err != nil {
		return nil, err
	}
	if xff := options["xff"]; xff != "" {
		ah.xff = strings.Split(xff, ":")
	}
	return ah, nil
}

func (ah *IPRangeAuthenticator) addIPNet(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ah.ipNet = append(ah.ipNet, ipNet)
	return nil
}

func (ah *IPRangeAuthenticator) GetRoles(req *http.Request, _ map[string]interface{}) ([]string, error) {
	clientIP, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, err
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" && len(ah.xff) > 0 {
		clientIP = ResolveXForwardedFor(append(strings.Split(xff, ", "), clientIP), ah.xff)
	}

	remoteHost := net.ParseIP(clientIP)
	for _, ipNet := range ah.ipNet {
		if ipNet.Contains(remoteHost) {
			return ah.roles, nil
		}
	}
	return nil, nil
}
