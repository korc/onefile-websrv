package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"strings"
)

type X509DNList []pkix.AttributeTypeAndValue

type SNIPatternType int

const (
	SNIPatternAny = iota
	SNIPatternDomain
	SNIPatternExact
)

type AuthX509Pattern struct {
	SType      SNIPatternType
	ClientAuth tls.ClientAuthType
	ClientCAs  *x509.CertPool
	sni        string
	require    bool
	action     string
}

func (l X509DNList) String() string {
	ret := []string{}
	for _, dn := range l {
		oid := ""
		for _, i := range dn.Type {
			if oid != "" {
				oid += "."
			}
			oid += fmt.Sprintf("%d", i)
		}
		if oidName, ok := oidMap[oid]; ok {
			oid = oidName
		}
		ret = append(ret, fmt.Sprintf("%s=%s", oid, dn.Value))
	}
	return strings.Join(ret, ",")
}

func NewAuthX509Pat(sni, action string) (ret AuthX509Pattern, err error) {
	if sni == "*" {
		ret.SType = SNIPatternAny
	} else if strings.HasPrefix(sni, "*.") {
		ret.SType = SNIPatternDomain
		sni = sni[1:]
	} else {
		ret.SType = SNIPatternExact
	}
	ret.sni = sni
	if strings.HasPrefix(action, "!") {
		ret.require = true
		action = action[1:]
	} else if strings.HasPrefix(action, "require:") {
		ret.require = true
		action = action[len("require:"):]
	}
	switch action {
	case "none":
	case "any":
		ret.ClientAuth = tls.RequestClientCert
		if ret.require {
			ret.ClientAuth = tls.RequireAnyClientCert
		}
	default:
		if strings.HasPrefix(action, "file:") {
			ret.ClientCAs = x509.NewCertPool()
			var pemData []byte
			pemData, err = os.ReadFile(action[len("file:"):])
			if err != nil {
				return
			}
			if !ret.ClientCAs.AppendCertsFromPEM(pemData) {
				err = fmt.Errorf("could not add certs from %#v", action)
				return
			}
			ret.ClientAuth = tls.VerifyClientCertIfGiven
			if ret.require {
				ret.ClientAuth = tls.RequireAndVerifyClientCert
			}
		} else {
			err = fmt.Errorf("action have to be 'file:<file.pem>', 'any' or 'none', not %#v", action)
		}
	}
	ret.action = action
	return
}

func (ap AuthX509Pattern) String() (ret string) {
	switch ap.SType {
	case SNIPatternAny:
		ret = "*="
	case SNIPatternDomain:
		ret = "*" + ap.sni + "="
	default:
		ret = ap.sni + "="
	}
	if ap.require {
		ret += "!"
	}
	ret += ap.action
	return
}

func (ap AuthX509Pattern) Matches(sni string) bool {
	if ap.SType == SNIPatternAny {
		return true
	}
	if ap.SType == SNIPatternDomain {
		return strings.HasSuffix(sni, ap.sni)
	}
	return strings.EqualFold(ap.sni, sni)
}

type AuthX509PatFlag []AuthX509Pattern

// Set implements flag.Value.
func (a *AuthX509PatFlag) Set(s string) error {
	nameAndValue := strings.SplitN(s, "=", 2)
	if len(nameAndValue) != 2 {
		return fmt.Errorf("auth string %#v does not contain '=' ", s)
	}
	pat, err := NewAuthX509Pat(nameAndValue[0], nameAndValue[1])
	if err != nil {
		return err
	}
	*a = append(*a, pat)

	return nil
}

// String implements flag.Value.
func (a AuthX509PatFlag) String() string {
	ret := []string{}
	for _, v := range a {
		ret = append(ret, v.String())
	}
	return strings.Join(ret, ", ")
}

func (a AuthX509PatFlag) FindPat(chi *tls.ClientHelloInfo) AuthX509Pattern {
	for _, p := range a {
		if p.Matches(strings.ToLower(chi.ServerName)) {
			return p
		}
	}
	return AuthX509Pattern{}
}
