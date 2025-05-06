package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

type SNIPatternType int

const (
	SNIPatternAny = iota
	SNIPatternDomain
	SNIPatternExact
	SNIPatternRegex
)

type AuthX509Pattern struct {
	SType      SNIPatternType
	ClientAuth tls.ClientAuthType
	ClientCAs  *x509.CertPool
	sni        string
	rex        *regexp.Regexp
	require    bool
	action     string
}

var knownOIDs = map[string]asn1.ObjectIdentifier{
	"DOMAINCOMPONENT":     {0, 9, 2342, 19200300, 100, 1, 25},
	"DC":                  {0, 9, 2342, 19200300, 100, 1, 25},
	"EMAIL":               {1, 2, 840, 113549, 1, 9, 1},
	"UNSTRUCTUREDNAME":    {1, 2, 840, 113549, 1, 9, 2},
	"UNSTRUCTUREDADDRESS": {1, 2, 840, 113549, 1, 9, 8},
	"POSTALCODE":          {2, 5, 4, 1},
	"CN":                  {2, 5, 4, 3},
	"SN":                  {2, 5, 4, 4},
	"SURNAME":             {2, 5, 4, 4},
	"COMMONNAME":          {2, 5, 4, 3},
	"SERIALNUMBER":        {2, 5, 4, 5},
	"DEVICESERIALNUMBER":  {2, 5, 4, 5},
	"C":                   {2, 5, 4, 6},
	"L":                   {2, 5, 4, 7},
	"ST":                  {2, 5, 4, 8},
	"STREETADDRESS":       {2, 5, 4, 9},
	"O":                   {2, 5, 4, 10},
	"OU":                  {2, 5, 4, 11},
	"TITLE":               {2, 5, 4, 12},
	"GN":                  {2, 5, 4, 42},
	"GIVENNAME":           {2, 5, 4, 42},
	"INITIALS":            {2, 5, 4, 43},
}

func StringToOID(typeName string) (asn1.ObjectIdentifier, error) {
	if t, have := knownOIDs[strings.ToUpper(typeName)]; have {
		return t, nil
	}
	var asn1Type asn1.ObjectIdentifier
	for _, z := range strings.Split(typeName, ".") {
		if i, err := strconv.Atoi(z); err != nil {
			knownOIDNames := []string{}
			for v := range knownOIDs {
				knownOIDNames = append(knownOIDNames, v)
			}
			return nil, fmt.Errorf("cannot convert %#v to int: %s. supported OID names: %v", z, err, knownOIDNames)
		} else {
			asn1Type = append(asn1Type, i)
		}
	}
	return asn1Type, nil
}

func createCertFromDNs(dnList []string) (cert *x509.Certificate, err error) {
	subject := pkix.Name{}

	for _, n := range dnList {
		typeAndValue := strings.SplitN(n, "=", 2)
		if len(typeAndValue) != 2 {
			err = fmt.Errorf("no '=' in %#v", n)
			return
		}
		asn1Type, err := StringToOID(typeAndValue[0])
		if err != nil {
			return nil, err
		}
		name := pkix.AttributeTypeAndValue{Type: asn1Type, Value: typeAndValue[1]}
		if reflect.DeepEqual(asn1Type, knownOIDs["DC"]) || reflect.DeepEqual(asn1Type, knownOIDs["EMAIL"]) {
			name.Value = asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(name.Value.(string))}
		}
		subject.ExtraNames = append(subject.ExtraNames, name)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{Subject: subject}
	tmpl.SerialNumber, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	var crtBytes []byte
	crtBytes, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, privKey)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(crtBytes)
	return
}

func (pat *AuthX509Pattern) SetAction(action string) (err error) {
	var actOpts options
	actOpts, action = parseCurlyParams(action)
	if actOpts.IsTrue("require", false) {
		pat.require = true
	}
	switch action {
	case "none":
	case "any":
		pat.ClientAuth = tls.RequestClientCert
		if pat.require {
			pat.ClientAuth = tls.RequireAnyClientCert
		}
	default:
		if strings.HasPrefix(action, "file:") {
			if pat.ClientCAs == nil {
				pat.ClientCAs = x509.NewCertPool()
			}
			var pemData []byte
			pemData, err = os.ReadFile(action[len("file:"):])
			if err != nil {
				return
			}
			if !pat.ClientCAs.AppendCertsFromPEM(pemData) {
				err = fmt.Errorf("could not add certs from %#v", action)
				return
			}
			pat.ClientAuth = tls.VerifyClientCertIfGiven
			if pat.require {
				pat.ClientAuth = tls.RequireAndVerifyClientCert
			}
		} else if strings.HasPrefix(action, "dn:") {
			var crt *x509.Certificate
			crt, err = createCertFromDNs(strings.Split(action[len("dn:"):], "/"))
			if err != nil {
				return
			}
			if pat.ClientCAs == nil {
				pat.ClientCAs = x509.NewCertPool()
			}
			pat.ClientCAs.AddCert(crt)
			pat.ClientAuth = tls.RequestClientCert
			if pat.require {
				pat.ClientAuth = tls.RequireAnyClientCert
			}
		} else {
			return fmt.Errorf("action have to be 'file:<file.pem>', dn:AA=BB/CC=DD/1.2.3=XXX/..., 'any' or 'none', not %#v", action)
		}
	}
	pat.action = action
	return nil
}

func NewAuthX509Pat(sni string) (pat *AuthX509Pattern, err error) {
	pat = &AuthX509Pattern{}
	if sni == "*" {
		pat.SType = SNIPatternAny
	} else if strings.HasPrefix(sni, "*.") {
		pat.SType = SNIPatternDomain
		sni = sni[1:]
	} else if strings.HasPrefix(sni, "^") {
		pat.SType = SNIPatternRegex
		pat.rex = regexp.MustCompile(sni)
	} else {
		pat.SType = SNIPatternExact
	}
	pat.sni = sni
	return
}

func (ap AuthX509Pattern) String() (ret string) {
	switch ap.SType {
	case SNIPatternAny:
		ret = "*="
	case SNIPatternDomain:
		ret = "*" + ap.sni + "="
	case SNIPatternRegex:
		ret = "^" + ap.sni + "="
	default:
		ret = ap.sni + "="
	}
	if ap.require {
		ret += "{require=1}"
	}
	ret += ap.action
	return
}

func (ap AuthX509Pattern) Matches(sni string) bool {
	switch ap.SType {
	case SNIPatternAny:
		return true
	case SNIPatternDomain:
		return strings.HasSuffix(sni, ap.sni)
	case SNIPatternRegex:
		return ap.rex.MatchString(sni)
	}
	return strings.EqualFold(ap.sni, sni)
}

type AuthX509PatFlag []*AuthX509Pattern

// Set implements flag.Value.
func (authFlag *AuthX509PatFlag) Set(s string) (err error) {
	nameAndValue := strings.SplitN(s, "=", 2)
	if len(nameAndValue) != 2 {
		return fmt.Errorf("auth string %#v does not contain '=' ", s)
	}
	var pat *AuthX509Pattern
	var foundExisting bool
	for _, testPat := range *authFlag {
		if testPat.sni == nameAndValue[0] {
			pat = testPat
			foundExisting = true
			break
		}
	}
	if !foundExisting {
		pat, err = NewAuthX509Pat(nameAndValue[0])
		if err != nil {
			return err
		}
	}
	if err := pat.SetAction(nameAndValue[1]); err != nil {
		return err
	}
	if !foundExisting {
		*authFlag = append(*authFlag, pat)
	}

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
			return *p
		}
	}
	return AuthX509Pattern{}
}
