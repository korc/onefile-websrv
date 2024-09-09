package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestCertAuthNeed(t *testing.T) {
	caCertTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test CA"},
		SerialNumber:          big.NewInt(int64(time.Now().Unix())),
		NotAfter:              time.Now().Add(time.Hour),
		NotBefore:             time.Now().Add(-time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.CreateCertificate(rand.Reader, caCertTmpl, caCertTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertX509, err := x509.ParseCertificate(caCert)
	if err != nil {
		t.Fatal(err)
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	srvCert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(int64(time.Now().Unix())),
		NotAfter:     time.Now().Add(time.Hour),
		NotBefore:    time.Now().Add(-time.Minute),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::")},
		DNSNames:     []string{"localhost", "test-server"},
		Subject:      pkix.Name{CommonName: "test server"},
	}, caCertX509, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	// pem.Encode(os.Stderr, &pem.Block{Type: "CERTIFICATE", Bytes: srvCert})
	// pem.Encode(os.Stderr, &pem.Block{Type: "CERTIFICATE", Bytes: caCert})

	testAuth := func(ah *AuthHandler, t *testing.T, servername string) (requested bool, caList [][]byte, err error) {
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{srvCert}, PrivateKey: srvKey}}}
		casMap := ah.ConfigureServerTLSConfig(tlsConfig)
		t.Logf("casMap: %#v", casMap)
		ln, err := tls.Listen("tcp", ":0", tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		lnAddr := ln.Addr().String()
		t.Logf("Listening on: %s", lnAddr)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				t.Logf("Could not accept connection: %s", err)
				return
			}
			t.Logf("connect from: %#v", conn.RemoteAddr().String())
			conn.Write([]byte("Hi!"))
			conn.Close()
		}()

		clientConfig := &tls.Config{RootCAs: x509.NewCertPool(), GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			t.Logf("client certificate requested %q", cri.AcceptableCAs)
			caList = cri.AcceptableCAs
			requested = true
			return &tls.Certificate{}, nil
		}, ServerName: servername}
		clientConfig.RootCAs.AddCert(caCertX509)

		conn, err := tls.Dial("tcp", lnAddr, clientConfig)
		if err != nil {
			return false, nil, err
		} else {
			defer conn.Close()
			t.Log("connected")

			buf, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			if string(buf) != "Hi!" {
				t.Fatal("bad read buffer")
			}
		}
		return
	}

	t.Run("none", func(t *testing.T) {
		authHandler := &AuthHandler{}
		authHandler.AddACL("^/", []string{"admin"})
		requested, caList, err := testAuth(authHandler, t, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Requested: %v, CAs: %q", requested, caList)
		if requested || len(caList) != 0 {
			t.Fail()
		}
	})

	t.Run("any", func(t *testing.T) {
		authHandler := &AuthHandler{}
		authHandler.AddAuth("Cert", "a-cert-hash", "admin")
		authHandler.AddACL("^/", []string{"admin"})
		requested, caList, err := testAuth(authHandler, t, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Requested: %v, CAs: %q", requested, caList)
		if !requested {
			t.Fail()
		}
	})

	t.Run("pki", func(t *testing.T) {
		authHandler := &AuthHandler{}
		authHandler.AddAuth("CertBy", hex.EncodeToString(caCert), "admin")
		authHandler.AddACL("^/", []string{"admin"})
		requested, caList, err := testAuth(authHandler, t, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Requested: %v, CAs: %q", requested, caList)
		if !requested || len(caList) == 0 {
			t.Fail()
		}
	})

	t.Run("vhost", func(t *testing.T) {
		authHandler := &AuthHandler{}
		authHandler.AddAuth("Cert", "a-cert-hash", "any")
		authHandler.AddAuth("CertBy", hex.EncodeToString(caCert), "pki")
		authHandler.AddACL("{host:test-server}^/", []string{"any"})
		authHandler.AddACL("{host:localhost}^/", []string{"pki"})

		t.Run("no-vhost", func(t *testing.T) {
			requested, caList, err := testAuth(authHandler, t, "")
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("requested: %v, CAs: %q", requested, caList)
			if requested || len(caList) > 0 {
				t.Error("unexpected request")
			}
		})

		t.Run("any", func(t *testing.T) {
			requested, caList, err := testAuth(authHandler, t, "test-server")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("requested: %v, CAs: %q", requested, caList)
			if !requested {
				t.Error("should have request for certificate")
			} else if len(caList) > 0 {
				t.Error("should have no CA list")
			}
		})

		t.Run("pki", func(t *testing.T) {
			requested, caList, err := testAuth(authHandler, t, "localhost")
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("requested: %v, CAs: %q", requested, caList)
			if !requested || len(caList) == 0 {
				t.Error("should be request with CA list")
			}
		})
	})
}
