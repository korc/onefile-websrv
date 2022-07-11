package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestAuthHost(t *testing.T) {
	basicTestPass := "dGVzdDpwYXNz" // test:pass
	h := &AuthHandler{}
	u, err := url.Parse("/")
	if err != nil {
		t.Errorf("Could not create url: %s", err)
	}
	h.AddAuth("Basic", basicTestPass, "test")
	_ = h.AddACL("{host:intra}^/", []string{"test"})
	t.Run("non-intra", func(t *testing.T) {
		if _, err := h.checkAuthPass(&http.Request{Header: map[string][]string{}, URL: u}); err != nil {
			t.Errorf("Failed: %s", err)
		}
	})
	t.Run("intra-no-auth", func(t *testing.T) {
		if _, err := h.checkAuthPass(&http.Request{Host: "intra", Header: map[string][]string{}, URL: u}); err == nil {
			t.Errorf("failed, err==nil")
		}
	})
	t.Run("intra-auth", func(t *testing.T) {
		if _, err := h.checkAuthPass(&http.Request{Host: "intra", Header: map[string][]string{
			"Authorization": {"Basic " + basicTestPass},
		}, URL: u}); err != nil {
			t.Errorf("Error with credentials: %s", err)
		}
	})
}

func TestFileWithIPRange(t *testing.T) {
	ah := &AuthHandler{}
	tmpDir := os.TempDir()
	ah.AddAuth("File", "{nofile=1,re-path="+tmpDir+"/$1}/(.+)", "nofile")
	ah.AddAuth("IPRange", "127.0.0.0/8", "localhost")
	ah.AddAuth("IPRange", "0.0.0.0/0", "ip4all")
	ah.AddAuth("IPRange", "::/0", "ip6all")
	ah.AddACL("{PUT}^/", []string{"ip6all+nofile"})
	ah.AddACL("{GET}^/", []string{"ip4all", "ip6all"})
	ah.AddACL("{DELETE}^/+", []string{"localhost"})
	ah.AddACL("^/", []string{"nobody"})

	tmpFileExisting, err := os.CreateTemp(tmpDir, "auth-check-exist-*")
	if err != nil {
		t.Skip("cannot create temp file", err)
	}
	defer tmpFileExisting.Close()
	tmpNotExisting, _ := os.CreateTemp(tmpDir, "auth-check-nofile-*")
	defer tmpNotExisting.Close()
	os.Remove(tmpNotExisting.Name())
	existingURL, _ := url.Parse("/" + path.Base(tmpFileExisting.Name()))
	nonExistingURL, _ := url.Parse("/" + path.Base(tmpNotExisting.Name()))
	myAddrIpv4 := "127.0.0.1:12345"
	myAddrIpv6 := "[::1]:12345"
	otherIpv4 := "1.2.3.4:12345"

	conf := struct {
		target *url.URL
		method string
		client string
	}{}

	fail := false
	succeed := true

	assert := func(t *testing.T, succeed bool) bool {
		_, err := ah.checkAuthPass(&http.Request{Header: http.Header{}, URL: conf.target, Method: conf.method, RemoteAddr: conf.client})
		if succeed && err != nil {
			t.Error("should succeed")
		} else if !succeed && err == nil {
			t.Error("should fail")
		}
		return err == nil
	}

	t.Run("PUT", func(t *testing.T) {
		conf.method = "PUT"
		t.Run("existing", func(t *testing.T) {
			conf.target = existingURL
			t.Run("ipv6", func(t *testing.T) {
				conf.client = myAddrIpv6
				assert(t, fail)
			})
			t.Run("ipv4", func(t *testing.T) {
				conf.client = myAddrIpv4
				assert(t, fail)
			})
		})
		t.Run("non-existing", func(t *testing.T) {
			conf.target = nonExistingURL
			t.Run("ipv4", func(t *testing.T) {
				conf.client = myAddrIpv4
				assert(t, fail)
			})
			t.Run("ipv6", func(t *testing.T) {
				conf.client = myAddrIpv6
				assert(t, succeed)
			})
		})
	})
	t.Run("GET", func(t *testing.T) {
		conf.method = "GET"
		t.Run("existing", func(t *testing.T) {
			conf.target = existingURL
			t.Run("ipv4", func(t *testing.T) {
				conf.client = otherIpv4
				assert(t, succeed)
			})
			t.Run("ipv6", func(t *testing.T) {
				conf.client = myAddrIpv6
				assert(t, succeed)
			})
		})
		t.Run("non-existing-ipv6", func(t *testing.T) {
			conf.target = existingURL
			conf.client = myAddrIpv6
			assert(t, succeed)
		})
	})
	t.Run("DELETE", func(t *testing.T) {
		conf.method = "DELETE"
		t.Run("existing", func(t *testing.T) {
			conf.target = existingURL
			t.Run("other", func(t *testing.T) {
				conf.client = otherIpv4
				assert(t, fail)
			})
			t.Run("self", func(t *testing.T) {
				t.Run("ipv4", func(t *testing.T) {
					conf.client = myAddrIpv4
					assert(t, succeed)
				})
				t.Run("ipv6", func(t *testing.T) {
					conf.client = myAddrIpv6
					assert(t, fail)
				})
			})
		})
	})
	t.Run("OPTIONS", func(t *testing.T) {
		conf.method = "OPTIONS"
		t.Run("existing", func(t *testing.T) {
			conf.target = existingURL
			t.Run("ipv6", func(t *testing.T) {
				conf.client = myAddrIpv6
				assert(t, fail)
			})
		})
		t.Run("non-existing", func(t *testing.T) {
			conf.target = nonExistingURL
			t.Run("ipv6", func(t *testing.T) {
				conf.client = myAddrIpv6
				assert(t, fail)
			})
		})
	})
	os.Remove(tmpFileExisting.Name())
}

func TestJWKAuth(t *testing.T) {
	jwks1 := `{"keys":[{"alg":"ES256","crv":"P-256","d":"wd7wz78KCVwvbikjHyy2jzyWVXJ8JPyb3u3HOv1Oca0","key_ops":["sign","verify"],"kid":"test","kty":"EC","x":"2N6xSlRBC8XxUikjbKibW4w6sYR-DcsJS7SmGy5tg_s","y":"F6kZrW2hAC4UHsgQC-GRW2npLeZwdP2iujmwIroWBPU"}]}`
	tkn1 := "eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3QiLCJ0eXAiOiJKV1QifQ.eyJyb2xlIjoidGVzdCIsImF1ZCI6Inp6eiJ9.dnCN9ctSIdKMmDBgFAfzGnFQJZDD1qfwVG4515vaHqjPVibR0EZqp4kIKQkil0-KAk0p_ayXGi5RKy9QrtZZZg"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(jwks1))
	}))
	defer srv.Close()
	h := &AuthHandler{}
	h.AddAuth("JWT", "{jwks=1}http:"+srv.URL, "jwks")
	h.AddAuth("JWT", "{jwks=1,aud-re=/(.+)\\.aaa$}http:"+srv.URL, "jwks-aud")
	t.Run("no-aud", func(t *testing.T) {
		u, _ := url.Parse("/")
		if req, err := h.checkAuthPass(&http.Request{
			Header: http.Header{"Authorization": []string{"Bearer " + tkn1}},
			URL:    u,
		}); err != nil {
			t.Errorf("auth failed: %s", err)
		} else {
			roles := req.Context().Value(authRoleContext).(map[string]bool)
			if _, ok := roles["jwks"]; !ok {
				t.Error("no 'jwks' role")
			}
			if _, ok := roles["jwks-aud"]; ok {
				t.Error("should not have 'jwks-aud' role")
			}
		}
	})

	t.Run("have-aud", func(t *testing.T) {
		u, _ := url.Parse("/zzz.aaa")
		if req, err := h.checkAuthPass(&http.Request{
			Header: http.Header{"Authorization": []string{"Bearer " + tkn1}},
			URL:    u,
		}); err != nil {
			t.Errorf("auth failed: %s", err)
		} else {
			roles := req.Context().Value(authRoleContext).(map[string]bool)
			if _, ok := roles["jwks"]; !ok {
				t.Error("no 'jwks' role")
			}
			if _, ok := roles["jwks-aud"]; !ok {
				t.Error("should have 'jwks-aud' role")
			}
		}
	})
}

func TestJWTSecretAuth(t *testing.T) {
	tokens := make([]struct {
		role        string
		secret      string
		signedToken string
	}, 3)
	h := &AuthHandler{}
	for i := range tokens {
		rndBytes := make([]byte, 8)
		rand.Reader.Read(rndBytes)
		tokens[i].role = fmt.Sprintf("test%d", i+1)
		tokens[i].secret = hex.EncodeToString(rndBytes)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": fmt.Sprintf("test-%d", i)})
		var err error
		tokens[i].signedToken, err = token.SignedString([]byte(tokens[i].secret))
		if err != nil {
			t.Error("Could not get signed token: ", err)
		}
		t.Logf("Signed token: %#v (secret=%#v)", tokens[i].signedToken, tokens[i].secret)
	}
	u, _ := url.Parse("/")
	h.AddAuth("JWTSecret", tokens[0].secret, tokens[0].role)
	h.AddAuth("JWTSecret", "{cookie=tst,header=X-Secret,query=tsse}"+tokens[1].secret, tokens[1].role)
	os.Setenv("TKN3SECRET", tokens[2].secret)
	h.AddAuth("JWTSecret", "${TKN3SECRET}", tokens[2].role)

	t.Run("jwt-secret", func(t *testing.T) {
		if _, err := h.checkAuthPass(&http.Request{Header: http.Header{}, URL: u}); err == nil {
			t.Error("Auth should not pass")
		}
		if req, err := h.checkAuthPass(&http.Request{Header: http.Header{"Authorization": []string{"Bearer " + tokens[0].signedToken}}, URL: u}); err != nil {
			t.Errorf("Auth should pass")
		} else {
			roles := req.Context().Value(authRoleContext).(map[string]bool)
			if _, ok := roles["test1"]; !ok {
				t.Error("Should have test1 role")
			}
		}
		if req, err := h.checkAuthPass(&http.Request{Header: http.Header{"Cookie": []string{"tst=" + tokens[1].signedToken}, "Authorization": []string{"Bearer " + tokens[2].signedToken}}, URL: u}); err != nil {
			t.Errorf("Auth should pass")
		} else {
			roles := req.Context().Value(authRoleContext).(map[string]bool)
			if _, ok := roles["test2"]; !ok {
				t.Error("Should have test2 role")
			}
			if _, ok := roles["test3"]; !ok {
				t.Error("Should have test3 role")
			}
		}
		q := u.Query()
		q.Set("tsse", tokens[1].signedToken)
		u.RawQuery = q.Encode()
		t.Logf("query param: %#v", u.Query().Get("tsse"))
		if req, err := h.checkAuthPass(&http.Request{Header: http.Header{}, URL: u}); err != nil {
			t.Errorf("Auth should pass")
		} else {
			roles := req.Context().Value(authRoleContext).(map[string]bool)
			if _, ok := roles["test2"]; !ok {
				t.Error("Should have test2 role")
			}
			delete(roles, "test2")
			if len(roles) > 0 {
				t.Error("Should have no other roles")
			}
		}
	})
}
