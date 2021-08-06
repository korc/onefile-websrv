package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/golang-jwt/jwt"
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
