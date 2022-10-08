package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestJWTtoJWT(t *testing.T) {
	srcSecret := bytes.NewBufferString("")
	io.CopyN(srcSecret, rand.Reader, 8)
	srcToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "this-is-me", "https://google.com/search": "WUT?"})
	srcJwt, err := srcToken.SignedString(srcSecret.Bytes())
	if err != nil {
		t.Fatalf("cannot sign token: %s", err)
		return
	}
	t.Logf("source token: %s", srcJwt)
	dstSecret := bytes.NewBufferString("")
	io.CopyN(dstSecret, rand.Reader, 8)
	params := "{aud=jwt:sub:q:tkn,exp=ts:+1h,sub=jwt:https%3A//google.com/search:q:tkn,b64=1}"
	h, err := protocolHandlers["jwt"]("/", params+base64.StdEncoding.EncodeToString(dstSecret.Bytes()), &serverConfig{logger: &simpleLogger{}})
	if err != nil {
		t.Errorf("cannot create jwt protocol handler: %s", err)
		return
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.DefaultClient.Get(srv.URL + "?tkn=" + url.QueryEscape(srcJwt))
	if err != nil {
		t.Errorf("could not get response from test server: %s", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("bad response code: %d", resp.StatusCode)
		return
	}
	retJwt, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("can't read token: %s", err)
		return
	}
	t.Logf("returned token: %s", retJwt)
	retToken, err := jwt.Parse(string(retJwt), func(t *jwt.Token) (interface{}, error) { return dstSecret.Bytes(), nil })
	if err != nil {
		t.Errorf("can't parse token: %s", err)
		return
	}
	if retToken.Claims.(jwt.MapClaims)["sub"] != "WUT?" {
		t.Errorf("sub claim not expected 'WUT?': %#v", retToken.Claims.(jwt.MapClaims)["sub"])
	}
	if retToken.Claims.(jwt.MapClaims)["aud"] != "this-is-me" {
		t.Errorf("aud claim not expected 'thi-is-me': %#v", retToken.Claims.(jwt.MapClaims)["aud"])
	}
}
