package main

import (
	"net/http"
	"net/url"
	"testing"
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
