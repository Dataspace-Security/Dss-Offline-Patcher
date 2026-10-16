package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T) (*Provider, func(map[string]any, string) string) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/a", "token_endpoint": srv.URL + "/t", "jwks_uri": srv.URL + "/jwks"})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1",
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}}})
		}
	}))
	t.Cleanup(srv.Close)
	p, err := New(context.Background(), Config{Issuer: srv.URL, ClientID: "app", RedirectURL: "https://x/cb",
		RoleGroups: map[string][]string{"viewer": {"v"}, "admin": {"a"}}}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	sign := func(c map[string]any, kid string) string {
		if c["iss"] == nil {
			c["iss"] = srv.URL
		}
		h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid})
		b, _ := json.Marshal(c)
		in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
		d := sha256.Sum256([]byte(in))
		s, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		return in + "." + base64.RawURLEncoding.EncodeToString(s)
	}
	return p, sign
}

func TestVerify(t *testing.T) {
	p, sign := setup(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Unix()
	good := sign(map[string]any{"aud": "app", "exp": exp, "sub": "u", "groups": []string{"v", "a"}, "amr": []string{"mfa"}}, "k1")
	c, err := p.Verify(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	id := p.identity(c)
	if id.Role != "admin" || !id.MFA {
		t.Fatalf("identity: %+v", id)
	}
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"app","exp":9999999999,"sub":"root"}`)) + "." + parts[2]
	cases := map[string]string{
		"tampered":    tampered,
		"wrong aud":   sign(map[string]any{"aud": "other", "exp": exp}, "k1"),
		"wrong iss":   sign(map[string]any{"iss": "https://evil", "aud": "app", "exp": exp}, "k1"),
		"expired":     sign(map[string]any{"aud": "app", "exp": time.Now().Add(-time.Hour).Unix()}, "k1"),
		"unknown kid": sign(map[string]any{"aud": "app", "exp": exp}, "k9"),
		"alg none":    base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k1"}`)) + "." + parts[1] + ".",
		"garbage":     "a.b",
	}
	for name, tok := range cases {
		if _, err := p.Verify(ctx, tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
