package e2e

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// fakeIdP is a minimal OIDC provider: /authorize immediately "logs in"
// whichever user the test selected and redirects back with a code.
type fakeIdP struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	user  map[string]any // claims for the next login
	codes map[string]map[string]string
}

func newIdP(t *testing.T) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: k, codes: map[string]map[string]string{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(k.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := fmt.Sprintf("c%d", time.Now().UnixNano())
		f.mu.Lock()
		f.codes[code] = map[string]string{"nonce": q.Get("nonce"), "challenge": q.Get("code_challenge"), "client": q.Get("client_id")}
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		c, ok := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		claims := map[string]any{}
		for k, v := range f.user {
			claims[k] = v
		}
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c["challenge"] {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		claims["iss"], claims["aud"], claims["nonce"] = f.srv.URL, c["client"], c["nonce"]
		claims["exp"], claims["iat"] = time.Now().Add(time.Hour).Unix(), time.Now().Unix()
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.sign(claims), "token_type": "Bearer"})
	})
	return f
}

func (f *fakeIdP) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, d[:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *fakeIdP) as(user string, groups []string, mfa bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user = map[string]any{"sub": "sub-" + user, "preferred_username": user, "email": user + "@corp.test", "groups": groups}
	if mfa {
		f.user["amr"] = []string{"pwd", "mfa"}
	} else {
		f.user["amr"] = []string{"pwd"}
	}
}

// browser logs in through the SSO redirect chain and returns a cookie client.
func (e *env) browser(t *testing.T, idp *fakeIdP, user string, groups []string, mfa bool) (*http.Client, string) {
	idp.as(user, groups, mfa)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Get(e.srv.URL + "/auth/login?return=/deployments")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return c, resp.Request.URL.String()
}

func call(t *testing.T, c *http.Client, method, u string, body any, csrf bool) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, u, rd)
	req.Header.Set("Content-Type", "application/json")
	if csrf {
		req.Header.Set("X-Offpatch-CSRF", "1")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestSSOAndTwoPersonApproval(t *testing.T) {
	idp := newIdP(t)
	extra := fmt.Sprintf(`"oidc": {"issuer": %q, "client_id": "offpatch-console", "redirect_url": "http://placeholder/auth/callback",
	  "role_groups": {"admin": ["pm-admins"], "user": ["pm-approvers", "pm-operators"], "viewer": ["pm-viewers"]}},
	  "require_mfa": true, "approval_policy": {"critical": 2}, "separation_of_duties": true,`, idp.srv.URL)
	e := newEnvOpts(t, false, extra)
	e.cfg.OIDC.RedirectURL = e.srv.URL + "/auth/callback"

	// ---- SSO login ----
	carol, landed := e.browser(t, idp, "carol", []string{"pm-approvers", "staff"}, true)
	if !strings.HasSuffix(landed, "/deployments") {
		t.Fatalf("login should land on return path, got %s", landed)
	}
	code, b := call(t, carol, "GET", e.srv.URL+"/api/me", nil, false)
	var me map[string]any
	json.Unmarshal(b, &me)
	if code != 200 || me["user"] != "carol" || me["role"] != "user" || me["source"] != "sso" || me["auth"] != "sso" || me["mfa"] != true {
		t.Fatalf("me: %d %s", code, b)
	}

	// No role group → refused.
	nobody, landed := e.browser(t, idp, "mallory", []string{"staff"}, true)
	if !strings.Contains(landed, "login_error") {
		t.Fatalf("user without role group should be refused, landed %s", landed)
	}
	if c, _ := call(t, nobody, "GET", e.srv.URL+"/api/me", nil, false); c != 401 {
		t.Fatalf("refused user has a session: %d", c)
	}
	// No MFA → refused.
	_, landed = e.browser(t, idp, "dave", []string{"pm-admins"}, false)
	if !strings.Contains(landed, "login_error") || !strings.Contains(landed, "Multi-factor") {
		t.Fatalf("login without MFA should be refused, landed %s", landed)
	}

	// ---- two-person approval for critical packages ----
	pkgs := map[string]manifest.Package{"KB5000009-x64": msuPkg("KB5000009-x64", "KB5000009")}
	files := map[string]string{"KB5000009-x64": e.payload("kb5000009.msu", "payload-9")}
	if b := e.transferAndIntake(e.bundle(bundleOpts{seq: 1}, pkgs, files)); b.State != "validated" {
		t.Fatalf("intake: %+v", b)
	}
	var p store.Package
	e.api("POST", "/api/packages/KB5000009-x64/approve", tokApprover, map[string]string{"reason": "CAB-1"}, &p)
	if p.State != "quarantined" || len(p.Approvals) != 1 || p.ApprovalsRequired != 2 {
		t.Fatalf("first approval of a critical package must not publish: %+v", p)
	}
	if c := e.api("POST", "/api/packages/KB5000009-x64/approve", tokApprover, map[string]string{"reason": "again"}, nil); c != 409 {
		t.Fatalf("same approver twice: %d", c)
	}
	// Cookie-authenticated writes need the CSRF header.
	if c, _ := call(t, carol, "POST", e.srv.URL+"/api/packages/KB5000009-x64/approve", map[string]string{"reason": "CAB-1 second"}, false); c != 401 {
		t.Fatalf("cookie POST without CSRF header: %d", c)
	}
	c, b := call(t, carol, "POST", e.srv.URL+"/api/packages/KB5000009-x64/approve", map[string]string{"reason": "CAB-1 second"}, true)
	json.Unmarshal(b, &p)
	if c != 200 || p.State != "approved" || len(p.Approvals) != 2 {
		t.Fatalf("second approval: %d %s", c, b)
	}

	// ---- separation of duties: approvers may not deploy ----
	dep := store.NewDeployment{PackageID: "KB5000009-x64", Name: "x", Rings: []store.Ring{{Name: "all", Groups: []string{"all"}}}, MaxFailurePct: 50}
	if c := e.createDep(tokApprover, dep, nil); c != 409 {
		t.Fatalf("approver deploying own approval: %d", c)
	}
	if c := e.createDep(tokOperator, dep, nil); c != 201 {
		t.Fatalf("operator deploy: %d", c)
	}

	// ---- user management: disable revokes sessions and blocks login ----
	var users []store.User
	e.api("GET", "/api/users", tokApprover, nil, &users) // approver is not admin
	if c := e.api("GET", "/api/users", tokApprover, nil, nil); c != 403 {
		t.Fatalf("non-admin listing users: %d", c)
	}
	admin, _ := e.browser(t, idp, "erin", []string{"pm-admins"}, true)
	c, b = call(t, admin, "GET", e.srv.URL+"/api/users", nil, false)
	json.Unmarshal(b, &users)
	sso := 0
	for _, u := range users {
		if u.Auth == "sso" {
			sso++
		}
	}
	if c != 200 || sso != 2 {
		t.Fatalf("users: %d %s", c, b)
	}
	if c, b := call(t, admin, "POST", e.srv.URL+"/api/users/carol/disable", map[string]string{"reason": "left the company"}, true); c != 200 {
		t.Fatalf("disable: %d %s", c, b)
	}
	if c, _ := call(t, carol, "GET", e.srv.URL+"/api/me", nil, false); c != 401 {
		t.Fatalf("disabled user's session still valid: %d", c)
	}
	_, landed = e.browser(t, idp, "carol", []string{"pm-approvers"}, true)
	if !strings.Contains(landed, "disabled") {
		t.Fatalf("disabled user could log in again: %s", landed)
	}

	// Logout ends the session.
	call(t, admin, "POST", e.srv.URL+"/auth/logout", nil, true)
	if c, _ := call(t, admin, "GET", e.srv.URL+"/api/me", nil, false); c != 401 {
		t.Fatalf("session valid after logout: %d", c)
	}
}
