package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"offpatch/internal/manifest"
	"offpatch/internal/repo"
	"offpatch/internal/store"
)

func init() { store.PasswordIterations = 1000 } // fast tests

// Static tokens per role (aliases included: operator and approver are user).
var roleTokens = map[string]string{
	"viewer": "t-viewer", "operator": "t-operator", "approver": "t-approver", "user": "t-user",
	"admin": "t-admin", "super_admin": "t-super",
}

// newRolesServer: a lab server with one static token per role in roleTokens
// (unless noTokens), extra spliced into the config.
func newRolesServer(t *testing.T, extra string, noTokens bool) *Server {
	t.Helper()
	dir := t.TempDir()
	pub, _, _ := manifest.GenerateKey()
	var toks []string
	if !noTokens {
		for role, tok := range roleTokens {
			toks = append(toks, fmt.Sprintf(`{"user":"tok-%s","role":%q,"token_sha256":%q}`, role, role, store.HashSecret(tok)))
		}
	}
	cfg := fmt.Sprintf(`{"insecure_http": true, %s "data_dir": "data", "trusted_keys":[{"public_key": %q, "sources":["s"]}], "admin_tokens":[%s]}`,
		extra, manifest.EncodePublic(pub), strings.Join(toks, ","))
	p := filepath.Join(dir, "pmserver.json")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(c.DataDir, 0o750)
	st, err := store.Open(filepath.Join(c.DataDir, "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rp, _ := repo.New(filepath.Join(c.DataDir, "repository"))
	ui := fstest.MapFS{"index.html": {Data: []byte("<html>console</html>")}}
	s, err := New(c, st, rp, ui, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type req struct {
	method, path string
	body         any
	token        string
	cookie       *http.Cookie
	csrf         bool
	ip           string
	tls          bool
}

func do(h http.Handler, q req) *httptest.ResponseRecorder {
	var rd io.Reader
	if q.body != nil {
		b, _ := json.Marshal(q.body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(q.method, q.path, rd)
	if q.token != "" {
		r.Header.Set("Authorization", "Bearer "+q.token)
	}
	if q.cookie != nil {
		r.AddCookie(q.cookie)
	}
	if q.csrf {
		r.Header.Set(csrfHeader, "1")
	}
	r.RemoteAddr = "192.0.2.1:5000"
	if q.ip != "" {
		r.RemoteAddr = q.ip + ":5000"
	}
	if q.tls {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errBody(w *httptest.ResponseRecorder) string {
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal(w.Body.Bytes(), &e)
	return e.Error
}

// The route table enforces the permission table for every role: below the
// minimum role → 403 (audited); at or above → not refused for the role.
func TestPermissionTable(t *testing.T) {
	s := newRolesServer(t, "", false)
	h := s.Handler()
	routes := []struct{ method, path, min string }{
		{"GET", "/api/summary", "viewer"},
		{"GET", "/api/deployments", "viewer"},
		{"GET", "/api/audit", "viewer"},
		{"GET", "/api/policy", "viewer"},
		{"POST", "/api/alerts/1/ack", "user"},
		{"POST", "/api/packages/p-1/approve", "user"},
		{"POST", "/api/packages/p-1/reject", "user"},
		{"POST", "/api/packages/p-1/revoke", "admin"},
		{"POST", "/api/acquisition-requests", "user"},
		{"PATCH", "/api/endpoints/e-1", "user"},
		{"POST", "/api/endpoints/e-1/retire", "user"},
		{"POST", "/api/enrollment-tokens", "user"},
		{"POST", "/api/deployments", "user"},
		{"POST", "/api/deployments/d-1/pause", "user"},
		{"POST", "/api/deployments/d-1/cancel", "user"},
		{"POST", "/api/deployments/d-1/approve", "user"},
		{"POST", "/api/deployments/d-1/reject", "user"},
		{"POST", "/api/deployments/d-1/retry_failed", "user"},
		{"POST", "/api/maintenance-windows", "user"},
		{"POST", "/api/maintenance-windows/w-1/delete", "user"},
		{"POST", "/api/exceptions", "admin"},
		{"POST", "/api/exceptions/x-1/revoke", "admin"},
		{"GET", "/api/users", "admin"},
		{"POST", "/api/users", "admin"},
		{"POST", "/api/users/someone@bank.example/disable", "admin"},
	}
	for _, rt := range routes {
		for role, tok := range roleTokens {
			w := do(h, req{method: rt.method, path: rt.path, body: map[string]any{}, token: tok})
			allowed := store.RoleRank(role) >= store.RoleRank(rt.min)
			if allowed && (w.Code == 401 || (w.Code == 403 && strings.HasPrefix(errBody(w), "requires role"))) {
				t.Errorf("%s %s as %s: refused (%d %s), min role %s", rt.method, rt.path, role, w.Code, w.Body, rt.min)
			}
			if !allowed && (w.Code != 403 || errBody(w) != "requires role "+rt.min) {
				t.Errorf("%s %s as %s: want 403 requires role %s, got %d %s", rt.method, rt.path, role, rt.min, w.Code, w.Body)
			}
		}
	}
	evs, _ := s.store.ListAudit(context.Background(), store.AuditQuery{Action: "access.denied"})
	if len(evs) == 0 {
		t.Fatal("denials not audited")
	}
	if w := do(h, req{method: "GET", path: "/api/summary"}); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
}

func TestMeAndPolicy(t *testing.T) {
	s := newRolesServer(t, `"deployment_approvals": 3,`, false)
	h := s.Handler()
	w := do(h, req{method: "GET", path: "/api/me", token: roleTokens["approver"]})
	var me map[string]any
	json.Unmarshal(w.Body.Bytes(), &me)
	if w.Code != 200 || me["role"] != "user" || me["auth"] != "token" || me["user"] != "tok-approver" || me["must_change_password"] != false {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	var pol map[string]any
	json.Unmarshal(do(h, req{method: "GET", path: "/api/policy", token: roleTokens["viewer"]}).Body.Bytes(), &pol)
	if pol["deployment_approvals"] != float64(3) {
		t.Fatalf("policy: %v", pol)
	}
	if s.store.Policy.TokenSuperAdmins != 1 || !s.store.Policy.ReservedUsers["tok-admin"] {
		t.Fatalf("policy from tokens: %+v", s.store.Policy)
	}
	// The console's /login (and /login?token=1) is the SPA.
	if w := do(h, req{method: "GET", path: "/login?token=1"}); w.Code != 200 || !strings.Contains(w.Body.String(), "console") {
		t.Fatalf("/login: %d", w.Code)
	}
	var ac map[string]any
	json.Unmarshal(do(h, req{method: "GET", path: "/auth/config"}).Body.Bytes(), &ac)
	if ac["password_login"] != true {
		t.Fatalf("auth config: %v", ac)
	}
	// Token "logout": nothing to end, still 200.
	if w := do(h, req{method: "POST", path: "/api/auth/logout", token: roleTokens["viewer"], csrf: true}); w.Code != 200 {
		t.Fatalf("token logout: %d", w.Code)
	}
}

func TestDeploymentApprovalsConfig(t *testing.T) {
	for _, c := range []struct {
		extra string
		ok    bool
		want  int
	}{{"", true, 2}, {`"deployment_approvals": 1,`, true, 1}, {`"deployment_approvals": 0,`, false, 0}, {`"deployment_approvals": 6,`, false, 0}} {
		cfg, err := LoadConfig(writeConfig(t, t.TempDir(), c.extra))
		if (err == nil) != c.ok || (c.ok && *cfg.DeploymentApprovals != c.want) {
			t.Errorf("%q: %v", c.extra, err)
		}
	}
	dir := t.TempDir()
	p := writeConfig(t, dir, "")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, bytes.Replace(b, []byte(`"role":"viewer"`), []byte(`"role":"root"`), 1), 0o600)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "super_admin") {
		t.Fatalf("unknown token role: %v", err)
	}
	os.WriteFile(p, bytes.Replace(b, []byte(`"role":"viewer"`), []byte(`"role":"operator"`), 1), 0o600)
	if c, err := LoadConfig(p); err != nil || c.AdminTokens[0].Role != "user" {
		t.Fatalf("operator alias: %v %+v", err, c)
	}
}

const testPW = "a long enough password"

func mkLocal(t *testing.T, s *Server, email, role string, mustChange bool) {
	t.Helper()
	if _, err := s.store.CreateLocalUser(context.Background(), store.Manager{Actor: "system:test", Role: store.RoleSuperAdmin},
		store.NewLocalUser{Email: email, Role: role, Password: testPW}, mustChange); err != nil {
		t.Fatal(err)
	}
}

func login(t *testing.T, h http.Handler, email, pw string) *http.Cookie {
	t.Helper()
	w := do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": email, "password": pw}, csrf: true, ip: "198.51.100.7"})
	if w.Code != 200 {
		t.Fatalf("login %s: %d %s", email, w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestPasswordLoginFlow(t *testing.T) {
	s := newRolesServer(t, "", false)
	h := s.Handler()
	mkLocal(t, s, "uma@bank.example", "user", true)
	body := func(email, pw string) map[string]string { return map[string]string{"email": email, "password": pw} }

	if w := do(h, req{method: "POST", path: "/api/auth/login", body: body("uma@bank.example", testPW)}); w.Code != 403 || !strings.Contains(errBody(w), csrfHeader) {
		t.Fatalf("login without CSRF header: %d %s", w.Code, w.Body)
	}
	wrong := do(h, req{method: "POST", path: "/api/auth/login", body: body("uma@bank.example", "not the password"), csrf: true})
	unknown := do(h, req{method: "POST", path: "/api/auth/login", body: body("nobody@bank.example", testPW), csrf: true})
	if wrong.Code != 401 || unknown.Code != 401 || wrong.Body.String() != unknown.Body.String() || errBody(wrong) != "wrong email or password" {
		t.Fatalf("enumeration: wrong %d %s, unknown %d %s", wrong.Code, wrong.Body, unknown.Code, unknown.Body)
	}
	w := do(h, req{method: "POST", path: "/api/auth/login", body: body("UMA@bank.example", testPW), csrf: true, tls: true})
	if w.Code != 200 || strings.Contains(w.Body.String(), "pbkdf2") {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var ck *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" || ck.MaxAge <= 0 {
		t.Fatalf("cookie flags: %+v", ck)
	}
	// Temporary password: only /api/me, password change and logout.
	if w := do(h, req{method: "GET", path: "/api/summary", cookie: ck}); w.Code != 403 || errBody(w) != "password_change_required" {
		t.Fatalf("forced change: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "POST", path: "/api/maintenance-windows", body: map[string]any{}, cookie: ck, csrf: true}); w.Code != 403 || errBody(w) != "password_change_required" {
		t.Fatalf("forced change (write): %d %s", w.Code, w.Body)
	}
	var me map[string]any
	w = do(h, req{method: "GET", path: "/api/me", cookie: ck})
	json.Unmarshal(w.Body.Bytes(), &me)
	if w.Code != 200 || me["auth"] != "password" || me["email"] != "uma@bank.example" || me["must_change_password"] != true || me["role"] != "user" || me["password_changed_at"] != "" {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	chg := map[string]string{"current": testPW, "new": "my own new passphrase"}
	if w := do(h, req{method: "POST", path: "/api/auth/password", body: chg, cookie: ck}); w.Code != 401 {
		t.Fatalf("password change without CSRF: %d", w.Code)
	}
	if w := do(h, req{method: "POST", path: "/api/auth/password", body: map[string]string{"current": "wrong one here", "new": "my own new passphrase"}, cookie: ck, csrf: true}); w.Code != 400 {
		t.Fatalf("wrong current: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "POST", path: "/api/auth/password", body: map[string]string{"current": testPW, "new": "short"}, cookie: ck, csrf: true}); w.Code != 400 {
		t.Fatalf("short new: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "POST", path: "/api/auth/password", body: chg, cookie: ck, csrf: true}); w.Code != 200 {
		t.Fatalf("change: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/api/summary", cookie: ck}); w.Code != 200 {
		t.Fatalf("after change: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "POST", path: "/api/auth/password", body: chg, token: roleTokens["admin"]}); w.Code != 409 {
		t.Fatalf("token principal changing password: %d", w.Code)
	}
	// Logout ends the session (and needs the CSRF header: no forced logout).
	if w := do(h, req{method: "POST", path: "/api/auth/logout", cookie: ck}); w.Code != 403 {
		t.Fatalf("logout without CSRF header: %d", w.Code)
	}
	if w := do(h, req{method: "POST", path: "/api/auth/logout", cookie: ck, csrf: true}); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := do(h, req{method: "GET", path: "/api/me", cookie: ck}); w.Code != 401 {
		t.Fatalf("after logout: %d", w.Code)
	}
}

func TestLoginLockoutAndRateLimit(t *testing.T) {
	s := newRolesServer(t, "", false)
	h := s.Handler()
	mkLocal(t, s, "uma@bank.example", "user", false)
	try := func(ip, pw string) *httptest.ResponseRecorder {
		return do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "uma@bank.example", "password": pw}, csrf: true, ip: ip})
	}
	for i := 0; i < store.MaxFailedLogins; i++ {
		if w := try("203.0.113.1", "wrong guess number"); w.Code != 401 {
			t.Fatalf("guess %d: %d", i, w.Code)
		}
	}
	if w := try("203.0.113.2", testPW); w.Code != 401 || errBody(w) != "wrong email or password" {
		t.Fatalf("locked account: %d %s", w.Code, w.Body)
	}
	// Per-IP limit: loginBurst attempts, then 429 (before any password work).
	mkLocal(t, s, "ivy@bank.example", "user", false)
	for i := 0; i < loginBurst; i++ {
		if w := do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "nobody@x.example", "password": "x"}, csrf: true, ip: "203.0.113.9"}); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "ivy@bank.example", "password": testPW}, csrf: true, ip: "203.0.113.9"})
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("rate limit: %d %v", w.Code, w.Header())
	}
	if w := do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "ivy@bank.example", "password": testPW}, csrf: true, ip: "203.0.113.10"}); w.Code != 200 {
		t.Fatalf("other address: %d", w.Code)
	}
}

func TestLoginKey(t *testing.T) {
	if loginKey("192.0.2.1") != "192.0.2.1" || loginKey("2001:db8:1:2:aaaa::1") != loginKey("2001:db8:1:2:bbbb::9") || loginKey("2001:db8:1:2::1") == loginKey("2001:db8:1:3::1") {
		t.Fatal("login rate-limit keys")
	}
}

func TestPasswordLoginRefusedWhenMFARequired(t *testing.T) {
	oidcCfg := `"oidc": {"issuer": "https://idp.corp", "client_id": "pm", "redirect_url": "https://pm/auth/callback"}, "require_mfa": true,`
	s := newRolesServer(t, oidcCfg, false)
	mkLocal(t, s, "uma@bank.example", "user", false)
	w := do(s.Handler(), req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "uma@bank.example", "password": testPW}, csrf: true})
	if w.Code != 403 || !strings.Contains(errBody(w), "multi-factor") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestUserManagementAPI(t *testing.T) {
	s := newRolesServer(t, "", true) // no tokens: local users only
	h := s.Handler()
	mkLocal(t, s, "vendor@offpatch.local", "super_admin", false)
	mkLocal(t, s, "adam@bank.example", "admin", false)
	sup := login(t, h, "vendor@offpatch.local", testPW)
	adm := login(t, h, "adam@bank.example", testPW)
	post := func(ck *http.Cookie, path string, body any) *httptest.ResponseRecorder {
		return do(h, req{method: "POST", path: path, body: body, cookie: ck, csrf: true})
	}
	// Admin: bank roles only.
	if w := post(adm, "/api/users", map[string]string{"email": "v2@offpatch.local", "role": "super_admin", "password": "temporary password 1"}); w.Code != 403 {
		t.Fatalf("admin creates super admin: %d %s", w.Code, w.Body)
	}
	if w := post(adm, "/api/users/vendor@offpatch.local/disable", map[string]string{"reason": "x"}); w.Code != 403 {
		t.Fatalf("admin disables super admin: %d %s", w.Code, w.Body)
	}
	if w := post(adm, "/api/users/vendor@offpatch.local/reset_password", map[string]string{}); w.Code != 403 {
		t.Fatalf("admin resets super admin: %d %s", w.Code, w.Body)
	}
	evs, _ := s.store.ListAudit(context.Background(), store.AuditQuery{Action: "access.denied"})
	if len(evs) < 3 {
		t.Fatalf("refusals audited: %d", len(evs))
	}
	w := post(adm, "/api/users", map[string]string{"email": "Uma@Bank.Example", "display_name": "Uma", "role": "user"})
	var created map[string]any
	json.Unmarshal(w.Body.Bytes(), &created)
	temp, _ := created["temp_password"].(string)
	if w.Code != 201 || created["email"] != "uma@bank.example" || len(temp) < 12 || created["must_change_password"] != true {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w := post(adm, "/api/users", map[string]string{"email": "ivy@bank.example", "role": "viewer", "password": "temporary password 1"}); w.Code != 201 || strings.Contains(w.Body.String(), "temp_password") {
		t.Fatalf("create with a given password: %d %s", w.Code, w.Body)
	}
	uma := login(t, h, "uma@bank.example", temp)
	if w := post(adm, "/api/users/uma@bank.example/set_role", map[string]string{"role": "super_admin"}); w.Code != 403 {
		t.Fatalf("admin grants super admin: %d", w.Code)
	}
	if w := post(adm, "/api/users/uma@bank.example/set_role", map[string]string{"role": "admin", "reason": "lead"}); w.Code != 200 {
		t.Fatalf("set_role: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/api/me", cookie: uma}); w.Code != 401 {
		t.Fatalf("role change must end sessions: %d", w.Code)
	}
	w = post(adm, "/api/users/uma@bank.example/reset_password", map[string]string{"reason": "forgot"})
	var rp map[string]any
	json.Unmarshal(w.Body.Bytes(), &rp)
	if w.Code != 200 || len(rp["temp_password"].(string)) < 12 {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	if w := post(adm, "/api/users/adam@bank.example/disable", map[string]string{"reason": "x"}); w.Code != 409 {
		t.Fatalf("disable self: %d", w.Code)
	}
	if w := post(adm, "/api/users/uma@bank.example/frobnicate", map[string]string{}); w.Code != 404 {
		t.Fatalf("unknown action: %d", w.Code)
	}
	w = do(h, req{method: "GET", path: "/api/users", cookie: adm})
	if w.Code != 200 || strings.Contains(w.Body.String(), "pbkdf2") || strings.Contains(w.Body.String(), "hash") {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var us []store.User
	json.Unmarshal(w.Body.Bytes(), &us)
	if len(us) != 4 {
		t.Fatalf("users: %+v", us)
	}
	// Last super admin: the only one cannot be disabled (and not by themselves).
	if w := post(sup, "/api/users/vendor@offpatch.local/disable", map[string]string{"reason": "x"}); w.Code != 409 {
		t.Fatalf("super admin disables self: %d", w.Code)
	}
	if w := post(sup, "/api/users", map[string]string{"email": "v2@offpatch.local", "role": "super_admin", "password": "temporary password 1"}); w.Code != 201 {
		t.Fatalf("super admin creates super admin: %d %s", w.Code, w.Body)
	}
	if w := post(sup, "/api/users/v2@offpatch.local/set_role", map[string]string{"role": "admin"}); w.Code != 200 {
		t.Fatalf("demote second super admin: %d %s", w.Code, w.Body)
	}
	mkLocal(t, s, "v3@offpatch.local", "super_admin", false)
	v3 := login(t, h, "v3@offpatch.local", testPW)
	if w := post(v3, "/api/users/vendor@offpatch.local/disable", map[string]string{"reason": "rotate"}); w.Code != 200 {
		t.Fatalf("disable one of two: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/api/me", cookie: sup}); w.Code != 401 {
		t.Fatalf("disabled super admin still signed in: %d", w.Code)
	}
	mkLocal(t, s, "v4@offpatch.local", "super_admin", false)
	v4 := login(t, h, "v4@offpatch.local", testPW)
	post(v3, "/api/users/v4@offpatch.local/disable", map[string]string{"reason": "x"})
	if w := post(v4, "/api/users/v3@offpatch.local/disable", map[string]string{"reason": "x"}); w.Code != 401 {
		t.Fatalf("disabled v4 still acting: %d", w.Code)
	}
	if w := post(v3, "/api/users/v3@offpatch.local/set_role", map[string]string{"role": "admin"}); w.Code != 409 {
		t.Fatalf("last super admin demotes self: %d", w.Code)
	}
	// User management audit: never passwords.
	all, _ := s.store.ListAudit(context.Background(), store.AuditQuery{Limit: 5000})
	b, _ := json.Marshal(all)
	if strings.Contains(string(b), temp) || strings.Contains(string(b), testPW) || strings.Contains(string(b), "pbkdf2") {
		t.Fatal("password or hash in the audit trail")
	}
}
