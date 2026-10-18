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
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/repo"
	"offpatch/internal/store"
	"offpatch/internal/totp"
)

func init() { store.PasswordIterations = 1000 } // fast tests

// roleTokens: one signed-in local user per role. The values are keys: do
// sends the session of that user (testSessions, filled by
// newRolesServer); any other token value goes out as a bearer token
// (refused: static admin tokens were removed).
var roleTokens = map[string]string{"viewer": "t-viewer", "user": "t-user", "admin": "t-admin", "super_admin": "t-super"}

// testSessions maps a roleTokens value to the session of its user on the
// newest test server (server tests do not run in parallel).
var testSessions = map[string]string{}

// testSecrets: authenticator secrets of users enrolled by the helpers.
var testSecrets = map[string][]byte{}

// signIn signs a local user in through the store and, when MFA is required
// and not enrolled yet, enrols an authenticator: a full session.
func signIn(t *testing.T, st *store.Store, email, pw string) string {
	t.Helper()
	ctx := context.Background()
	l, err := st.LoginPassword(ctx, email, pw, time.Hour)
	if err != nil {
		t.Fatalf("sign in %s: %v", email, err)
	}
	if l.MFAPending {
		sec := testSecrets[email]
		if l, err = st.LoginMFA(ctx, email, totp.Code(sec, st.Now().Add(totp.Period*time.Second)), "", time.Hour); err != nil {
			t.Fatalf("mfa %s: %v", email, err)
		}
	}
	if l.MFAEnrollment {
		en, err := st.MFAEnrollStart(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		sec, _ := totp.DecodeSecret(en.SecretBase32)
		testSecrets[email] = sec
		if _, err := st.MFAEnrollConfirm(ctx, email, totp.Code(sec, st.Now()), l.Token); err != nil {
			t.Fatalf("enrol %s: %v", email, err)
		}
	}
	return l.Token
}

// newRolesServer: a lab server with one signed-in local user per role in
// roleTokens (unless noUsers), extra spliced into the config.
func newRolesServer(t *testing.T, extra string, noUsers bool) *Server {
	t.Helper()
	dir := t.TempDir()
	pub, _, _ := manifest.GenerateKey()
	cfg := fmt.Sprintf(`{"insecure_http": true, %s "data_dir": "data", "trusted_keys":[{"public_key": %q, "sources":["s"]}]}`,
		extra, manifest.EncodePublic(pub))
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
	testSessions = map[string]string{}
	if !noUsers {
		for role, tok := range roleTokens {
			email := strings.ReplaceAll(role, "_", "-") + "@roles.test"
			mkLocal(t, s, email, role, false)
			testSessions[tok] = signIn(t, st, email, testPW)
		}
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
	if sess, ok := testSessions[q.token]; ok {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess})
		if q.method != "GET" && q.method != "HEAD" {
			r.Header.Set(csrfHeader, "1")
		}
	} else if q.token != "" {
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
		{"POST", "/api/users/someone@bank.example/reset_mfa", "admin"},
		{"POST", "/api/users/someone@bank.example/delete", "admin"},
		{"GET", "/api/exceptions", "viewer"},
		{"GET", "/api/bundles", "user"},
		{"GET", "/api/bundles/1", "user"},
		{"GET", "/api/transfer/reconcile", "user"},
		{"GET", "/api/acquisition", "user"},
		{"GET", "/api/acquisition-requests", "user"},
		{"GET", "/api/library", "super_admin"},
		{"GET", "/api/library/app/google.chrome", "super_admin"},
		{"GET", "/api/updates", "viewer"},
		{"GET", "/api/packages", "viewer"},
		{"POST", "/api/auth/mfa/disable", "super_admin"},
	}
	// Reports, the audit trail and the server-made PDFs: every signed-in role.
	for _, path := range []string{
		"/api/reports/compliance", "/api/reports/compliance.csv", "/api/reports/endpoints.csv", "/api/reports/targets.csv",
		"/api/reports/compliance-pack", "/api/reports/compliance-pack.zip", "/api/reports/compliance-pack.pdf", "/api/reports/compliance.pdf",
		"/api/reports/profile/history", "/api/audit", "/api/audit/verify", "/api/audit/export?package_id=p-1", "/api/audit.pdf",
	} {
		routes = append(routes, struct{ method, path, min string }{"GET", path, "viewer"})
	}
	for _, rt := range routes {
		min, refusal := rt.min, "requires role "+rt.min
		for role, tok := range roleTokens {
			w := do(h, req{method: rt.method, path: rt.path, body: map[string]any{}, token: tok})
			allowed := store.RoleRank(role) >= store.RoleRank(min)
			if allowed && (w.Code == 401 || (w.Code == 403 && strings.HasPrefix(errBody(w), "requires role"))) {
				t.Errorf("%s %s as %s: refused (%d %s), min role %s", rt.method, rt.path, role, w.Code, w.Body, min)
			}
			if !allowed && (w.Code != 403 || errBody(w) != refusal) {
				t.Errorf("%s %s as %s: want 403 %q, got %d %s", rt.method, rt.path, role, refusal, w.Code, w.Body)
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
	w := do(h, req{method: "GET", path: "/api/me", token: roleTokens["user"]})
	var me map[string]any
	json.Unmarshal(w.Body.Bytes(), &me)
	if w.Code != 200 || me["role"] != "user" || me["auth"] != "password" || me["user"] != "user@roles.test" || me["must_change_password"] != false ||
		me["mfa_enrolled"] != true || me["mfa_required"] != true || me["mfa"] != true {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	json.Unmarshal(do(h, req{method: "GET", path: "/api/me", token: roleTokens["super_admin"]}).Body.Bytes(), &me)
	if me["mfa_required"] != false || me["mfa_enrolled"] != false {
		t.Fatalf("super admin me: %v", me)
	}
	var pol map[string]any
	json.Unmarshal(do(h, req{method: "GET", path: "/api/policy", token: roleTokens["viewer"]}).Body.Bytes(), &pol)
	if pol["deployment_approvals"] != float64(3) {
		t.Fatalf("policy: %v", pol)
	}
	// The console's /login is the SPA.
	if w := do(h, req{method: "GET", path: "/login"}); w.Code != 200 || !strings.Contains(w.Body.String(), "console") {
		t.Fatalf("/login: %d", w.Code)
	}
	var ac map[string]any
	json.Unmarshal(do(h, req{method: "GET", path: "/auth/config"}).Body.Bytes(), &ac)
	if _, has := ac["static_tokens"]; ac["password_login"] != true || has {
		t.Fatalf("auth config: %v", ac)
	}
	// Logout without a session: nothing to end, still 200.
	if w := do(h, req{method: "POST", path: "/api/auth/logout", csrf: true}); w.Code != 200 {
		t.Fatalf("logout without a session: %d", w.Code)
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
}

const testPW = "a long enough password"

func mkLocal(t *testing.T, s *Server, email, role string, mustChange bool) {
	t.Helper()
	if _, err := s.store.CreateLocalUser(context.Background(), store.Manager{Actor: "system:test", Role: store.RoleSuperAdmin},
		store.NewLocalUser{Email: email, Role: role, Password: testPW}, mustChange); err != nil {
		t.Fatal(err)
	}
}

// login signs in over HTTP (email + password, then the authenticator code
// when one is enrolled; enrols one when MFA is required and the password
// is not temporary) and returns the session cookie.
func login(t *testing.T, h http.Handler, email, pw string) *http.Cookie {
	t.Helper()
	ip := fmt.Sprintf("198.51.100.%d", len(email)%200+1)
	w := do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": email, "password": pw}, csrf: true, ip: ip})
	if w.Code != 200 {
		t.Fatalf("login %s: %d %s", email, w.Code, w.Body)
	}
	var res map[string]any
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["mfa_required"] == true {
		pre := cookieNamed(w, mfaCookie)
		code := totp.Code(testSecrets[email], time.Now().Add(totp.Period*time.Second))
		w = do(h, req{method: "POST", path: "/api/auth/mfa", body: map[string]string{"code": code}, cookie: pre, csrf: true, ip: ip})
		if w.Code != 200 {
			t.Fatalf("mfa %s: %d %s", email, w.Code, w.Body)
		}
	}
	ck := cookieNamed(w, sessionCookie)
	if ck == nil {
		t.Fatal("no session cookie")
	}
	if res["mfa_enrollment_required"] == true && res["must_change_password"] != true {
		enrolHTTP(t, h, email, ck, ip)
	}
	return ck
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

// enrolHTTP enrols an authenticator with the session cookie ck and returns
// the recovery codes.
func enrolHTTP(t *testing.T, h http.Handler, email string, ck *http.Cookie, ip string) []string {
	t.Helper()
	w := do(h, req{method: "POST", path: "/api/auth/mfa/enroll/start", body: map[string]any{}, cookie: ck, csrf: true, ip: ip})
	var en store.MFAEnrollment
	json.Unmarshal(w.Body.Bytes(), &en)
	if w.Code != 200 || en.SecretBase32 == "" || !strings.HasPrefix(en.OTPAuthURI, "otpauth://totp/DSS%20Patcher:") {
		t.Fatalf("enroll start %s: %d %s", email, w.Code, w.Body)
	}
	sec, _ := totp.DecodeSecret(en.SecretBase32)
	testSecrets[email] = sec
	w = do(h, req{method: "POST", path: "/api/auth/mfa/enroll/confirm", body: map[string]string{"code": totp.Code(sec, time.Now())}, cookie: ck, csrf: true, ip: ip})
	var res struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || len(res.RecoveryCodes) != store.RecoveryCodes {
		t.Fatalf("enroll confirm %s: %d %s", email, w.Code, w.Body)
	}
	return res.RecoveryCodes
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
	// Bank role, no authenticator yet: enrolment only.
	if w := do(h, req{method: "GET", path: "/api/summary", cookie: ck}); w.Code != 403 || errBody(w) != "mfa_enrollment_required" {
		t.Fatalf("after change, before MFA enrolment: %d %s", w.Code, w.Body)
	}
	enrolHTTP(t, h, "uma@bank.example", ck, "192.0.2.1")
	if w := do(h, req{method: "GET", path: "/api/summary", cookie: ck}); w.Code != 200 {
		t.Fatalf("after change and enrolment: %d %s", w.Code, w.Body)
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

// require_mfa (SSO setting) also makes the authenticator required for
// local super admins; password sign-in itself stays available.
func TestRequireMFAIncludesSuperAdmins(t *testing.T) {
	oidcCfg := `"oidc": {"issuer": "https://idp.corp", "client_id": "pm", "redirect_url": "https://pm/auth/callback"}, "require_mfa": true,`
	s := newRolesServer(t, oidcCfg, true)
	mkLocal(t, s, "vendor@dataspacesecurity.test", "super_admin", false)
	w := do(s.Handler(), req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "vendor@dataspacesecurity.test", "password": testPW}, csrf: true})
	var res map[string]any
	json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res["mfa_enrollment_required"] != true {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	ck := cookieNamed(w, sessionCookie)
	if w := do(s.Handler(), req{method: "GET", path: "/api/summary", cookie: ck}); w.Code != 403 || errBody(w) != "mfa_enrollment_required" {
		t.Fatalf("before enrolment: %d %s", w.Code, w.Body)
	}
	enrolHTTP(t, s.Handler(), "vendor@dataspacesecurity.test", ck, "192.0.2.1")
	if w := do(s.Handler(), req{method: "GET", path: "/api/summary", cookie: ck}); w.Code != 200 {
		t.Fatalf("after enrolment: %d %s", w.Code, w.Body)
	}
}

func TestUserManagementAPI(t *testing.T) {
	s := newRolesServer(t, "", true) // no tokens: local users only
	h := s.Handler()
	mkLocal(t, s, "vendor@dataspacesecurity.test", "super_admin", false)
	mkLocal(t, s, "adam@bank.example", "admin", false)
	sup := login(t, h, "vendor@dataspacesecurity.test", testPW)
	adm := login(t, h, "adam@bank.example", testPW)
	post := func(ck *http.Cookie, path string, body any) *httptest.ResponseRecorder {
		return do(h, req{method: "POST", path: path, body: body, cookie: ck, csrf: true})
	}
	// Admin: bank roles only.
	if w := post(adm, "/api/users", map[string]string{"email": "v2@dataspacesecurity.test", "role": "super_admin", "password": "temporary password 1"}); w.Code != 403 {
		t.Fatalf("admin creates super admin: %d %s", w.Code, w.Body)
	}
	if w := post(adm, "/api/users/vendor@dataspacesecurity.test/disable", map[string]string{"reason": "x"}); w.Code != 403 {
		t.Fatalf("admin disables super admin: %d %s", w.Code, w.Body)
	}
	if w := post(adm, "/api/users/vendor@dataspacesecurity.test/reset_password", map[string]string{}); w.Code != 403 {
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
	if w := post(sup, "/api/users/vendor@dataspacesecurity.test/disable", map[string]string{"reason": "x"}); w.Code != 409 {
		t.Fatalf("super admin disables self: %d", w.Code)
	}
	if w := post(sup, "/api/users", map[string]string{"email": "v2@dataspacesecurity.test", "role": "super_admin", "password": "temporary password 1"}); w.Code != 201 {
		t.Fatalf("super admin creates super admin: %d %s", w.Code, w.Body)
	}
	if w := post(sup, "/api/users/v2@dataspacesecurity.test/set_role", map[string]string{"role": "admin"}); w.Code != 200 {
		t.Fatalf("demote second super admin: %d %s", w.Code, w.Body)
	}
	mkLocal(t, s, "v3@dataspacesecurity.test", "super_admin", false)
	v3 := login(t, h, "v3@dataspacesecurity.test", testPW)
	if w := post(v3, "/api/users/vendor@dataspacesecurity.test/disable", map[string]string{"reason": "rotate"}); w.Code != 200 {
		t.Fatalf("disable one of two: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/api/me", cookie: sup}); w.Code != 401 {
		t.Fatalf("disabled super admin still signed in: %d", w.Code)
	}
	mkLocal(t, s, "v4@dataspacesecurity.test", "super_admin", false)
	v4 := login(t, h, "v4@dataspacesecurity.test", testPW)
	post(v3, "/api/users/v4@dataspacesecurity.test/disable", map[string]string{"reason": "x"})
	if w := post(v4, "/api/users/v3@dataspacesecurity.test/disable", map[string]string{"reason": "x"}); w.Code != 401 {
		t.Fatalf("disabled v4 still acting: %d", w.Code)
	}
	if w := post(v3, "/api/users/v3@dataspacesecurity.test/set_role", map[string]string{"role": "admin"}); w.Code != 409 {
		t.Fatalf("last super admin demotes self: %d", w.Code)
	}
	// User management audit: never passwords.
	all, _ := s.store.ListAudit(context.Background(), store.AuditQuery{Limit: 5000})
	b, _ := json.Marshal(all)
	if strings.Contains(string(b), temp) || strings.Contains(string(b), testPW) || strings.Contains(string(b), "pbkdf2") {
		t.Fatal("password or hash in the audit trail")
	}
}

// /api/summary and /api/system carry their audit block for every role.
func TestAuditBlockEveryRole(t *testing.T) {
	s := newRolesServer(t, "", false)
	h := s.Handler()
	for _, path := range []string{"/api/summary", "/api/system"} {
		for role, tok := range roleTokens {
			w := do(h, req{method: "GET", path: path, token: tok})
			var v map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &v); w.Code != 200 || err != nil {
				t.Fatalf("%s as %s: %d %v", path, role, w.Code, err)
			}
			_, has := v["audit"]
			if !has {
				t.Errorf("%s as %s: no audit block", path, role)
			}
			if _, ok := v["endpoints"]; path == "/api/summary" && !ok {
				t.Errorf("%s as %s: summary lost its endpoints block", path, role)
			}
		}
	}
}
