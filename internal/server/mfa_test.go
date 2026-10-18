package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"offpatch/internal/store"
	"offpatch/internal/totp"
)

// The sign-in with an authenticator over HTTP: password → mfa_required and
// a pre-auth cookie → /api/auth/mfa with a code (each once) or a recovery
// code → session. Reset and delete by an admin.
func TestMFASignInAPI(t *testing.T) {
	s := newRolesServer(t, "", true)
	h := s.Handler()
	mkLocal(t, s, "adam@bank.example", "admin", false)
	mkLocal(t, s, "vera@bank.example", "viewer", false)
	adm := login(t, h, "adam@bank.example", testPW)

	// Viewer: MFA required too; enrol with the enrolment-only session.
	w := do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "vera@bank.example", "password": testPW}, csrf: true, ip: "203.0.113.50"})
	var res map[string]any
	json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res["mfa_enrollment_required"] != true {
		t.Fatalf("viewer login: %d %s", w.Code, w.Body)
	}
	ck := cookieNamed(w, sessionCookie)
	var me map[string]any
	json.Unmarshal(do(h, req{method: "GET", path: "/api/me", cookie: ck}).Body.Bytes(), &me)
	if me["mfa_required"] != true || me["mfa_enrolled"] != false {
		t.Fatalf("me before enrolment: %v", me)
	}
	codes := enrolHTTP(t, h, "vera@bank.example", ck, "203.0.113.50")
	if w := do(h, req{method: "POST", path: "/api/auth/mfa/enroll/start", body: map[string]any{}, cookie: ck, csrf: true}); w.Code != 409 {
		t.Fatalf("second enrolment: %d", w.Code)
	}
	// Next sign-in: two steps.
	w = do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "vera@bank.example", "password": testPW}, csrf: true, ip: "203.0.113.51"})
	json.Unmarshal(w.Body.Bytes(), &res)
	pre := cookieNamed(w, mfaCookie)
	if w.Code != 200 || res["mfa_required"] != true || cookieNamed(w, sessionCookie) != nil || pre == nil || !pre.HttpOnly || pre.Path != "/api/auth/mfa" {
		t.Fatalf("password step: %d %s %+v", w.Code, w.Body, pre)
	}
	mfa := func(body map[string]string, c *http.Cookie) *httptest.ResponseRecorder {
		return do(h, req{method: "POST", path: "/api/auth/mfa", body: body, cookie: c, csrf: true, ip: "203.0.113.52"})
	}
	if w := mfa(map[string]string{"code": "000000"}, nil); w.Code != 401 || !strings.Contains(errBody(w), "sign-in expired") {
		t.Fatalf("no pre-auth cookie: %d %s", w.Code, w.Body)
	}
	forged := &http.Cookie{Name: mfaCookie, Value: "eyJlIjoidmVyYUBiYW5rLmV4YW1wbGUifQ.AAAA"}
	if w := mfa(map[string]string{"code": "000000"}, forged); w.Code != 401 {
		t.Fatalf("forged pre-auth cookie: %d", w.Code)
	}
	sec := testSecrets["vera@bank.example"]
	if w := mfa(map[string]string{"code": totp.Code(sec, time.Now())}, pre); w.Code != 401 || errBody(w) != "wrong or expired code" {
		t.Fatalf("replayed enrolment code: %d %s", w.Code, w.Body)
	}
	code := totp.Code(sec, time.Now().Add(30*time.Second))
	w = mfa(map[string]string{"code": code}, pre)
	if w.Code != 200 || cookieNamed(w, sessionCookie) == nil {
		t.Fatalf("code: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/api/summary", cookie: cookieNamed(w, sessionCookie)}); w.Code != 200 {
		t.Fatalf("after MFA: %d", w.Code)
	}
	if w := mfa(map[string]string{"code": code}, pre); w.Code != 401 {
		t.Fatalf("replayed code: %d", w.Code)
	}
	if w := mfa(map[string]string{"recovery_code": codes[0]}, pre); w.Code != 200 {
		t.Fatalf("recovery code: %d %s", w.Code, w.Body)
	}
	if w := mfa(map[string]string{"recovery_code": codes[0]}, pre); w.Code != 401 {
		t.Fatalf("recovery code reused: %d", w.Code)
	}
	// Users list shows enrolment; admin resets it; the user enrols again.
	var us []store.User
	json.Unmarshal(do(h, req{method: "GET", path: "/api/users", cookie: adm}).Body.Bytes(), &us)
	for _, u := range us {
		if u.Username == "vera@bank.example" && !u.MFAEnrolled {
			t.Fatalf("users list: %+v", u)
		}
	}
	post := func(path string) *httptest.ResponseRecorder {
		return do(h, req{method: "POST", path: path, body: map[string]string{"reason": "lost phone"}, cookie: adm, csrf: true})
	}
	if w := post("/api/users/vera@bank.example/reset_mfa"); w.Code != 200 {
		t.Fatalf("reset_mfa: %d %s", w.Code, w.Body)
	}
	w = do(h, req{method: "POST", path: "/api/auth/login", body: map[string]string{"email": "vera@bank.example", "password": testPW}, csrf: true, ip: "203.0.113.53"})
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["mfa_enrollment_required"] != true {
		t.Fatalf("after reset: %s", w.Body)
	}
	// Delete: gone, sessions end; not yourself.
	vck := cookieNamed(w, sessionCookie)
	if w := post("/api/users/adam@bank.example/delete"); w.Code != 409 {
		t.Fatalf("delete self: %d", w.Code)
	}
	if w := post("/api/users/vera@bank.example/delete"); w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if w := do(h, req{method: "GET", path: "/api/me", cookie: vck}); w.Code != 401 {
		t.Fatalf("deleted user's session: %d", w.Code)
	}
	// Super admin: MFA optional, may switch it off for themselves only.
	mkLocal(t, s, "vendor@dataspacesecurity.test", "super_admin", false)
	sup := login(t, h, "vendor@dataspacesecurity.test", testPW)
	enrolHTTP(t, h, "vendor@dataspacesecurity.test", sup, "203.0.113.54")
	if w := do(h, req{method: "POST", path: "/api/auth/mfa/disable", body: map[string]string{"code": "1"}, cookie: adm, csrf: true}); w.Code != 403 {
		t.Fatalf("admin disables MFA: %d", w.Code)
	}
	if w := do(h, req{method: "POST", path: "/api/auth/mfa/disable", body: map[string]string{"code": totp.Code(testSecrets["vendor@dataspacesecurity.test"], time.Now().Add(30*time.Second))}, cookie: sup, csrf: true}); w.Code != 200 {
		t.Fatalf("super admin disables own MFA: %d %s", w.Code, w.Body)
	}
}

// The MFA key is created 0600 on first start and reused afterwards.
func TestMFAKeyFile(t *testing.T) {
	p := t.TempDir() + "/keys/mfa.key"
	k1, err := loadMFAKey(p)
	if err != nil || len(k1) != 32 {
		t.Fatal(err)
	}
	k2, err := loadMFAKey(p)
	if err != nil || string(k1) != string(k2) {
		t.Fatal("key not reused")
	}
	os.WriteFile(p, []byte("short"), 0o600)
	if _, err := loadMFAKey(p); err == nil {
		t.Fatal("bad key accepted")
	}
}
