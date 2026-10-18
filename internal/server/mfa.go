package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"offpatch/internal/store"
)

// Authenticator-app MFA for local users (store/mfa.go): the second sign-in
// step, enrolment and the super admin's opt-out. docs/05-api.md "MFA".

const (
	mfaCookie       = "offpatch_mfa"
	mfaPreAuthFor   = 5 * time.Minute
	mfaEnrollNeeded = "mfa_enrollment_required"
)

// mfaEnrollExempt: what a session limited to MFA enrolment may call.
var mfaEnrollExempt = map[string]bool{"/api/me": true, "/api/auth/mfa/enroll/start": true, "/api/auth/mfa/enroll/confirm": true,
	"/api/auth/logout": true, "/api/auth/password": true}

// loadMFAKey reads the 32-byte key (64 hex characters) that encrypts MFA
// secrets, creating it (0600) on first start.
func loadMFAKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create MFA key %s: %w", path, err)
		}
		_, werr := f.WriteString(hex.EncodeToString(k) + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		return k, werr
	}
	if err != nil {
		return nil, fmt.Errorf("MFA key %s: %w", path, err)
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("MFA key %s: want 64 hex characters (32 bytes)", path)
	}
	return k, nil
}

type mfaPreAuth struct {
	Email string `json:"e"`
	Exp   int64  `json:"x"`
	Nonce string `json:"n"`
}

// setMFAPreAuth: the password was right; the signed cookie lets the
// browser finish with a code within mfaPreAuthFor.
func (s *Server) setMFAPreAuth(w http.ResponseWriter, r *http.Request, email string) {
	n := make([]byte, 12)
	rand.Read(n)
	b, _ := json.Marshal(mfaPreAuth{Email: email, Exp: time.Now().Add(mfaPreAuthFor).Unix(), Nonce: hex.EncodeToString(n)})
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: s.sign(b), Path: "/api/auth/mfa", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteStrictMode, MaxAge: int(mfaPreAuthFor.Seconds())})
}

func clearMFAPreAuth(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: mfaCookie, Value: "", Path: "/api/auth/mfa", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

// mfaLogin: POST /api/auth/mfa {code} or {recovery_code} with the pre-auth
// cookie from POST /api/auth/login → session cookie.
func (s *Server) mfaLogin(w http.ResponseWriter, r *http.Request) {
	if s.loginLimited(w, r) {
		return
	}
	if r.Header.Get(csrfHeader) != "1" {
		writeErr(w, http.StatusForbidden, "missing "+csrfHeader+" header")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, loginMaxBody)
	var body struct {
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !decode(w, r, &body) {
		return
	}
	c, err := r.Cookie(mfaCookie)
	var pa mfaPreAuth
	if err == nil {
		raw, ok := s.unsign(c.Value)
		if !ok || json.Unmarshal(raw, &pa) != nil {
			err = errors.New("bad")
		}
	}
	if err != nil || pa.Email == "" || time.Now().Unix() > pa.Exp {
		clearMFAPreAuth(w, r)
		writeErr(w, http.StatusUnauthorized, "sign-in expired; enter your email and password again")
		return
	}
	res, err := s.store.LoginMFA(r.Context(), pa.Email, body.Code, body.RecoveryCode, s.cfg.SessionTTL.Duration)
	switch {
	case errors.Is(err, store.ErrBadMFACode):
		writeErr(w, http.StatusUnauthorized, "wrong or expired code")
		return
	case errors.Is(err, store.ErrDisabled):
		clearMFAPreAuth(w, r)
		writeErr(w, http.StatusForbidden, "your access has been disabled; ask an administrator")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	clearMFAPreAuth(w, r)
	s.setSessionCookie(w, r, res.Token)
	writeJSON(w, 200, map[string]any{"user": res.Email, "email": res.Email, "role": res.Role, "auth": "password",
		"must_change_password": res.MustChangePassword, "mfa": true})
}

func (s *Server) localPrincipal(w http.ResponseWriter, r *http.Request) (*principal, bool) {
	p := r.Context().Value(keyPrincipal).(*principal)
	if p.Source != "password" {
		writeErr(w, http.StatusConflict, "only local (email + password) users enrol an authenticator here; SSO users use their identity provider's MFA")
		return nil, false
	}
	return p, true
}

// mfaEnrollStart: POST /api/auth/mfa/enroll/start → {secret_base32, otpauth_uri}.
func (s *Server) mfaEnrollStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.localPrincipal(w, r)
	if !ok {
		return
	}
	v, err := s.store.MFAEnrollStart(r.Context(), p.User)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// mfaEnrollConfirm: POST /api/auth/mfa/enroll/confirm {code} →
// {recovery_codes} (shown once); the session becomes a full one.
func (s *Server) mfaEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	p, ok := s.localPrincipal(w, r)
	if !ok {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	codes, err := s.store.MFAEnrollConfirm(r.Context(), p.User, body.Code, c.Value)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "recovery_codes": codes})
}

// mfaDisable: POST /api/auth/mfa/disable {code}: a super admin removes
// their own authenticator (optional for that role).
func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request) {
	p, ok := s.localPrincipal(w, r)
	if !ok {
		return
	}
	if s.loginLimited(w, r) {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.store.DisableOwnMFA(r.Context(), p.User, p.Role, body.Code); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
