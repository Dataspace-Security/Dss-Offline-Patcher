package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"offpatch/internal/oidc"
	"offpatch/internal/store"
)

const (
	sessionCookie = "offpatch_session"
	stateCookie   = "offpatch_login"
	csrfHeader    = "X-Offpatch-CSRF"
)

// authState holds lazily-initialised SSO state (the IdP may be briefly
// unreachable at startup; discovery is retried on the next login).
type authState struct {
	mu       sync.Mutex
	provider *oidc.Provider
	hmacKey  []byte
}

func newAuthState() *authState {
	k := make([]byte, 32)
	rand.Read(k)
	return &authState{hmacKey: k}
}

func (s *Server) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	if s.cfg.OIDC == nil {
		return nil, errors.New("single sign-on is not configured")
	}
	s.auth.mu.Lock()
	defer s.auth.mu.Unlock()
	if s.auth.provider != nil {
		return s.auth.provider, nil
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if f := s.cfg.OIDC.CACertFile; f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		pool.AppendCertsFromPEM(pem)
		tr.TLSClientConfig.RootCAs = pool
	}
	hc := &http.Client{Timeout: 15 * time.Second, Transport: tr}
	p, err := oidc.New(ctx, *s.cfg.OIDC, hc)
	if err != nil {
		return nil, err
	}
	s.auth.provider = p
	return p, nil
}

func (s *Server) sign(b []byte) string {
	m := hmac.New(sha256.New, s.auth.hmacKey)
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) unsign(v string) ([]byte, bool) {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return nil, false
	}
	b, err1 := base64.RawURLEncoding.DecodeString(v[:i])
	mac, err2 := base64.RawURLEncoding.DecodeString(v[i+1:])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	m := hmac.New(sha256.New, s.auth.hmacKey)
	m.Write(b)
	return b, hmac.Equal(mac, m.Sum(nil))
}

func safeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "\\") {
		return "/"
	}
	return p
}

func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"sso":           s.cfg.OIDC != nil,
		"static_tokens": *s.cfg.AllowStaticTokens && len(s.cfg.AdminTokens) > 0,
		"require_mfa":   s.cfg.RequireMFA,
		// Email + password sign-in for local users (not when MFA is required:
		// a password alone is one factor).
		"password_login": !s.cfg.RequireMFA,
	})
}

func (s *Server) loginFail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?login_error="+url.QueryEscape(msg), http.StatusFound)
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	p, err := s.oidcProvider(r.Context())
	if err != nil {
		s.log.Error("oidc", "err", err)
		s.loginFail(w, r, "Single sign-on is unavailable: "+err.Error())
		return
	}
	u, ls := p.AuthURL(safeReturn(r.URL.Query().Get("return")))
	b, _ := json.Marshal(ls)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: s.sign(b), Path: "/auth/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, err := r.Cookie(stateCookie)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth/", MaxAge: -1})
	if err != nil {
		s.loginFail(w, r, "Login session expired; please try again.")
		return
	}
	raw, ok := s.unsign(c.Value)
	var ls oidc.LoginState
	if !ok || json.Unmarshal(raw, &ls) != nil || time.Now().Unix() > ls.Expires {
		s.loginFail(w, r, "Login session invalid or expired; please try again.")
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(ls.State)) != 1 {
		s.loginFail(w, r, "Login state mismatch; please try again.")
		return
	}
	if e := q.Get("error"); e != "" {
		s.loginFail(w, r, "Identity provider: "+e+" "+q.Get("error_description"))
		return
	}
	p, err := s.oidcProvider(ctx)
	if err != nil {
		s.loginFail(w, r, "Single sign-on is unavailable.")
		return
	}
	id, err := p.Exchange(ctx, q.Get("code"), ls)
	if err != nil {
		s.log.Warn("oidc exchange failed", "err", err)
		s.store.Audit(ctx, store.Ev{Actor: "system:auth", Action: "auth.login_denied", ObjectType: "user", ObjectID: "unknown", Failure: true,
			Details: map[string]any{"reason": err.Error()}})
		s.loginFail(w, r, "Sign-in could not be verified.")
		return
	}
	deny := func(reason string) {
		s.store.Audit(ctx, store.Ev{Actor: "user:" + id.Username, Action: "auth.login_denied", ObjectType: "user", ObjectID: id.Username, Failure: true,
			Details: map[string]any{"reason": reason, "groups": id.Groups}})
		s.loginFail(w, r, reason)
	}
	id.Role = store.CanonicalRole(id.Role)
	if id.Role == "" {
		deny("Your account is not in any offpatch role group. Ask an administrator for access.")
		return
	}
	if p.Config().RequireMFA && !id.MFA {
		deny("Multi-factor authentication is required. Sign in again using MFA.")
		return
	}
	tok, err := s.store.Login(ctx, id.Username, id.Role, id.Email, "oidc", id.MFA, s.cfg.SessionTTL.Duration)
	if errors.Is(err, store.ErrDisabled) {
		s.loginFail(w, r, "Your offpatch access has been disabled.")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		s.loginFail(w, r, "This name belongs to a local (email + password) user; SSO sign-in with it is refused. Ask an administrator.")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.setSessionCookie(w, r, tok)
	http.Redirect(w, r, safeReturn(ls.Return), http.StatusFound)
}

// setSessionCookie: the console session (SSO and local users alike).
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, tok string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.SessionTTL.Seconds())})
}

// authLogout ends the cookie session (SSO or local user). With a static
// token there is no session: nothing to end, 200 all the same.
func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if r.Header.Get(csrfHeader) != "1" { // no forced logout from another site
			writeErr(w, http.StatusForbidden, "missing "+csrfHeader+" header")
			return
		}
		s.store.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	resp := map[string]string{}
	if s.auth.provider != nil && s.auth.provider.EndSessionURL() != "" {
		resp["end_session_url"] = s.auth.provider.EndSessionURL()
	}
	writeJSON(w, 200, resp)
}

// principalFor authenticates an admin request by static bearer token
// (break-glass/automation, if allowed) or session cookie (SSO or local
// email + password user).
func (s *Server) principalFor(r *http.Request) (*principal, string) {
	if tok := bearer(r); tok != "" {
		if !*s.cfg.AllowStaticTokens {
			return nil, "static admin tokens are disabled; sign in to the console"
		}
		hash := store.HashSecret(tok)
		for _, t := range s.cfg.AdminTokens {
			if subtle.ConstantTimeCompare([]byte(hash), []byte(t.TokenSHA256)) == 1 {
				return &principal{User: t.User, Role: t.Role, Source: "token"}, ""
			}
		}
		return nil, "invalid admin token"
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, "not signed in"
	}
	ss, err := s.store.LookupSession(r.Context(), c.Value)
	if err != nil {
		return nil, "session expired; sign in again"
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != "1" {
		return nil, "missing " + csrfHeader + " header"
	}
	if s.cfg.RequireMFA && !ss.MFA {
		return nil, "multi-factor authentication required"
	}
	src := "sso"
	if ss.Source == "password" {
		src = "password"
	}
	return &principal{User: ss.Username, Role: ss.Role, Source: src, MFA: ss.MFA, MustChangePassword: ss.MustChangePassword}, ""
}
