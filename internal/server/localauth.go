package server

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"offpatch/internal/store"
)

// Local users: email + password sign-in, forced password change, and user
// management (docs/05-api.md "Users"). The store enforces the role limits;
// this layer adds the per-IP sign-in limit, the cookie and HTTP mapping.

const (
	// loginBurst attempts per client IP, then one more every loginEvery.
	// Applies before any password work. Unlike enrollment, loopback is not
	// exempt: a local attacker should not get unlimited guesses either.
	loginBurst = 10
	loginEvery = 6 * time.Second
	// loginMaxBody bounds an unauthenticated sign-in request.
	loginMaxBody = 8 << 10

	passwordChangeRequired = "password_change_required"
	badCredentials         = "wrong email or password"
)

// passwordChangeExempt: what a user with a temporary password may call.
var passwordChangeExempt = map[string]bool{"/api/me": true, "/api/auth/password": true, "/api/auth/logout": true}

// loginKey: the rate-limit bucket of a client address. IPv6 clients share
// one bucket per /64 (one host usually has a whole /64 to rotate through).
func loginKey(ip string) string {
	a := net.ParseIP(ip)
	if a == nil || a.To4() != nil {
		return ip
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// loginLimited applies the per-IP sign-in limit (429 with Retry-After).
// Through the console proxy proxyAuthLimited has already applied it.
func (s *Server) loginLimited(w http.ResponseWriter, r *http.Request) bool {
	if p := proxiedInfo(r); p != nil && p.loginCharged {
		return false
	}
	ip := clientIP(r)
	if ok, wait := s.loginLimit.allow(loginKey(ip)); !ok {
		s.log.Warn("sign-in rate limited", "ip", ip)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many sign-in attempts from this address; retry later")
		return true
	}
	return false
}

// passwordLogin: POST /api/auth/login {email, password, setup_code} →
// session cookie. One answer for unknown email, wrong password, locked
// account and (built-in account on the default password) a missing or
// wrong setup code: the store decides, store/setupcode.go.
func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request) {
	if s.loginLimited(w, r) {
		return
	}
	// Same CSRF rule as every cookie-authenticated change (no login CSRF).
	if r.Header.Get(csrfHeader) != "1" {
		writeErr(w, http.StatusForbidden, "missing "+csrfHeader+" header")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, loginMaxBody)
	var body struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		SetupCode string `json:"setup_code"`
	}
	if !decode(w, r, &body) {
		return
	}
	// Wrong passwords lock the account per client address (store
	// authlimits.go): the same key as the rate limit.
	res, err := s.store.LoginSetupCodeFrom(r.Context(), body.Email, body.Password, body.SetupCode, loginKey(clientIP(r)), s.cfg.SessionTTL.Duration)
	switch {
	case errors.Is(err, store.ErrBadCredentials):
		writeErr(w, http.StatusUnauthorized, badCredentials)
		return
	case errors.Is(err, store.ErrDisabled):
		writeErr(w, http.StatusForbidden, "your offpatch access has been disabled; ask an administrator")
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	if res.MFAPending {
		// Second step: POST /api/auth/mfa with a code within 5 minutes
		// (at most mfaPreAuthTries codes per password).
		if !s.setMFAPreAuth(w, r, res.Email) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusServiceUnavailable, "too many sign-ins in progress; try again in a minute")
			return
		}
		writeJSON(w, 200, map[string]any{"mfa_required": true, "email": res.Email})
		return
	}
	s.setSessionCookie(w, r, res.Token)
	writeJSON(w, 200, map[string]any{"user": res.Email, "email": res.Email, "role": res.Role, "auth": "password",
		"must_change_password": res.MustChangePassword, "mfa_required": false, "mfa_enrollment_required": res.MFAEnrollment})
}

// changePassword: POST /api/auth/password {current, new} (local users).
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(keyPrincipal).(*principal)
	if p.Source != "password" {
		writeErr(w, http.StatusConflict, "only local (email + password) users change their password here")
		return
	}
	if s.loginLimited(w, r) {
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	if err := s.store.ChangeOwnPassword(r.Context(), p.User, body.Current, body.New, c.Value); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) manager(r *http.Request) store.Manager {
	return store.Manager{Actor: actor(r), Role: r.Context().Value(keyPrincipal).(*principal).Role}
}

// userFail maps store errors; refusals by role are audited as access.denied.
func (s *Server) userFail(w http.ResponseWriter, r *http.Request, target string, err error) {
	if errors.Is(err, store.ErrForbidden) {
		p := r.Context().Value(keyPrincipal).(*principal)
		s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "access.denied", ObjectType: "user", ObjectID: target, Failure: true,
			Details: map[string]any{"role": p.Role, "api": r.Method + " " + r.URL.Path, "reason": err.Error()}})
	}
	s.fail(w, err)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// createUser: POST /api/users {email, display_name, role, password}. The
// password is temporary (the user must change it at first sign-in); when
// empty, one is generated and returned once as temp_password.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var n store.NewLocalUser
	if !decode(w, r, &n) {
		return
	}
	temp := ""
	if n.Password == "" {
		temp = store.GeneratePassword()
		n.Password = temp
	}
	u, err := s.store.CreateLocalUser(r.Context(), s.manager(r), n, true)
	if err != nil {
		s.userFail(w, r, n.Email, err)
		return
	}
	resp := map[string]any{"email": u.Email, "username": u.Email, "display_name": u.DisplayName, "role": u.Role,
		"must_change_password": u.MustChangePassword, "source": "local", "auth": "password"}
	if temp != "" {
		resp["temp_password"] = temp
	}
	writeJSON(w, 201, resp)
}

// userAction: POST /api/users/{name}/{disable|enable|reset_password|set_role}
// with {reason, role (set_role), password (reset_password; generated and
// returned once as temp_password when empty)}.
func (s *Server) userAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason   string `json:"reason"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	ctx, by, name := r.Context(), s.manager(r), r.PathValue("name")
	resp := map[string]any{"ok": true}
	var err error
	switch r.PathValue("action") {
	case "disable", "enable":
		err = s.store.SetUserDisabled(ctx, by, name, r.PathValue("action") == "disable", body.Reason)
	case "reset_password":
		pw := body.Password
		if pw == "" {
			pw = store.GeneratePassword()
			resp["temp_password"] = pw
		}
		err = s.store.ResetLocalPassword(ctx, by, name, pw, body.Reason)
	case "set_role":
		err = s.store.SetLocalUserRole(ctx, by, name, body.Role, body.Reason)
	case "reset_mfa":
		err = s.store.ResetMFA(ctx, by, name, body.Reason)
	case "delete":
		err = s.store.DeleteLocalUser(ctx, by, name, body.Reason)
	default:
		writeErr(w, 404, "unknown action")
		return
	}
	if err != nil {
		s.userFail(w, r, name, err)
		return
	}
	writeJSON(w, 200, resp)
}
