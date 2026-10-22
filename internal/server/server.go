// Package server is the management-plane HTTP API (admin + agent) and the
// embedded console. See docs/05-api.md.
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"offpatch/internal/pki"
	"offpatch/internal/repo"
	"offpatch/internal/store"
)

type Server struct {
	cfg   *Config
	store *store.Store
	repo  *repo.Repo
	log   *slog.Logger
	ui    fs.FS
	th    store.Thresholds
	ca    *pki.CA // nil in insecure_http lab mode
	auth  *authState
	pub   *publicCert // public_tls; nil when not configured
	// publicConns: raw connections that were served the public certificate.
	publicConns sync.Map

	// Set by TLSConfig before serving: whether the CA is sent in the chain
	// (needed to pin it) and the names/IPs the server certificate covers.
	caInChain bool
	certHosts []string

	intel    intelCache
	progress *progressMap
	// Derived fleet views, cached for fleetTTL while store.Generation is unchanged.
	needsCache genCache[needsView]
	refsCache  genCache[map[string]store.AcqRequestRef]
	lib        libCache // Library index, per intelligence generation

	enrollLimit *ipLimiter
	loginLimit  *ipLimiter // email + password sign-in, per client IP
	// proxyAuth: the listener-wide sign-in budget of the console_proxy
	// listener (forwarded client IPs can be forged by a local process),
	// with a reserved share for recently signed-in addresses; proxyauth.go.
	proxyAuth *proxyAuthGate
	preAuth   preAuthStore // MFA pre-auth nonces (single use, mfa.go)
	repKey    reportKey    // audit-signing key, for compliance packages
	polKey    reportKey    // policy signing key (acqpolicy_sign.go)
}

func New(cfg *Config, st *store.Store, rp *repo.Repo, ui fs.FS, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, store: st, repo: rp, ui: ui, log: log,
		th: store.Thresholds{OfflineAfter: cfg.OfflineAfter.Duration, StaleAfter: cfg.StaleInventoryAfter.Duration, LostAfterInstall: cfg.LostAfterInstall.Duration}}
	s.auth = newAuthState()
	s.progress = newProgressMap()
	s.enrollLimit = newIPLimiter(enrollBurst, enrollEvery)
	s.loginLimit = newIPLimiter(loginBurst, loginEvery)
	s.proxyAuth = newProxyAuthGate()
	store.WarmPasswordCheck()
	dl := map[string]time.Duration{}
	for k, v := range cfg.PatchDeadlines {
		dl[k] = v.Duration
	}
	st.Policy = store.Policy{ApprovalsRequired: cfg.ApprovalPolicy, SeparationOfDuties: cfg.SeparationOfDuties, Deadlines: dl,
		DeploymentApprovals: store.DefaultDeploymentApprovals}
	if cfg.DeploymentApprovals != nil {
		st.Policy.DeploymentApprovals = *cfg.DeploymentApprovals
	}
	st.Policy.RequireMFA = cfg.LocalMFARequired()
	st.Policy.RequireSetupCode = cfg.RequireSetupCode
	if cfg.MaxDownloadsTotal != nil {
		st.Policy.MaxDownloadsTotal = *cfg.MaxDownloadsTotal
	}
	if cfg.MaxDownloadsPerSite != nil {
		st.Policy.MaxDownloadsPerSite = *cfg.MaxDownloadsPerSite
	}
	st.Policy.SiteMaxDownloads = cfg.SiteMaxDownloads
	if err := st.ApplyDeploymentApprovalPolicy(context.Background()); err != nil {
		return nil, fmt.Errorf("apply deployment approval policy: %w", err)
	}
	st.AcqStaleAfter = cfg.AcquisitionStaleAfter.Duration
	if cfg.MFAKeyFile != "" {
		key, err := loadMFAKey(cfg.MFAKeyFile)
		if err != nil {
			return nil, err
		}
		if err := st.SetMFAKey(key); err != nil {
			return nil, err
		}
	}
	if cfg.PKIDir != "" {
		ca, err := pki.Load(cfg.PKIDir)
		if err != nil {
			return nil, fmt.Errorf("load PKI from %s: %w", cfg.PKIDir, err)
		}
		s.ca = ca
	}
	if cfg.PublicTLS != nil {
		s.pub = newPublicCert(cfg.PublicTLS, log)
	}
	cfg.LogAuthMode(log)
	return s, nil
}

// TLSConfig requests (but does not require) client certificates: browsers
// using the console present none; agents must present one (enforced in
// requireAgent).
//
// With the internal CA, the server certificate is served together with the CA
// certificate, so a client can pin the CA by fingerprint before it trusts it
// (the one-command endpoint install does this).
//
// With public_tls, connections asking for a public name (SNI) get the public
// certificate and no client-certificate request instead (publictls.go).
func (s *Server) TLSConfig() *tls.Config {
	cfg := s.withPublicTLS(s.internalTLSConfig())
	s.checkAgentURLCert()
	return cfg
}

func (s *Server) internalTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
	if s.ca == nil {
		return cfg
	}
	pool.AddCert(s.ca.Cert)
	if s.cfg.TLSCert == "" {
		return cfg
	}
	pair, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		s.log.Warn("could not load server certificate to add the CA to the chain", "err", err)
		return cfg
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		s.log.Warn("could not parse server certificate", "err", err)
		cfg.Certificates = []tls.Certificate{pair}
		return cfg
	}
	s.certHosts = append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		s.certHosts = append(s.certHosts, ip.String())
	}
	if leaf.CheckSignatureFrom(s.ca.Cert) == nil {
		s.caInChain = true
		if !slices.ContainsFunc(pair.Certificate[1:], func(c []byte) bool { return bytes.Equal(c, s.ca.Cert.Raw) }) {
			pair.Certificate = append(pair.Certificate, s.ca.Cert.Raw)
		}
	}
	cfg.Certificates = []tls.Certificate{pair}
	return cfg
}

// principal is who is calling: User is the name (the email for local
// users), Role canonical, Source token | sso | password.
type principal struct {
	User, Role, Source string
	MFA                bool
	// MustChangePassword: a local user with a temporary password; every
	// call except /api/me, password change and logout gets 403
	// password_change_required.
	MustChangePassword bool
	// MFAEnrollOnly: a local user who must enrol an authenticator first;
	// every call except mfaEnrollExempt gets 403 mfa_enrollment_required.
	MFAEnrollOnly bool
}

type ctxKey int

const (
	keyPrincipal ctxKey = iota
	keyEndpoint
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Permission table (docs/05-api.md "Roles"): viewer reads; user runs the
	// day-to-day work; admin also manages bank users, exceptions and
	// revocations; super_admin (vendor) everything. Each route names the
	// lowest role allowed; the console hides what a role cannot do, but this
	// table is the security boundary.
	admin := func(role, pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireAdmin(role, h)) }
	const viewer, user, adm = store.RoleViewer, store.RoleUser, store.RoleAdmin

	admin(viewer, "GET /api/me", s.me)
	admin(viewer, "GET /api/summary", s.summary)
	admin(viewer, "GET /api/dashboard/trend", s.dashboardTrend)
	// Imports (what was asked for, downloaded and received): user and up.
	admin(user, "GET /api/bundles", s.listBundles)
	admin(user, "GET /api/bundles/{id}", s.getBundle)
	admin(user, "GET /api/transfer/reconcile", s.reconcile)
	admin(viewer, "GET /api/system", s.system)
	admin(user, "GET /api/acquisition", s.acquisition)
	// Reports and the audit trail (incl. the server-made PDFs): every
	// signed-in role reads them; the report profile is edited by admins.
	admin(viewer, "GET /api/reports/compliance", s.complianceReport)
	admin(viewer, "GET /api/reports/compliance.csv", s.complianceCSV)
	admin(viewer, "GET /api/reports/endpoints.csv", s.endpointsCSV)
	admin(viewer, "GET /api/reports/targets.csv", s.targetsCSV)
	admin(viewer, "GET /api/reports/profile", s.getReportProfile)
	admin(adm, "PUT /api/reports/profile", s.putReportProfile)
	admin(viewer, "GET /api/reports/profile/history", s.reportProfileHistory)
	admin(viewer, "GET /api/reports/compliance-pack", s.compliancePack)
	admin(viewer, "GET /api/reports/compliance-pack.zip", s.compliancePackZip)
	admin(viewer, "GET /api/reports/compliance-pack.pdf", s.compliancePackPDF)
	admin(viewer, "GET /api/reports/compliance.pdf", s.compliancePDF)
	admin(viewer, "GET /api/audit", s.listAudit)
	admin(viewer, "GET /api/audit/verify", s.verifyAudit)
	admin(viewer, "GET /api/audit/export", s.exportLifecycle)
	admin(viewer, "GET /api/audit.pdf", s.auditPDF)
	admin(viewer, "GET /api/alerts", s.listAlerts)
	admin(user, "POST /api/alerts/{id}/ack", s.ackAlert)
	mux.HandleFunc("GET /metrics", s.metrics)
	admin(viewer, "GET /api/packages", s.listPackages)
	admin(viewer, "GET /api/packages/{id}", s.getPackage)
	admin(user, "POST /api/packages/{id}/{action}", s.packageAction) // approve | reject
	admin(adm, "POST /api/packages/{id}/revoke", s.packageAction)
	admin(viewer, "GET /api/endpoints", s.listEndpoints)
	admin(viewer, "GET /api/endpoints/{id}", s.getEndpoint)
	admin(viewer, "GET /api/endpoints/{id}/available", s.availableFor)
	admin(viewer, "GET /api/endpoints/{id}/updates", s.endpointUpdates)
	admin(viewer, "GET /api/updates", s.fleetUpdates)
	admin(viewer, "GET /api/intel", s.intelStatus)
	// The Library (everything that could be imported) is the vendor's tool.
	admin(store.RoleSuperAdmin, "GET /api/library", s.library)
	admin(store.RoleSuperAdmin, "GET /api/library/{kind}/{id}", s.libraryItem)
	admin(user, "POST /api/acquisition-requests", s.exportAcqRequest)
	// Auto-download policy: the vendor's (super admin) setting, read and write.
	admin(store.RoleSuperAdmin, "GET /api/acquisition/policy", s.getAcqPolicy)
	admin(store.RoleSuperAdmin, "PUT /api/acquisition/policy", s.putAcqPolicy)
	admin(store.RoleSuperAdmin, "GET /api/acquisition/policy/history", s.acqPolicyHistory)
	admin(store.RoleSuperAdmin, "GET /api/acquisition/policy/file", s.acqPolicyFile)
	admin(store.RoleSuperAdmin, "POST /api/acquisition/policy/queue", s.requeueAcqPolicy)
	// A source change needs a second super admin (S-4): approve or reject the pending one.
	admin(store.RoleSuperAdmin, "POST /api/acquisition/policy/pending/approve", s.approveAcqPolicy)
	admin(store.RoleSuperAdmin, "POST /api/acquisition/policy/pending/reject", s.rejectAcqPolicy)
	admin(store.RoleSuperAdmin, "POST /api/acquisition/run", s.runAcquisitionNow)
	admin(viewer, "GET /api/packages-needs", s.packageNeeds)
	admin(viewer, "GET /api/policy", s.policy)
	admin(viewer, "GET /api/fleet/status", s.fleetStatusHandler)
	admin(user, "GET /api/acquisition-requests", s.listAcqRequests)
	admin(user, "PATCH /api/endpoints/{id}", s.patchEndpoint)
	admin(user, "POST /api/endpoints/{id}/retire", s.retireEndpoint)
	admin(user, "POST /api/enrollment-tokens", s.createEnrollmentToken)
	admin(viewer, "GET /api/agent-setup", s.agentSetup)
	admin(viewer, "GET /api/agent-setup/files/{name}", s.agentSetupFile)
	admin(viewer, "GET /api/deployments", s.listDeployments)
	admin(user, "POST /api/deployments", s.createDeployment)
	admin(viewer, "GET /api/deployments/{id}", s.getDeployment)
	admin(user, "POST /api/deployments/{id}/{action}", s.deploymentAction) // pause | resume | cancel | advance
	admin(user, "POST /api/deployments/{id}/approve", s.approveDeployment)
	admin(user, "POST /api/deployments/{id}/reject", s.rejectDeployment)
	admin(user, "POST /api/deployments/{id}/retry_failed", s.retryFailed)
	admin(viewer, "GET /api/maintenance-windows", s.listWindows)
	admin(user, "POST /api/maintenance-windows", s.createWindow)
	admin(user, "POST /api/maintenance-windows/{id}/delete", s.deleteWindow)
	admin(viewer, "GET /api/exceptions", s.listExceptions)
	admin(adm, "POST /api/exceptions", s.createException)
	admin(adm, "POST /api/exceptions/{id}/revoke", s.revokeException)

	mux.HandleFunc("GET /auth/config", s.authConfig)
	mux.HandleFunc("GET /auth/login", s.authLogin)
	mux.HandleFunc("GET /auth/callback", s.authCallback)
	mux.HandleFunc("POST /auth/logout", s.authLogout)
	mux.HandleFunc("POST /api/auth/login", s.passwordLogin)
	mux.HandleFunc("POST /api/auth/logout", s.authLogout)
	admin(viewer, "POST /api/auth/password", s.changePassword)
	admin(adm, "GET /api/users", s.listUsers)
	admin(adm, "POST /api/users", s.createUser)
	admin(adm, "POST /api/users/{name}/{action}", s.userAction) // disable | enable | reset_password | set_role | reset_mfa | delete
	mux.HandleFunc("POST /api/auth/mfa", s.mfaLogin)
	admin(viewer, "POST /api/auth/mfa/enroll/start", s.mfaEnrollStart)
	admin(viewer, "POST /api/auth/mfa/enroll/confirm", s.mfaEnrollConfirm)
	admin(store.RoleSuperAdmin, "POST /api/auth/mfa/disable", s.mfaDisable)

	mux.HandleFunc("GET /api/agent-setup/bootstrap/windows.ps1", s.bootstrapWindows)
	mux.HandleFunc("GET /api/agent-setup/bootstrap/files/{name}", s.bootstrapFile)
	mux.HandleFunc("POST /api/agent/enroll", s.agentEnroll)
	mux.Handle("POST /api/agent/checkin", s.requireAgent(s.agentCheckin))
	mux.Handle("GET /api/agent/manifest/{id}", s.requireAgent(s.agentManifest))
	mux.Handle("GET /api/agent/content/{sha}", s.requireAgent(s.agentContent))
	mux.Handle("POST /api/agent/report", s.requireAgent(s.agentReport))
	mux.Handle("POST /api/agent/heartbeat", s.requireAgent(s.agentHeartbeat))
	mux.Handle("POST /api/agent/renew", s.requireAgent(s.agentRenew))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, http.StatusNotFound, "no such endpoint") })
	mux.Handle("/", s.spa())
	return securityHeaders(s.refusePublicAgent(mux))
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// spa serves the embedded console with index.html fallback.
func (s *Server) spa() http.Handler {
	files := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := s.ui.Open(p); err == nil {
				f.Close()
				files.ServeHTTP(w, r)
				return
			}
		}
		b, err := fs.ReadFile(s.ui, "index.html")
		if err != nil {
			http.Error(w, "console not built", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
}

// ---- auth ----

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// requireAdmin admits principals of at least role; anyone lower gets 403
// "requires role <role>" (audited as access.denied).
func (s *Server) requireAdmin(role string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, why := s.principalFor(r)
		if p == nil {
			writeErr(w, http.StatusUnauthorized, why)
			return
		}
		if p.MustChangePassword && !passwordChangeExempt[r.URL.Path] {
			writeErr(w, http.StatusForbidden, passwordChangeRequired)
			return
		}
		if p.MFAEnrollOnly && !mfaEnrollExempt[r.URL.Path] {
			writeErr(w, http.StatusForbidden, mfaEnrollNeeded)
			return
		}
		if store.RoleRank(p.Role) < store.RoleRank(role) {
			s.store.Audit(r.Context(), store.Ev{Actor: "user:" + p.User, Action: "access.denied", ObjectType: "api", ObjectID: r.Method + " " + r.URL.Path, Failure: true,
				Details: map[string]any{"role": p.Role, "required": role}})
			writeErr(w, http.StatusForbidden, "requires role "+role)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyPrincipal, p)))
	})
}

func actor(r *http.Request) string {
	return "user:" + r.Context().Value(keyPrincipal).(*principal).User
}

func (s *Server) requireAgent(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var id string
		switch {
		case r.TLS != nil && len(r.TLS.VerifiedChains) > 0:
			// mTLS: the verified client certificate names the endpoint, and its
			// serial must be the endpoint's current one (renewed or retired
			// certificates stop working).
			c := r.TLS.PeerCertificates[0]
			if err := s.store.CheckEndpointCert(r.Context(), c.Subject.CommonName, pki.SerialHex(c)); err != nil {
				writeErr(w, http.StatusUnauthorized, "client certificate not valid for an active endpoint")
				return
			}
			id = c.Subject.CommonName
		case s.cfg.InsecureHTTP:
			tok := bearer(r)
			eid, err := s.store.EndpointIDBySecret(r.Context(), tok)
			if tok == "" || err != nil {
				writeErr(w, http.StatusUnauthorized, "unknown device credential")
				return
			}
			id = eid
		default:
			writeErr(w, http.StatusUnauthorized, "client certificate required")
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyEndpoint, id)))
	})
}

func endpointID(r *http.Request) string { return r.Context().Value(keyEndpoint).(string) }

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, store.ErrForbidden):
		writeErr(w, http.StatusForbidden, err.Error())
	case errors.Is(err, store.ErrBusy):
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, store.ErrMFALocked):
		writeErr(w, http.StatusTooManyRequests, err.Error())
	default:
		s.log.Error("internal error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

type reasonBody struct {
	Reason string `json:"reason"`
}

// ---- admin handlers ----

// me: who is signed in. auth: password (local user) | sso | token.
// source is the older name of auth ("sso" also for local users' sessions
// in versions before local users; kept for scripts).
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(keyPrincipal).(*principal)
	v := map[string]any{"user": p.User, "role": p.Role, "auth": p.Source, "source": p.Source, "mfa": p.MFA,
		"email": "", "display_name": "", "must_change_password": p.MustChangePassword, "password_changed_at": "", "builtin": false,
		"default_password": false, "mfa_enrolled": false, "mfa_required": s.cfg.RequireMFA}
	switch p.Source {
	case "password":
		lp, err := s.store.GetLocalProfile(r.Context(), p.User)
		if err != nil {
			s.fail(w, err)
			return
		}
		enrolled, err := s.store.MFAEnrolled(r.Context(), p.User)
		if err != nil {
			s.fail(w, err)
			return
		}
		v["email"], v["display_name"], v["password_changed_at"], v["builtin"] = p.User, lp.DisplayName, lp.PasswordChangedAt, lp.Builtin
		v["default_password"] = lp.DefaultPassword
		v["mfa_enrolled"], v["mfa_required"] = enrolled, s.store.MFARequired(p.Role)
	case "sso":
		email, err := s.store.UserEmail(r.Context(), p.User)
		if err != nil {
			s.fail(w, err)
			return
		}
		v["email"] = email
	}
	writeJSON(w, 200, v)
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	sm, err := s.honestSummary(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, sm)
}

// isVendor: the signed-in principal is the vendor super admin.
func isVendor(r *http.Request) bool {
	p, _ := r.Context().Value(keyPrincipal).(*principal)
	return p != nil && store.CanonicalRole(p.Role) == store.RoleSuperAdmin
}

func (s *Server) listBundles(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListBundles(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id must be numeric")
		return
	}
	v, err := s.store.GetBundle(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) listPackages(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListPackages(r.Context(), r.URL.Query().Get("state"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) getPackage(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetPackage(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) packageAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action == "" { // POST /api/packages/{id}/revoke (admin route)
		action = "revoke"
	}
	if action != "approve" && action != "reject" && action != "revoke" {
		writeErr(w, 404, "unknown action")
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	if !s.agentAllowed(w, r, r.PathValue("id"), superAdminOnly, agentVendorOnly, store.RoleSuperAdmin) {
		return
	}
	publish := func(p store.Package) error { return s.repo.Publish(p.QuarantinePath, p.SHA256, p.Size) }
	v, err := s.store.SetPackageState(r.Context(), actor(r), r.PathValue("id"), action, body.Reason, publish)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) patchEndpoint(w http.ResponseWriter, r *http.Request) {
	var p store.EndpointPatch
	if !decode(w, r, &p) {
		return
	}
	if _, err := s.store.UpdateEndpoint(r.Context(), actor(r), r.PathValue("id"), p); err != nil {
		s.fail(w, err)
		return
	}
	v, err := s.store.GetEndpoint(r.Context(), r.PathValue("id"), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v.Endpoint)
}

func (s *Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Groups         []string `json:"groups"`
		Site           string   `json:"site"`
		ExpiresInHours int      `json:"expires_in_hours"`
		MaxUses        int      `json:"max_uses"`
	}
	if !decode(w, r, &body) {
		return
	}
	v, err := s.store.CreateEnrollmentToken(r.Context(), actor(r), body.Groups, body.Site, body.ExpiresInHours, body.MaxUses)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, v)
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListDeployments(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) createDeployment(w http.ResponseWriter, r *http.Request) {
	var n store.NewDeployment
	if !decode(w, r, &n) {
		return
	}
	if !s.agentAllowed(w, r, n.PackageID, superAdminOnly, agentVendorOnly, store.RoleSuperAdmin) {
		return
	}
	v, err := s.store.CreateDeployment(r.Context(), actor(r), n)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, v)
}

func (s *Server) getDeployment(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetDeployment(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, s.withLive(v))
}

func (s *Server) deploymentAction(w http.ResponseWriter, r *http.Request) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	if !s.agentDeploymentManaged(w, r, r.PathValue("id")) {
		return
	}
	v, err := s.store.DeploymentAction(r.Context(), actor(r), r.PathValue("id"), r.PathValue("action"), body.Reason)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// approveDeployment / rejectDeployment: the two-person rule (store
// ApproveDeployment). Bank users and admins only, never the creator.
func (s *Server) approveDeployment(w http.ResponseWriter, r *http.Request) {
	s.decideDeployment(w, r, s.store.ApproveDeployment)
}

func (s *Server) rejectDeployment(w http.ResponseWriter, r *http.Request) {
	s.decideDeployment(w, r, s.store.RejectDeployment)
}

func (s *Server) decideDeployment(w http.ResponseWriter, r *http.Request, decide func(ctx context.Context, actor, role, id, reason string) (store.Deployment, error)) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	if !s.agentDeploymentAllowed(w, r, r.PathValue("id")) {
		return
	}
	p := r.Context().Value(keyPrincipal).(*principal)
	v, err := decide(r.Context(), actor(r), p.Role, r.PathValue("id"), body.Reason)
	if err != nil {
		if errors.Is(err, store.ErrForbidden) {
			s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "access.denied", ObjectType: "deployment", ObjectID: r.PathValue("id"), Failure: true,
				Details: map[string]any{"role": p.Role, "required": "user or admin (bank approver)", "api": r.Method + " " + r.URL.Path}})
		}
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListExceptions(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) createException(w http.ResponseWriter, r *http.Request) {
	var n store.NewException
	if !decode(w, r, &n) {
		return
	}
	v, err := s.store.CreateException(r.Context(), actor(r), n)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, v)
}

func (s *Server) revokeException(w http.ResponseWriter, r *http.Request) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	v, err := s.store.RevokeException(r.Context(), actor(r), r.PathValue("id"), body.Reason)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	before, _ := strconv.ParseInt(q.Get("before_seq"), 10, 64)
	v, err := s.store.ListAudit(r.Context(), store.AuditQuery{ObjectID: q.Get("object_id"), Action: q.Get("action"), Actor: q.Get("actor"),
		PackageID: q.Get("package_id"), Limit: limit, BeforeSeq: before})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.VerifyAudit(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// exportLifecycle bundles all evidence for one package: source bundle and
// transfer receipt, catalog record, approvals, deployments with per-endpoint
// results, exceptions, every related audit event, and chain status.
func (s *Server) exportLifecycle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pid := r.URL.Query().Get("package_id")
	p, err := s.store.GetPackage(ctx, pid)
	if err != nil {
		s.fail(w, err)
		return
	}
	b, err := s.store.GetValidatedBundleByBundleID(ctx, p.BundleID)
	if err != nil {
		s.fail(w, err)
		return
	}
	deps, err := s.store.DeploymentsForPackage(ctx, pid)
	if err != nil {
		s.fail(w, err)
		return
	}
	excs, err := s.store.ExceptionsForPackage(ctx, pid)
	if err != nil {
		s.fail(w, err)
		return
	}
	evs, err := s.allAudit(ctx, store.AuditQuery{PackageID: pid})
	if err != nil {
		s.fail(w, err)
		return
	}
	bevs, err := s.allAudit(ctx, store.AuditQuery{ObjectID: p.BundleID})
	if err != nil {
		s.fail(w, err)
		return
	}
	chain, err := s.store.VerifyAudit(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.store.Audit(ctx, store.Ev{Actor: actor(r), Action: "audit.exported", ObjectType: "package", ObjectID: pid, PackageID: pid})
	w.Header().Set("Content-Disposition", `attachment; filename="lifecycle-`+pid+`.json"`)
	writeJSON(w, 200, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339), "package": p, "bundle": b, "deployments": deps,
		"exceptions": excs, "events": append(bevs, evs...), "audit_chain": map[string]any{"ok": chain.OK, "count": chain.Count},
	})
}

// auditPage is the largest page ListAudit returns.
var auditPage = 5000

// allAudit pages through every matching audit event in sequence order
// (evidence exports must not be silently truncated).
func (s *Server) allAudit(ctx context.Context, q store.AuditQuery) ([]store.AuditEvent, error) {
	q.Ascending, q.Limit = true, auditPage
	out := []store.AuditEvent{}
	for {
		page, err := s.store.ListAudit(ctx, q)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < auditPage {
			return out, nil
		}
		q.AfterSeq = page[len(page)-1].Seq
	}
}

// ---- agent handlers ----

// Enrollment is unauthenticated: small bodies, and per-IP rate limiting
// (a fleet enrolls from many addresses; one address hammering is an attack
// or a broken script).
const (
	enrollMaxBody = 64 << 10
	enrollBurst   = 20
	enrollEvery   = 3 * time.Second
)

func (s *Server) agentEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if ok, wait := s.enrollAllowed(ip); !ok {
		s.log.Warn("enrollment rate limited", "ip", ip)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many enrollment attempts from this address; retry later")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, enrollMaxBody)
	var req store.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	if err := store.ValidHostname(req.Hostname); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Source = ip
	var issue store.CertIssuer
	if s.ca != nil {
		if req.CSR == "" {
			writeErr(w, http.StatusBadRequest, "csr required: this server issues mTLS client certificates")
			return
		}
		issue = s.issuer(req.CSR)
	}
	id, secret, certPEM, err := s.store.Enroll(r.Context(), req, issue)
	if err != nil {
		if errors.Is(err, store.ErrInvalid) {
			if errors.Is(err, store.ErrEnrollDenied) {
				// Audited at most once per address per minute (store); every attempt is logged.
				s.log.Warn("enrollment denied", "ip", ip, "hostname", req.Hostname)
			}
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		s.fail(w, err)
		return
	}
	resp := map[string]string{"endpoint_id": id}
	if s.ca != nil {
		resp["certificate"] = certPEM
		resp["ca_certificate"] = string(s.ca.CertPEM)
	} else {
		resp["secret"] = secret // lab mode only
	}
	writeJSON(w, 201, resp)
}

func (s *Server) agentCheckin(w http.ResponseWriter, r *http.Request) {
	var req store.CheckinRequest
	if !decode(w, r, &req) {
		return
	}
	res, err := s.store.Checkin(r.Context(), endpointID(r), req)
	if err != nil {
		s.fail(w, err)
		return
	}
	rate := s.cfg.DownloadRateKbps
	if v, ok := s.cfg.SiteDownloadKbps[res.Site]; ok {
		rate = v
	}
	resp := map[string]any{"assignments": res.Assignments, "reboot_now": res.RebootNow,
		"checkin_interval_seconds": s.cfg.CheckinIntervalSeconds, "download_rate_kbps": rate,
		"preinstall": s.cfg.Preinstall.policyFor(res.OS), "next_checkin_seconds": res.NextCheckinSeconds}
	if doc, _ := s.store.GetMeta(r.Context(), "trust_doc"); doc != "" {
		resp["trust"] = json.RawMessage(doc)
	}
	writeJSON(w, 200, resp)
}

func (s *Server) agentManifest(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	if !s.store.PackageAssigned(r.Context(), endpointID(r), pid) {
		writeErr(w, 404, "not assigned")
		return
	}
	m, sig, kid, err := s.store.SignedManifest(r.Context(), pid)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"manifest": base64.StdEncoding.EncodeToString(m), "signature": sig, "key_id": kid})
}

func (s *Server) agentContent(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	p, err := s.store.ContentAllowed(r.Context(), endpointID(r), sha)
	if err != nil {
		writeErr(w, 404, "content not available to this endpoint")
		return
	}
	path, err := s.repo.Path(sha)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	f, err := os.Open(path)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-SHA256", sha)
	// ServeContent handles Range for resumable downloads.
	http.ServeContent(w, r, p.FileName, st.ModTime(), f)
}

func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	var rep store.Report
	if !decode(w, r, &rep) {
		return
	}
	if err := s.store.ReportTarget(r.Context(), endpointID(r), rep); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// agentHeartbeat keeps the endpoint "seen"; an optional body carries live
// progress of the current download or install (kept in memory only, not
// audited). Old agents send no body or "{}".
func (s *Server) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	var body heartbeatBody
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, heartbeatMaxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "heartbeat body too large")
		return
	}
	if len(bytes.TrimSpace(b)) > 0 {
		// Lenient: newer agents may send fields this server does not know.
		if err := json.Unmarshal(b, &body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}
	if body.Progress != nil {
		if err := body.Progress.validate(); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	eid := endpointID(r)
	if err := s.store.Heartbeat(r.Context(), eid); err != nil {
		s.fail(w, err)
		return
	}
	if p := body.Progress; p != nil {
		ok, err := s.store.HasTarget(r.Context(), eid, p.DeploymentID, p.PackageID)
		if err != nil {
			s.fail(w, err)
			return
		}
		if ok { // progress for deployments the endpoint is not in is ignored
			s.progress.put(eid, *p)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// issuer signs the CSR for an endpoint (enrollment and renewal).
func (s *Server) issuer(csrPEM string) store.CertIssuer {
	return func(endpointID string) (string, string, string, error) {
		certPEM, c, err := s.ca.SignClientCSR([]byte(csrPEM), endpointID)
		if err != nil {
			return "", "", "", err
		}
		return string(certPEM), pki.SerialHex(c), c.NotAfter.UTC().Format(time.RFC3339), nil
	}
}

func (s *Server) agentRenew(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		writeErr(w, http.StatusConflict, "server runs without PKI (lab mode)")
		return
	}
	var body struct {
		CSR string `json:"csr"`
	}
	if !decode(w, r, &body) {
		return
	}
	certPEM, err := s.store.RenewCert(r.Context(), endpointID(r), s.issuer(body.CSR))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"certificate": certPEM, "ca_certificate": string(s.ca.CertPEM)})
}

func (s *Server) retireEndpoint(w http.ResponseWriter, r *http.Request) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	e, err := s.store.RetireEndpoint(r.Context(), actor(r), r.PathValue("id"), body.Reason)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, e)
}

func (s *Server) listWindows(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListWindows(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) createWindow(w http.ResponseWriter, r *http.Request) {
	var mw store.MaintenanceWindow
	if !decode(w, r, &mw) {
		return
	}
	v, err := s.store.CreateWindow(r.Context(), actor(r), mw)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 201, v)
}

func (s *Server) deleteWindow(w http.ResponseWriter, r *http.Request) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	if err := s.store.DeleteWindow(r.Context(), actor(r), r.PathValue("id"), body.Reason); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) reconcile(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.Reconcile(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) availableFor(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.AvailableFor(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) packageNeeds(w http.ResponseWriter, r *http.Request) {
	v, err := s.fleetNeeds(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v.needs)
}
