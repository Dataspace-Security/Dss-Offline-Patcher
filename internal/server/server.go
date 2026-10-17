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

	// Set by TLSConfig before serving: whether the CA is sent in the chain
	// (needed to pin it) and the names/IPs the server certificate covers.
	caInChain bool
	certHosts []string

	intel intelCache
}

func New(cfg *Config, st *store.Store, rp *repo.Repo, ui fs.FS, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, store: st, repo: rp, ui: ui, log: log,
		th: store.Thresholds{OfflineAfter: cfg.OfflineAfter.Duration, StaleAfter: cfg.StaleInventoryAfter.Duration, LostAfterInstall: cfg.LostAfterInstall.Duration}}
	s.auth = newAuthState()
	dl := map[string]time.Duration{}
	for k, v := range cfg.PatchDeadlines {
		dl[k] = v.Duration
	}
	st.Policy = store.Policy{ApprovalsRequired: cfg.ApprovalPolicy, SeparationOfDuties: cfg.SeparationOfDuties, Deadlines: dl}
	if cfg.PKIDir != "" {
		ca, err := pki.Load(cfg.PKIDir)
		if err != nil {
			return nil, fmt.Errorf("load PKI from %s: %w", cfg.PKIDir, err)
		}
		s.ca = ca
	}
	return s, nil
}

// TLSConfig requests (but does not require) client certificates: browsers
// using the console present none; agents must present one (enforced in
// requireAgent).
//
// With the internal CA, the server certificate is served together with the CA
// certificate, so a client can pin the CA by fingerprint before it trusts it
// (the one-command endpoint install does this).
func (s *Server) TLSConfig() *tls.Config {
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

type principal struct {
	User, Role, Source string
	MFA                bool
}

type ctxKey int

const (
	keyPrincipal ctxKey = iota
	keyEndpoint
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	admin := func(role, pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireAdmin(role, h)) }

	admin("viewer", "GET /api/me", s.me)
	admin("viewer", "GET /api/summary", s.summary)
	admin("viewer", "GET /api/bundles", s.listBundles)
	admin("viewer", "GET /api/bundles/{id}", s.getBundle)
	admin("viewer", "GET /api/transfer/reconcile", s.reconcile)
	admin("viewer", "GET /api/system", s.system)
	admin("viewer", "GET /api/acquisition", s.acquisition)
	admin("viewer", "GET /api/reports/compliance", s.complianceReport)
	admin("viewer", "GET /api/reports/compliance.csv", s.complianceCSV)
	admin("viewer", "GET /api/reports/endpoints.csv", s.endpointsCSV)
	admin("viewer", "GET /api/alerts", s.listAlerts)
	admin("operator", "POST /api/alerts/{id}/ack", s.ackAlert)
	mux.HandleFunc("GET /metrics", s.metrics)
	admin("viewer", "GET /api/packages", s.listPackages)
	admin("viewer", "GET /api/packages/{id}", s.getPackage)
	admin("approver", "POST /api/packages/{id}/{action}", s.packageAction)
	admin("viewer", "GET /api/endpoints", s.listEndpoints)
	admin("viewer", "GET /api/endpoints/{id}", s.getEndpoint)
	admin("viewer", "GET /api/endpoints/{id}/available", s.availableFor)
	admin("viewer", "GET /api/endpoints/{id}/updates", s.endpointUpdates)
	admin("viewer", "GET /api/updates", s.fleetUpdates)
	admin("viewer", "GET /api/intel", s.intelStatus)
	admin("viewer", "GET /api/packages-needs", s.packageNeeds)
	admin("operator", "PATCH /api/endpoints/{id}", s.patchEndpoint)
	admin("operator", "POST /api/endpoints/{id}/retire", s.retireEndpoint)
	admin("operator", "POST /api/enrollment-tokens", s.createEnrollmentToken)
	admin("viewer", "GET /api/agent-setup", s.agentSetup)
	admin("viewer", "GET /api/agent-setup/files/{name}", s.agentSetupFile)
	admin("viewer", "GET /api/deployments", s.listDeployments)
	admin("operator", "POST /api/deployments", s.createDeployment)
	admin("viewer", "GET /api/deployments/{id}", s.getDeployment)
	admin("operator", "POST /api/deployments/{id}/{action}", s.deploymentAction)
	admin("viewer", "GET /api/maintenance-windows", s.listWindows)
	admin("operator", "POST /api/maintenance-windows", s.createWindow)
	admin("operator", "POST /api/maintenance-windows/{id}/delete", s.deleteWindow)
	admin("viewer", "GET /api/exceptions", s.listExceptions)
	admin("approver", "POST /api/exceptions", s.createException)
	admin("approver", "POST /api/exceptions/{id}/revoke", s.revokeException)
	admin("viewer", "GET /api/audit", s.listAudit)
	admin("viewer", "GET /api/audit/verify", s.verifyAudit)
	admin("viewer", "GET /api/audit/export", s.exportLifecycle)

	mux.HandleFunc("GET /auth/config", s.authConfig)
	mux.HandleFunc("GET /auth/login", s.authLogin)
	mux.HandleFunc("GET /auth/callback", s.authCallback)
	mux.HandleFunc("POST /auth/logout", s.authLogout)
	admin("admin", "GET /api/users", s.listUsers)
	admin("admin", "POST /api/users/{name}/{action}", s.userAction)

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
	return securityHeaders(mux)
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

func (s *Server) requireAdmin(role string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, why := s.principalFor(r)
		if p == nil {
			writeErr(w, http.StatusUnauthorized, why)
			return
		}
		if roleRank[p.Role] < roleRank[role] {
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

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(keyPrincipal).(*principal)
	writeJSON(w, 200, map[string]any{"user": p.User, "role": p.Role, "source": p.Source, "mfa": p.MFA})
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	sm, err := s.store.Summary(r.Context(), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, sm)
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
	if action != "approve" && action != "reject" && action != "revoke" {
		writeErr(w, 404, "unknown action")
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
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

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListEndpoints(r.Context(), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) getEndpoint(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.GetEndpoint(r.Context(), r.PathValue("id"), s.th)
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
	writeJSON(w, 200, v)
}

func (s *Server) deploymentAction(w http.ResponseWriter, r *http.Request) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	v, err := s.store.DeploymentAction(r.Context(), actor(r), r.PathValue("id"), r.PathValue("action"), body.Reason)
	if err != nil {
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
	evs, err := s.store.ListAudit(ctx, store.AuditQuery{PackageID: pid, Limit: 5000, Ascending: true})
	if err != nil {
		s.fail(w, err)
		return
	}
	bevs, err := s.store.ListAudit(ctx, store.AuditQuery{ObjectID: p.BundleID, Limit: 100, Ascending: true})
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

// ---- agent handlers ----

func (s *Server) agentEnroll(w http.ResponseWriter, r *http.Request) {
	var req store.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
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
		"preinstall": s.cfg.Preinstall.policyFor(res.OS)}
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

func (s *Server) agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Heartbeat(r.Context(), endpointID(r)); err != nil {
		s.fail(w, err)
		return
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
	v, err := s.store.Needs(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}
