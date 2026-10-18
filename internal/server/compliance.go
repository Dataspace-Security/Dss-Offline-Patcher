package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"offpatch/internal/auditexport"
	"offpatch/internal/compliance"
	"offpatch/internal/store"
)

// Auditor compliance report (docs/10-compliance-report.md): the versioned
// report profile, the JSON pack and the signed ZIP package.

// privilegedActions: audit actions listed as privileged activity (E-009).
var privilegedActions = []string{"user.", "auth.locked", "access.denied", "package.approved", "package.rejected", "package.revoked",
	"package.approval_recorded", "deployment.approved", "deployment.rejected", "deployment.activated", "deployment.cancelled",
	"exception.", "trust.", "enrollment_token.", "endpoint.retired", "audit.", "report.", "window.", "backup."}

// privilegedLimit bounds the events listed in E-009 (the signed audit
// export holds them all).
const privilegedLimit = 50000

// maxReportDays bounds a report period.
const maxReportDays = 3660

type reportKey struct {
	mu  sync.Mutex
	key ed25519.PrivateKey
}

// signingKey is the audit-signing key (created on first use, the same file
// the audit export signs checkpoints with).
func (s *Server) signingKey() (ed25519.PrivateKey, error) {
	s.repKey.mu.Lock()
	defer s.repKey.mu.Unlock()
	if s.repKey.key != nil {
		return s.repKey.key, nil
	}
	k, err := auditexport.LoadOrCreateKey(filepath.Join(s.cfg.DataDir, "audit-signing.key"))
	if err != nil {
		return nil, err
	}
	s.repKey.key = k
	return k, nil
}

// ---- profile ----

func (s *Server) getReportProfile(w http.ResponseWriter, r *http.Request) {
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErr(w, 400, "version must be a positive number")
			return
		}
		rec, err := s.store.GetReportProfileVersion(r.Context(), n)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, 200, rec)
		return
	}
	rec, err := s.store.GetReportProfile(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) putReportProfile(w http.ResponseWriter, r *http.Request) {
	base := -1
	if v := r.URL.Query().Get("base_version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, 400, "base_version must be a number")
			return
		}
		base = n
	}
	var p store.ReportProfile
	if !decode(w, r, &p) {
		return
	}
	rec, err := s.store.SaveReportProfile(r.Context(), actor(r), p, base)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) reportProfileHistory(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ReportProfileHistory(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

// ---- pack ----

// reportPeriod parses ?from=&to= (YYYY-MM-DD, inclusive) in the report time
// zone (?tz= IANA name, default the server's). Default: this month so far.
func (s *Server) reportPeriod(r *http.Request) (from, to time.Time, loc *time.Location, err error) {
	q := r.URL.Query()
	loc = time.Local
	if tz := q.Get("tz"); tz != "" {
		if loc, err = time.LoadLocation(tz); err != nil {
			return from, to, nil, store.Errf(store.ErrInvalid, "unknown time zone %q", tz)
		}
	}
	now := s.store.Now().In(loc)
	from = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, loc)
	to = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, 1)
	if v := q.Get("from"); v != "" {
		if from, err = time.ParseInLocation("2006-01-02", v, loc); err != nil {
			return from, to, nil, store.Errf(store.ErrInvalid, "from must be YYYY-MM-DD")
		}
	}
	if v := q.Get("to"); v != "" {
		t, perr := time.ParseInLocation("2006-01-02", v, loc)
		if perr != nil {
			return from, to, nil, store.Errf(store.ErrInvalid, "to must be YYYY-MM-DD")
		}
		to = t.AddDate(0, 0, 1)
	}
	switch {
	case !from.Before(to):
		return from, to, nil, store.Errf(store.ErrInvalid, "from must not be after to")
	case to.Sub(from) > maxReportDays*24*time.Hour:
		return from, to, nil, store.Errf(store.ErrInvalid, "the period is limited to %d days", maxReportDays)
	case from.After(now):
		return from, to, nil, store.Errf(store.ErrInvalid, "the period starts in the future")
	}
	return from, to, loc, nil
}

// reportInput gathers the pack's data: cached fleet views (endpoints with
// honest status, package needs) and one query per data set.
func (s *Server) reportInput(ctx context.Context, p *principal, from, to time.Time, loc *time.Location, redact bool) (*compliance.Input, error) {
	in := &compliance.Input{Now: s.store.Now(), Loc: loc, From: from, To: to, GeneratedBy: compliance.User{User: p.User, Role: p.Role},
		ProductVersion: Version, Redact: redact, Policy: s.store.Policy, Filters: map[string]string{"scope": "all enrolled endpoints"}}
	if redact {
		in.Filters["redact"] = "hostnames, IP addresses, user IDs"
	}
	var err error
	if in.Profile, err = s.store.GetReportProfile(ctx); err != nil {
		return nil, err
	}
	if in.ProfileHistory, err = s.store.ReportProfileHistory(ctx); err != nil {
		return nil, err
	}
	if in.Endpoints, err = s.honestEndpoints(ctx); err != nil {
		return nil, err
	}
	nv, err := s.fleetNeeds(ctx)
	if err != nil {
		return nil, err
	}
	in.Needs = make(map[string][]string, len(nv.needs))
	for id, n := range nv.needs { // copied: the cached view is shared
		in.Needs[id] = append([]string(nil), n.Endpoints...)
	}
	if in.Packages, err = s.store.ListPackages(ctx, ""); err != nil {
		return nil, err
	}
	if in.Targets, err = s.store.PackTargets(ctx); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(in.Packages))
	for _, pk := range in.Packages {
		if pk.State == "approved" || pk.State == "quarantined" {
			ids = append(ids, pk.PackageID)
		}
	}
	if in.InstallTimes, err = s.store.InstallTimes(ctx, ids); err != nil {
		return nil, err
	}
	if in.Exceptions, err = s.store.ListExceptions(ctx); err != nil {
		return nil, err
	}
	if in.Deployments, err = s.store.ListDeployments(ctx); err != nil {
		return nil, err
	}
	if in.Bundles, err = s.store.ListBundles(ctx); err != nil {
		return nil, err
	}
	if in.Receipts, err = s.store.ListReceipts(ctx); err != nil {
		return nil, err
	}
	if in.Acquisitions, err = s.store.AcquisitionBetween(ctx, from, to); err != nil {
		return nil, err
	}
	if in.Users, err = s.store.ListUsers(ctx); err != nil {
		return nil, err
	}
	if in.IntelAge, err = s.intelAge(ctx); err != nil {
		return nil, err
	}
	// Incremental chain verification (a full walk at most hourly, as the
	// status pages); GET /api/audit/verify always walks everything.
	if in.Chain, err = s.store.AuditChainStatus(ctx); err != nil {
		return nil, err
	}
	if in.AuditHeadSeq, _, err = s.store.AuditHead(ctx); err != nil {
		return nil, err
	}
	if in.PrivilegedEvents, in.PrivilegedTruncated, err = s.store.AuditBetween(ctx, from, to, privilegedActions, privilegedLimit); err != nil {
		return nil, err
	}
	if in.DeploymentEvents, _, err = s.store.AuditBetween(ctx, from, to, []string{"deployment.auto_paused", "deployment.paused", "deployment.resumed", "deployment.advanced"}, 0); err != nil {
		return nil, err
	}
	if in.ReportEvents, _, err = s.store.AuditBetween(ctx, from, to, []string{"report."}, 0); err != nil {
		return nil, err
	}
	if in.BackupEvents, _, err = s.store.AuditBetween(ctx, time.Unix(0, 0), in.Now.Add(time.Hour), []string{"backup."}, 1000); err != nil {
		return nil, err
	}
	exported, _ := s.store.GetMeta(ctx, "audit_exported_seq")
	expSeq, _ := strconv.ParseInt(exported, 10, 64)
	c := s.cfg
	in.Settings = compliance.Settings{SeparationOfDuties: c.SeparationOfDuties, DeploymentApprovals: s.store.Policy.RequiredDeploymentApprovals(),
		ApprovalPolicy: c.ApprovalPolicy, RequireMFA: c.RequireMFA, SSO: c.OIDC != nil, TLS: c.TLSCert != "", MTLSAgents: c.PKIDir != "",
		InsecureHTTP: c.InsecureHTTP, ScannerConfigured: len(c.ScanCommand) > 0, AuditExportDir: c.AuditExportDir != "", AuditExportedSeq: expSeq,
		AuditRetention: c.AuditRetention.Duration, AuditCheckpointEvery: c.AuditCheckpointEvery.Duration, OfflineAfter: c.OfflineAfter.Duration,
		StaleAfter: c.StaleInventoryAfter.Duration, DeploymentMode: c.DeploymentMode}
	return in, nil
}

func (s *Server) buildPack(r *http.Request) (*compliance.Pack, error) {
	ctx := r.Context()
	from, to, loc, err := s.reportPeriod(r)
	if err != nil {
		return nil, err
	}
	redact := r.URL.Query().Get("redact") == "1" || r.URL.Query().Get("redact") == "true"
	in, err := s.reportInput(ctx, r.Context().Value(keyPrincipal).(*principal), from, to, loc, redact)
	if err != nil {
		return nil, err
	}
	var salt []byte
	if redact {
		if salt, err = s.store.PseudonymSalt(ctx); err != nil {
			return nil, err
		}
	}
	return compliance.Build(in, salt)
}

func (s *Server) auditPackGenerated(ctx context.Context, actorName string, pk *compliance.Pack, format, manifestSHA string) error {
	d := map[string]any{"report_id": pk.Meta.ReportID, "period_from": pk.Meta.Period.From, "period_to": pk.Meta.Period.To, "format": format,
		"redacted": pk.Meta.Redacted, "profile_version": pk.ProfileVersion.Version, "overall_suggested": pk.OverallAssessment.Suggested,
		"generated_at": pk.Meta.GeneratedAt}
	if manifestSHA != "" {
		d["manifest_sha256"] = manifestSHA
	}
	return s.store.Audit(ctx, store.Ev{Actor: actorName, Action: "report.compliance_generated", ObjectType: "report", ObjectID: pk.Meta.ReportID, Details: d})
}

// compliancePack: GET /api/reports/compliance-pack?from=&to=[&redact=1][&tz=]
func (s *Server) compliancePack(w http.ResponseWriter, r *http.Request) {
	pk, err := s.buildPack(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.auditPackGenerated(r.Context(), actor(r), pk, "json", ""); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, pk)
}

// compliancePackZip: GET /api/reports/compliance-pack.zip — the signed
// package, streamed. The generation is audited (with the manifest hash)
// before the ZIP is finished: if that fails the download is incomplete.
func (s *Server) compliancePackZip(w http.ResponseWriter, r *http.Request) {
	pk, err := s.buildPack(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	key, err := s.signingKey()
	if err != nil {
		s.fail(w, err)
		return
	}
	name := "compliance-" + pk.Meta.ReportID
	if pk.Meta.Redacted {
		name += "-redacted"
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.zip"`)
	_, err = pk.WriteZip(w, key, func(sum string) error {
		return s.auditPackGenerated(r.Context(), actor(r), pk, "zip", sum)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		s.log.Error("compliance package not completed", "report_id", pk.Meta.ReportID, "err", err)
	}
}
