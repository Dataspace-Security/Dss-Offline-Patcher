package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/pki"
	"offpatch/internal/store"
)

// ---- reports ----

func (s *Server) complianceReport(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.Compliance(r.Context(), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, rep)
}

func writeCSV(w http.ResponseWriter, name string, header []string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	cw := csv.NewWriter(w)
	cw.Write(header)
	for _, row := range rows {
		for i, v := range row {
			// Neutralise spreadsheet formula injection from data fields.
			if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
				row[i] = "'" + v
			}
		}
		cw.Write(row)
	}
	cw.Flush()
}

func f1(v float64) string {
	if v < 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func (s *Server) complianceCSV(w http.ResponseWriter, r *http.Request) {
	rep, err := s.store.Compliance(r.Context(), s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	var rows [][]string
	for _, p := range rep.Packages {
		rows = append(rows, []string{p.PackageID, p.Title, p.Severity, p.State, p.ReleaseDate, p.Deadline, strconv.Itoa(p.Targets), strconv.Itoa(p.Verified),
			strconv.Itoa(p.Outstanding), strconv.Itoa(p.Overdue), strconv.Itoa(p.Exceptions), f1(p.PctComplete),
			f1(p.DaysReleaseToReceived), f1(p.DaysReceivedToApproved), f1(p.DaysApprovedToFirst), f1(p.DaysReleaseToP90),
			strconv.Itoa(p.Needed), strconv.Itoa(p.NotTargeted)})
	}
	s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "report.exported", ObjectType: "report", ObjectID: "compliance.csv"})
	writeCSV(w, "compliance-"+time.Now().UTC().Format("20060102")+".csv",
		[]string{"package_id", "title", "severity", "state", "release_date", "deadline", "targets", "verified", "outstanding", "overdue", "exceptions",
			"pct_compliant", "days_release_to_received", "days_received_to_approved", "days_approved_to_first_verified", "days_release_to_90pct_verified",
			"needed", "not_targeted"}, rows)
}

// targetsCSV is the per-endpoint evidence an auditor asks for: every
// install target with its state, when it verified, the inventory line that
// proved it, who approved the package and the deployment.
func (s *Server) targetsCSV(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.TargetEvidenceReport(r.Context(), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	rows := make([][]string, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, []string{t.EndpointID, t.Hostname, t.PackageID, t.Title, t.State, t.VerifiedAt, t.Evidence, t.ApprovedBy, t.DeploymentID})
	}
	s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "report.exported", ObjectType: "report", ObjectID: "targets.csv"})
	writeCSV(w, "targets-"+time.Now().UTC().Format("20060102")+".csv",
		[]string{"endpoint", "hostname", "package_id", "title", "state", "verified_at", "evidence", "approved_by", "deployment_id"}, rows)
}

func (s *Server) endpointsCSV(w http.ResponseWriter, r *http.Request) {
	eps, err := s.honestEndpoints(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	var rows [][]string
	for _, e := range eps {
		rows = append(rows, []string{e.Hostname, e.EndpointID, e.Status, e.OSVersion, strconv.Itoa(e.Build), e.Edition, e.Arch, strings.Join(e.Groups, " "),
			e.Site, e.Owner, e.Criticality, e.LastSeen, e.InventoryAt, strconv.FormatBool(e.RebootPending), e.AgentVersion, e.CertNotAfter})
	}
	s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "report.exported", ObjectType: "report", ObjectID: "endpoints.csv"})
	writeCSV(w, "endpoints-"+time.Now().UTC().Format("20060102")+".csv",
		[]string{"hostname", "endpoint_id", "status", "os_version", "build", "edition", "arch", "groups", "site", "owner", "criticality",
			"last_seen", "inventory_at", "reboot_pending", "agent_version", "cert_not_after"}, rows)
}

// ---- alerts ----

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListAlerts(r.Context(), r.URL.Query().Get("open") == "1")
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) ackAlert(w http.ResponseWriter, r *http.Request) {
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "id must be numeric")
		return
	}
	if err := s.store.AckAlert(r.Context(), actor(r), id, body.Reason); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// NotifyConfig delivers alerts to systems INSIDE the isolated zone only.
type NotifyConfig struct {
	SMTP *struct {
		Addr string   `json:"addr"` // internal relay host:port
		From string   `json:"from"`
		To   []string `json:"to"`
	} `json:"smtp"`
	WebhookURL   string `json:"webhook_url"` // internal SIEM / chat bridge
	MinSeverity  string `json:"min_severity"`
	WebhookToken string `json:"webhook_token"`
}

var sevRank = map[string]int{"info": 1, "warning": 2, "critical": 3}

// deliverEvery: how often undelivered alerts are pushed to mail/webhook.
// Delivery runs apart from the sweep, so a slow or unreachable relay delays
// notifications but never the sweep (lost endpoints, auto-pause, expiry).
var deliverEvery = 30 * time.Second

// RunAlerts sweeps time-based conditions and delivers new alerts, until ctx
// is cancelled and both loops have returned.
func (s *Server) RunAlerts(ctx context.Context, every time.Duration) {
	done := make(chan struct{})
	kick := make(chan struct{}, 1)
	go func() {
		defer close(done)
		s.runDelivery(ctx, kick)
	}()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		// The intelligence's Windows revisions back check-in verification
		// and the unverified-install explanations (store.SetUBRHint): load
		// it before anyone opens the console.
		if _, _, err := s.intelIndex(ctx); err != nil {
			s.log.Error("update intelligence", "err", err)
		}
		if err := s.store.SweepAlerts(ctx, s.th); err != nil {
			s.log.Error("alert sweep", "err", err)
		}
		if err := s.checkServerCert(ctx, time.Now()); err != nil {
			s.log.Error("server certificate check", "err", err)
		}
		if err := s.checkPublicCert(ctx); err != nil {
			s.log.Error("public certificate check", "err", err)
		}
		if err := s.SweepIntelAlerts(ctx); err != nil {
			s.log.Error("update intelligence alert sweep", "err", err)
		}
		if _, err := s.SnapshotFleetDay(ctx, FleetSnapshotEvery); err != nil {
			s.log.Error("daily fleet snapshot", "err", err)
		}
		select { // deliver what the sweep raised; never wait for delivery
		case kick <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			<-done
			return
		case <-t.C:
		}
	}
}

// runDelivery delivers after each sweep (kick) and every deliverEvery (for
// alerts raised by intake and agent reports in between).
func (s *Server) runDelivery(ctx context.Context, kick <-chan struct{}) {
	t := time.NewTicker(deliverEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
		case <-t.C:
		}
		s.deliverAlerts(ctx)
	}
}

// serverCertWarn: alert this long before the server TLS certificate expires.
const serverCertWarn = 30 * 24 * time.Hour

// checkServerCert raises a warning when the server certificate expires
// within serverCertWarn (critical once expired: agents refuse it).
func (s *Server) checkServerCert(ctx context.Context, now time.Time) error {
	if s.cfg.TLSCert == "" {
		return nil
	}
	b, err := os.ReadFile(s.cfg.TLSCert)
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return fmt.Errorf("%s: no PEM certificate", s.cfg.TLSCert)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}
	left := c.NotAfter.Sub(now)
	if left > serverCertWarn {
		return nil
	}
	sev, msg := "warning", fmt.Sprintf("server TLS certificate expires %s (in %d days); run `pmserver reissue-server-cert` and restart before then", c.NotAfter.UTC().Format("2006-01-02"), int(left.Hours()/24))
	if left <= 0 {
		sev, msg = "critical", fmt.Sprintf("server TLS certificate EXPIRED %s: agents cannot connect; run `pmserver reissue-server-cert` and restart", c.NotAfter.UTC().Format("2006-01-02"))
	}
	return s.store.RaiseAlert(ctx, sev, "server_cert_expiring", "server", pki.SerialHex(c), msg)
}

func (s *Server) deliverAlerts(ctx context.Context) {
	n := s.cfg.Notify
	as, err := s.store.UndeliveredAlerts(ctx)
	if err != nil {
		s.log.Error("alerts", "err", err)
		return
	}
	// After one failure a channel is not retried this round: an unreachable
	// relay costs one timeout per round, not one per alert.
	mailDown, hookDown := false, false
	for _, a := range as {
		if ctx.Err() != nil {
			return
		}
		ok := true
		if n != nil && sevRank[a.Severity] >= sevRank[orDefault(n.MinSeverity, "warning")] {
			if n.SMTP != nil {
				if mailDown {
					ok = false
				} else if err := sendMail(n.SMTP.Addr, n.SMTP.From, n.SMTP.To, a); err != nil {
					s.log.Warn("alert mail failed; will retry", "err", err)
					ok, mailDown = false, true
				}
			}
			if n.WebhookURL != "" {
				if hookDown {
					ok = false
				} else if err := s.postWebhook(ctx, n.WebhookURL, n.WebhookToken, a); err != nil {
					s.log.Warn("alert webhook failed; will retry", "err", err)
					ok, hookDown = false, true
				}
			}
		}
		if ok {
			s.store.MarkDelivered(ctx, a.ID)
		}
	}
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// smtpTimeout bounds one whole mail transaction (connect to QUIT).
var smtpTimeout = 30 * time.Second

// sendMail is smtp.SendMail with a deadline: a relay that accepts the
// connection and then stalls must not hang alert delivery.
func sendMail(addr, from string, to []string, a store.Alert) error {
	subject := fmt.Sprintf("[offpatch %s] %s", strings.ToUpper(a.Severity), a.Kind)
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\nObject: %s %s\r\nRaised: %s\r\n",
		from, strings.Join(to, ", "), subject, a.Message, a.ObjectType, a.ObjectID, a.CreatedAt)
	conn, err := net.DialTimeout("tcp", addr, smtpTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(smtpTimeout)); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok { // as smtp.SendMail does
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(body)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *Server) postWebhook(ctx context.Context, url, token string, a store.Alert) error {
	b, _ := json.Marshal(a)
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook: %s", resp.Status)
	}
	return nil
}

// ---- metrics (Prometheus text format) ----

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if s.cfg.MetricsToken == "" {
		writeErr(w, 404, "metrics disabled (set metrics_token)")
		return
	}
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.MetricsToken)) != 1 {
		writeErr(w, 401, "metrics token required")
		return
	}
	ctx := r.Context()
	sm, err := s.honestSummary(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	rep, err := s.store.Compliance(ctx, s.th)
	if err != nil {
		s.fail(w, err)
		return
	}
	alerts, _ := s.store.ListAlerts(ctx, true)
	var b strings.Builder
	gauge := func(name, help string, vals map[string]int, label string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s{%s=%q} %d\n", name, label, k, vals[k])
		}
	}
	gauge("offpatch_endpoints", "Endpoints by derived status.", sm.Endpoints.ByStatus, "status")
	gauge("offpatch_packages", "Catalog packages by state.", sm.Packages, "state")
	gauge("offpatch_bundles", "Received bundles by state.", sm.Bundles, "state")
	gauge("offpatch_deployments", "Deployments by state.", sm.Deployments, "state")
	sev := map[string]int{}
	for _, a := range alerts {
		sev[a.Severity]++
	}
	gauge("offpatch_alerts_open", "Unacknowledged alerts by severity.", sev, "severity")
	overdue, compliant := map[string]int{}, map[string]int{}
	for k, v := range rep.BySeverity {
		overdue[k] = v.Overdue
		compliant[k] = int(v.PctComplete)
	}
	gauge("offpatch_targets_overdue", "Unpatched targets past their deadline, by severity.", overdue, "severity")
	gauge("offpatch_compliance_percent", "Percent of targets verified, by severity.", compliant, "severity")
	fmt.Fprintf(&b, "# HELP offpatch_fleet_reporting_percent Endpoints that checked in recently.\n# TYPE offpatch_fleet_reporting_percent gauge\noffpatch_fleet_reporting_percent %.1f\n", rep.Fleet.PctReporting)
	fmt.Fprintf(&b, "# HELP offpatch_exceptions_active Active exceptions.\n# TYPE offpatch_exceptions_active gauge\noffpatch_exceptions_active %d\n", sm.ActiveExceptions)
	auditOK := 0
	if sm.Audit.OK {
		auditOK = 1
	}
	fmt.Fprintf(&b, "# HELP offpatch_audit_chain_ok 1 if the audit hash chain verifies.\n# TYPE offpatch_audit_chain_ok gauge\noffpatch_audit_chain_ok %d\n", auditOK)
	fmt.Fprintf(&b, "# HELP offpatch_audit_events Audit events in the chain.\n# TYPE offpatch_audit_events counter\noffpatch_audit_events %d\n", sm.Audit.Count)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}
