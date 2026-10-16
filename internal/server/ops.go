package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"time"

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
			f1(p.DaysReleaseToReceived), f1(p.DaysReceivedToApproved), f1(p.DaysApprovedToFirst), f1(p.DaysReleaseToP90)})
	}
	s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "report.exported", ObjectType: "report", ObjectID: "compliance.csv"})
	writeCSV(w, "compliance-"+time.Now().UTC().Format("20060102")+".csv",
		[]string{"package_id", "title", "severity", "state", "release_date", "deadline", "targets", "verified", "outstanding", "overdue", "exceptions",
			"pct_compliant", "days_release_to_received", "days_received_to_approved", "days_approved_to_first_verified", "days_release_to_90pct_verified"}, rows)
}

func (s *Server) endpointsCSV(w http.ResponseWriter, r *http.Request) {
	eps, err := s.store.ListEndpoints(r.Context(), s.th)
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

// RunAlerts sweeps time-based conditions and delivers new alerts.
func (s *Server) RunAlerts(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.store.SweepAlerts(ctx, s.th); err != nil {
			s.log.Error("alert sweep", "err", err)
		}
		s.deliverAlerts(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) deliverAlerts(ctx context.Context) {
	n := s.cfg.Notify
	as, err := s.store.UndeliveredAlerts(ctx)
	if err != nil {
		s.log.Error("alerts", "err", err)
		return
	}
	for _, a := range as {
		ok := true
		if n != nil && sevRank[a.Severity] >= sevRank[orDefault(n.MinSeverity, "warning")] {
			if n.SMTP != nil {
				if err := sendMail(n.SMTP.Addr, n.SMTP.From, n.SMTP.To, a); err != nil {
					s.log.Warn("alert mail failed; will retry", "err", err)
					ok = false
				}
			}
			if n.WebhookURL != "" {
				if err := s.postWebhook(ctx, n.WebhookURL, n.WebhookToken, a); err != nil {
					s.log.Warn("alert webhook failed; will retry", "err", err)
					ok = false
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

func sendMail(addr, from string, to []string, a store.Alert) error {
	subject := fmt.Sprintf("[offpatch %s] %s", strings.ToUpper(a.Severity), a.Kind)
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\nObject: %s %s\r\nRaised: %s\r\n",
		from, strings.Join(to, ", "), subject, a.Message, a.ObjectType, a.ObjectID, a.CreatedAt)
	return smtp.SendMail(addr, nil, from, to, []byte(body))
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
	sm, err := s.store.Summary(ctx, s.th)
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
