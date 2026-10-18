package compliance

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/store"
)

// Evidence files (template §6). Each is a CSV written in one pass;
// formula characters are neutralised as in the other CSV exports.

func safeCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

type csvOut struct {
	w    *csv.Writer
	rows int
}

func (c *csvOut) row(cells ...string) {
	for i, v := range cells {
		cells[i] = safeCell(v)
	}
	c.w.Write(cells)
	c.rows++
}

func b2s(b bool) string { return strconv.FormatBool(b) }

// evidenceWriters, by evidence ID: header first, then rows.
func (pk *Pack) evidenceWriter(id string) func(*csvOut) {
	in := pk.in
	switch id {
	case "E-001":
		return func(c *csvOut) {
			c.w.Write([]string{"record", "priority", "max_days", "source", "clock_start", "exception_process", "policy_version", "approved_by", "approved_at", "review_date", "reference"})
			pol := in.Profile.Profile.Policy
			c.row("policy", "", "", "", "", "", pol.Version, pol.ApprovedBy, pol.ApprovedAt, pol.ReviewDate, pol.Reference)
			for _, d := range in.Profile.Profile.Deadlines {
				c.row("deadline", d.Priority, strconv.Itoa(d.MaxDays), d.Source, d.ClockStart, d.ExceptionProcess, "", "", "", "", "")
			}
		}
	case "E-002":
		return func(c *csvOut) {
			c.w.Write([]string{"endpoint_id", "hostname", "status", "os", "os_version", "build", "edition", "arch", "groups", "site", "owner", "criticality",
				"last_seen", "inventory_at", "reboot_pending", "agent_version", "os_support", "missing_os_updates", "missing_app_updates", "enrolled_at", "retired_at"})
			for _, e := range in.Endpoints {
				sup, mos, mapps := "", "", ""
				if e.Missing != nil {
					sup, mos, mapps = e.Missing.OSSupport, strconv.Itoa(e.Missing.OS), strconv.Itoa(e.Missing.Apps)
				}
				c.row(e.EndpointID, e.Hostname, e.Status, e.OS, e.OSVersion, strconv.Itoa(e.Build), e.Edition, e.Arch, strings.Join(e.Groups, " "), e.Site,
					e.Owner, e.Criticality, e.LastSeen, e.InventoryAt, b2s(e.RebootPending), e.AgentVersion, sup, mos, mapps, e.EnrolledAt, e.RetiredAt)
			}
		}
	case "E-003":
		return func(c *csvOut) {
			c.w.Write([]string{"package_id", "title", "vendor", "kind", "version", "kb", "severity", "priority", "release_date", "received_at", "bundle_id", "state",
				"approvals", "approved_by", "approved_at", "max_days", "clock_start", "sha256", "size", "source_url", "vendor_signature", "superseded_by"})
			for _, p := range in.Packages {
				pr := store.PriorityForSeverity(p.Severity)
				r := in.Profile.Profile.DeadlineFor(in.Policy, pr)
				var by []string
				for _, a := range p.Approvals {
					by = append(by, a.By)
				}
				c.row(p.PackageID, p.Title, p.Vendor, p.Kind, p.Version, p.KB, p.Severity, pr, p.ReleaseDate, p.CreatedAt, p.BundleID, p.State,
					strconv.Itoa(len(p.Approvals)), strings.Join(by, "; "), approvedAt(p), strconv.Itoa(r.MaxDays), r.ClockStart, p.SHA256,
					strconv.FormatInt(p.Size, 10), p.SourceURL, p.VendorSignature.Status, p.SupersededBy)
			}
		}
	case "E-004":
		return func(c *csvOut) {
			c.w.Write([]string{"record", "file", "file_sha256", "size", "adapter", "sent_at", "received_at", "key_id", "signature_ok", "reconciliation"})
			arrived := map[string]bool{}
			for _, b := range in.Bundles {
				arrived[b.FileSHA256] = true
			}
			receipted := map[string]bool{}
			for _, r := range in.Receipts {
				if !inPeriod(in, r.ReceivedAt) {
					continue
				}
				if r.SignatureOK {
					receipted[r.FileSHA256] = true
				}
				st := "receipt_without_bundle"
				if arrived[r.FileSHA256] {
					st = "matched"
				}
				if strings.HasSuffix(r.File, ".trust.json") {
					st = "trust_document"
				}
				c.row("receipt", r.File, r.FileSHA256, strconv.FormatInt(r.Size, 10), r.Adapter, r.SentAt, r.ReceivedAt, r.KeyID, b2s(r.SignatureOK), st)
			}
			for _, b := range in.Bundles {
				if inPeriod(in, b.ReceivedAt) && !receipted[b.FileSHA256] {
					c.row("bundle_without_receipt", b.Filename, b.FileSHA256, strconv.FormatInt(b.FileSize, 10), "", "", b.ReceivedAt, b.KeyID, "", "bundle_without_receipt")
				}
			}
		}
	case "E-005":
		return func(c *csvOut) {
			c.w.Write([]string{"bundle_id", "source", "sequence", "key_id", "state", "filename", "file_sha256", "received_at", "packages", "checks", "error"})
			for _, b := range in.Bundles {
				if !inPeriod(in, b.ReceivedAt) {
					continue
				}
				var ch []string
				for _, k := range b.Checks {
					ch = append(ch, k.Name+"="+map[bool]string{true: "ok", false: "FAILED"}[k.OK])
				}
				c.row(b.BundleID, b.Source, strconv.FormatInt(b.Sequence, 10), b.KeyID, b.State, b.Filename, b.FileSHA256, b.ReceivedAt, strconv.Itoa(b.PackageCount), strings.Join(ch, " "), b.Error)
			}
		}
	case "E-006":
		return func(c *csvOut) {
			c.w.Write([]string{"deployment_id", "package_id", "name", "operation", "emergency", "justification", "state", "created_by", "created_at", "approvals_required",
				"approvers", "approved_at", "activated_at", "rings", "max_failure_pct", "health_checks", "approval_evidence"})
			pkgs := map[string]store.Package{}
			for _, p := range in.Packages {
				pkgs[p.PackageID] = p
			}
			for _, d := range in.Deployments {
				if !inPeriod(in, d.CreatedAt) && !inPeriod(in, d.ActivatedAt) {
					continue
				}
				var by, at, rings []string
				for _, a := range d.Approvals {
					by, at = append(by, a.By), append(at, a.At)
				}
				for _, r := range d.Rings {
					rings = append(rings, r.Name+"("+strings.Join(r.Groups, " ")+")")
				}
				ev := "ok"
				if d.State == "pending_approval" || d.State == "rejected" {
					ev = "not in production (" + d.State + ")"
				} else if msg := approvalProblem(d, pkgs[d.PackageID], in.Settings.SeparationOfDuties); msg != "" {
					ev = msg
				}
				c.row(d.DeploymentID, d.PackageID, d.Name, d.Operation, b2s(d.Emergency), d.Justification, d.State, d.CreatedBy, d.CreatedAt,
					strconv.Itoa(d.ApprovalsRequired), strings.Join(by, "; "), strings.Join(at, "; "), d.ActivatedAt, strings.Join(rings, " > "),
					strconv.Itoa(d.MaxFailurePct), strconv.Itoa(len(d.HealthChecks)), ev)
			}
		}
	case "E-007":
		return func(c *csvOut) {
			c.w.Write([]string{"endpoint_id", "hostname", "package_id", "title", "kb", "severity", "priority", "release_date", "acquired_at", "approved_at",
				"clock_start", "deadline", "deadline_source", "installed_at", "verified_at", "outcome", "past_deadline", "deployment_id", "evidence", "exception_id", "basis"})
			for _, pr := range pk.pairs {
				p := pk.exported(pr)
				c.row(p.EndpointID, p.Hostname, p.PackageID, p.Title, p.KB, p.Severity, p.Priority, p.ReleaseDate, p.AcquiredAt, p.ApprovedAt,
					p.ClockStart, p.Deadline, p.DeadlineSource, p.InstalledAt, p.VerifiedAt, p.Outcome, b2s(p.PastDeadline), p.DeploymentID, p.Evidence, p.ExceptionID, p.Basis)
			}
		}
	case "E-008":
		return func(c *csvOut) {
			c.w.Write([]string{"record", "id", "endpoint_id", "hostname", "package_id", "state", "owner", "reason_or_detail", "compensating_controls", "approver", "opened", "expires_or_updated", "attempts"})
			host := map[string]string{}
			for _, e := range in.Endpoints {
				host[e.EndpointID] = e.Hostname
			}
			for _, x := range pk.Exceptions {
				c.row("exception", x.ExceptionID, x.EndpointID, x.Scope, x.PackageID, x.Status, x.Owner, x.Reason, x.CompensatingControls, x.Approver, x.Opened, x.Expires, "")
			}
			for _, t := range in.Targets {
				if t.State == "failed" || t.State == "lost_after_install" {
					if t.DeploymentState == "cancelled" {
						continue
					}
					c.row("failure", t.DeploymentID, t.EndpointID, host[t.EndpointID], t.PackageID, t.State, "", t.Detail, "", "", "", t.UpdatedAt, strconv.Itoa(t.Attempts))
				}
			}
			for _, d := range in.Deployments {
				if d.Operation == "rollback" && (inPeriod(in, d.CreatedAt) || inPeriod(in, d.ActivatedAt)) {
					c.row("rollback", d.DeploymentID, "", "", d.PackageID, d.State, d.CreatedBy, d.Justification, "", approverList(d), d.CreatedAt, d.UpdatedAt, "")
				}
			}
			for _, e := range in.BackupEvents {
				c.row("backup", strconv.FormatInt(e.Seq, 10), "", "", "", e.Action, e.Actor, string(e.Details), "", "", e.TS, "", "")
			}
		}
	case "E-009":
		return func(c *csvOut) {
			c.w.Write([]string{"record", "seq_or_user", "ts_or_role", "actor_or_auth", "action_or_mfa", "object", "outcome_or_disabled", "details", "hash"})
			for _, u := range in.Users {
				mfa := u.MFA || u.MFAEnrolled
				c.row("account", u.Username, u.Role, u.Auth, "mfa="+b2s(mfa), "last_login="+u.LastLogin, b2s(u.Disabled), "", "")
			}
			for _, e := range in.PrivilegedEvents {
				c.row("event", strconv.FormatInt(e.Seq, 10), e.TS, e.Actor, e.Action, e.ObjectType+":"+e.ObjectID, e.Outcome, string(e.Details), e.Hash)
			}
		}
	case "E-010":
		return func(c *csvOut) {
			c.w.Write([]string{"record", "seq_or_version", "ts", "actor", "action", "object", "details"})
			for _, e := range in.ReportEvents {
				c.row("report_event", strconv.FormatInt(e.Seq, 10), e.TS, e.Actor, e.Action, e.ObjectID, string(e.Details))
			}
			for _, h := range in.ProfileHistory {
				c.row("profile_version", strconv.Itoa(h.Version), h.EditedAt, h.EditedBy, "report.profile_updated", "sha256="+h.SHA256, "")
			}
			for _, f := range pk.Findings {
				c.row("finding", f.ID, "", f.Owner, f.Status, f.Control, f.Title+" — due "+f.DueDate)
			}
		}
	}
	return nil
}

func approverList(d store.Deployment) string {
	var by []string
	for _, a := range d.Approvals {
		by = append(by, a.By)
	}
	return strings.Join(by, "; ")
}

// WriteEvidence writes evidence file id to w and returns its rows and
// SHA-256 (hex).
func (pk *Pack) WriteEvidence(id string, w io.Writer) (int, string, error) {
	fn := pk.evidenceWriter(id)
	if fn == nil {
		return 0, "", fmt.Errorf("unknown evidence %s", id)
	}
	h := sha256.New()
	cw := csv.NewWriter(io.MultiWriter(w, h))
	c := &csvOut{w: cw}
	fn(c)
	cw.Flush()
	return c.rows, hex.EncodeToString(h.Sum(nil)), cw.Error()
}

// EvidenceFiles lists the evidence file paths in the package, by ID.
func EvidenceFiles() map[string]string {
	out := map[string]string{}
	for _, d := range evidenceDefs {
		out[d.id] = d.file
	}
	return out
}

func (pk *Pack) evidencePeriod() string {
	return pk.Meta.Period.From + " to " + pk.Meta.Period.To
}

// register builds the evidence register (§6) with the hash of each file.
func (pk *Pack) register() ([]Evidence, error) {
	in := pk.in
	conf := in.Profile.Profile.ConfidentialityClass
	if in.Redact {
		conf += " (redacted: hostnames, IP addresses and user IDs pseudonymized)"
	}
	var out []Evidence
	for _, d := range evidenceDefs {
		rows, sum, err := pk.WriteEvidence(d.id, io.Discard)
		if err != nil {
			return nil, err
		}
		e := Evidence{ID: d.id, Item: d.item, SourceSystem: Product + " " + in.ProductVersion, Period: pk.evidencePeriod(), SHA256: sum, Records: rows,
			Confidentiality: conf, Included: d.file}
		switch d.id {
		case "E-001":
			pol := in.Profile.Profile.Policy
			e.SourceSystem = Product + " report profile (version " + strconv.Itoa(in.Profile.Version) + ")"
			e.Period = "version " + orDash(pol.Version) + ", approved " + orDash(pol.ApprovedAt)
			e.Scope = "organisation"
			e.Complete = pol.ApprovedBy != "" || pol.Reference != ""
			if pol.Reference != "" {
				e.Included = d.file + "; policy document: " + pol.Reference
			}
			e.Note = "Deadline table and policy record; the policy document itself is referenced, not included."
		case "E-002":
			e.Period = "as of " + pk.Timeliness.AsOf
			e.Scope = plural(pk.ExecutiveSummary.InScopeEndpoints, "endpoint", "endpoints") + " in scope (population, not a sample)"
			e.Complete = pk.ExecutiveSummary.InScopeEndpoints > 0
			e.Note = "Per-endpoint software inventory is available in the console (endpoint detail) and is not exported here."
		case "E-003":
			e.Scope = plural(len(in.Packages), "catalog package", "catalog packages")
			e.Complete = len(in.Packages) > 0
		case "E-004":
			e.Scope = "bundles and receipts received in the period"
			e.Complete = rows > 0
		case "E-005":
			e.Scope = "bundles received in the period"
			e.Complete = rows > 0
		case "E-006":
			e.Scope = "deployments created or activated in the period"
			e.Complete = rows > 0
			e.Note = "Pilot ring order is in the rings column; test results are recorded outside the product (PM-08)."
		case "E-007":
			e.Scope = plural(len(pk.pairs), "endpoint/update pair", "endpoint/update pairs") + " (population)"
			e.Complete = len(pk.pairs) > 0
		case "E-008":
			e.Scope = "exceptions, failed targets, rollbacks and backups"
			e.Complete = true // every failure and exception is recorded; none is a valid population
		case "E-009":
			e.Scope = "privileged accounts and actions"
			e.Complete = in.Chain.OK && len(in.Users) > 0
			if in.PrivilegedTruncated {
				e.Note = "Event list truncated; the full trail is in the signed audit export."
			}
		case "E-010":
			e.Scope = "report history, profile versions and findings"
			m := in.Profile.Profile.ManualControls["PM-15"]
			e.Complete = len(in.ReportEvents) > 0 || m.EvidenceRef != ""
			if m.EvidenceRef != "" {
				e.Included = d.file + "; governance pack: " + m.EvidenceRef
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func (pk *Pack) exceptionRows() []ExceptionRow {
	in := pk.in
	host := map[string]string{}
	for _, e := range in.Endpoints {
		host[e.EndpointID] = e.Hostname
	}
	out := []ExceptionRow{}
	for _, x := range in.Exceptions {
		st := "Active"
		switch {
		case x.Revoked:
			st = "Revoked"
		case !x.Active:
			st = "Expired"
		}
		// Exceptions of interest: active now, or opened / expiring in the period.
		if st != "Active" && !inPeriod(in, x.CreatedAt) && !inPeriod(in, x.ExpiresAt) {
			continue
		}
		patch := x.PackageID
		if patch == "" {
			patch = "all updates"
		}
		out = append(out, ExceptionRow{ExceptionID: x.ExceptionID, EndpointID: x.EndpointID, Scope: orDash(host[x.EndpointID]), PackageID: x.PackageID, Patch: patch,
			Reason: x.Reason, CompensatingControls: x.CompensatingControls, Owner: x.Owner, Approver: x.CreatedBy, Opened: dateOf(x.CreatedAt, in.Loc),
			Expires: dateOf(x.ExpiresAt, in.Loc), Status: st})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Opened < out[j].Opened })
	return out
}

func dateOf(ts string, loc *time.Location) string {
	t := parseTS(ts)
	if t.IsZero() {
		return ts
	}
	return t.In(loc).Format("2006-01-02")
}
