package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Report profile: the organisation facts the auditor compliance report
// needs and the product cannot know (legal entity, regulators, policy
// approval, reviewed regulatory mappings, manual control conclusions,
// sign-off). Every save is a new version (who, when, SHA-256), audited
// report.profile_updated; the report records the version it used.
// See docs/10-compliance-report.md.

const reportProfileSchema = `CREATE TABLE IF NOT EXISTS report_profiles(
  version INTEGER PRIMARY KEY, profile TEXT NOT NULL, sha256 TEXT NOT NULL,
  edited_by TEXT NOT NULL, edited_at TEXT NOT NULL)`

// Status values of a control, mapping or the overall assessment (template §2.4).
const (
	StatusCompliant     = "Compliant"
	StatusPartial       = "Partially compliant"
	StatusNonCompliant  = "Non-compliant"
	StatusNotApplicable = "Not applicable"
	StatusNotAssessed   = "Not assessed"
)

// ControlStatuses lists the status values in template order.
var ControlStatuses = []string{StatusCompliant, StatusPartial, StatusNonCompliant, StatusNotApplicable, StatusNotAssessed}

// Regulators selectable in the profile.
var Regulators = []string{"RBI", "SEBI", "IRDAI", "PFRDA", "MeitY", "CERT-In", "other"}

// Deadline priorities, most urgent first, and clock start definitions.
var (
	DeadlinePriorities = []string{"emergency", "critical", "high", "moderate", "low"}
	ClockStarts        = []string{"release", "acquired", "approved"}
)

// ControlIDs are the template's common control matrix rows.
var ControlIDs = func() []string {
	out := make([]string, 17)
	for i := range out {
		out[i] = fmt.Sprintf("PM-%02d", i+1)
	}
	return out
}()

type ReportExclusion struct {
	System     string `json:"system"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
	ReviewDate string `json:"review_date"`
}

type OfflineModel struct {
	AcquisitionZone  string `json:"acquisition_zone"`
	TransferBoundary string `json:"transfer_boundary"`
	Quarantine       string `json:"quarantine"`
	Repository       string `json:"repository"`
	EndpointComms    string `json:"endpoint_comms"`
	EgressEvidence   string `json:"egress_evidence"`
}

// DeadlineRule: the organisation's maximum time for a priority.
type DeadlineRule struct {
	Priority         string `json:"priority"` // emergency | critical | high | moderate | low
	MaxDays          int    `json:"max_days"`
	Source           string `json:"source"`
	ClockStart       string `json:"clock_start"` // release | acquired | approved
	ExceptionProcess string `json:"exception_process"`
}

type PolicyRecord struct {
	Version    string `json:"version"`
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"`
	ReviewDate string `json:"review_date"`
	Reference  string `json:"reference"`
}

// RegulatoryMapping is a CANDIDATE mapping until a reviewer confirms
// applicability (applicable yes|no) and records a result.
type RegulatoryMapping struct {
	Framework   string `json:"framework"`
	Instrument  string `json:"instrument"`
	Expectation string `json:"expectation"`
	Evidence    string `json:"evidence"`
	ClauseRef   string `json:"clause_ref"`
	Applicable  string `json:"applicable"` // yes | no | unknown
	Rationale   string `json:"rationale"`
	Reviewer    string `json:"reviewer"`
	ReviewedAt  string `json:"reviewed_at"`
	Result      string `json:"result"` // a status value or ""
	Notes       string `json:"notes"`
}

type Signoff struct {
	Role     string `json:"role"`
	Name     string `json:"name"`
	Comments string `json:"comments"`
	Date     string `json:"date"`
}

// ManualControl: a reviewer's conclusion for a control the product cannot
// evidence (or extra evidence for one it can).
type ManualControl struct {
	Status      string `json:"status"`
	EvidenceRef string `json:"evidence_ref"`
	Note        string `json:"note"`
}

// AssessmentOverride replaces the computed overall assessment when set.
type AssessmentOverride struct {
	Status    string `json:"status"`
	Rationale string `json:"rationale"`
}

type ReportProfile struct {
	LegalEntity          string                   `json:"legal_entity"`
	RegulatedActivity    string                   `json:"regulated_activity"`
	Regulators           []string                 `json:"regulators"`
	EntityCategory       string                   `json:"entity_category"`
	AssessmentOwner      string                   `json:"assessment_owner"`
	IndependentReviewer  string                   `json:"independent_reviewer"`
	SystemsInScope       string                   `json:"systems_in_scope"`
	EndpointTypes        string                   `json:"endpoint_types"`
	Exclusions           []ReportExclusion        `json:"exclusions"`
	OfflineModel         OfflineModel             `json:"offline_model"`
	Deadlines            []DeadlineRule           `json:"deadlines"`
	Policy               PolicyRecord             `json:"policy"`
	RegulatoryMappings   []RegulatoryMapping      `json:"regulatory_mappings"`
	Signoff              []Signoff                `json:"signoff"`
	ScopeLimitations     string                   `json:"scope_limitations"`
	ManagementResponse   string                   `json:"management_response"`
	ManualControls       map[string]ManualControl `json:"manual_controls"`
	OverallAssessment    AssessmentOverride       `json:"overall_assessment"`
	ConfidentialityClass string                   `json:"confidentiality_class"`
}

// ReportProfileRecord is one stored version (version 0: the defaults,
// nothing saved yet).
type ReportProfileRecord struct {
	Version   int           `json:"version"`
	EditedBy  string        `json:"edited_by"`
	EditedAt  string        `json:"edited_at"`
	SHA256    string        `json:"sha256"`
	IsDefault bool          `json:"is_default"`
	Profile   ReportProfile `json:"profile"`
}

// ReportProfileVersion is a history entry (no profile body).
type ReportProfileVersion struct {
	Version  int    `json:"version"`
	EditedBy string `json:"edited_by"`
	EditedAt string `json:"edited_at"`
	SHA256   string `json:"sha256"`
}

// DefaultExceptionProcess describes the product's exception record.
const DefaultExceptionProcess = "Approved exception in DSS Patcher (owner, reason, compensating controls, expiry), approved by a bank admin"

// TemplateMappings are the template §4 rows: candidate mappings, applicable
// "unknown" until a compliance reviewer decides.
var TemplateMappings = []RegulatoryMapping{
	{Framework: "RBI", Instrument: "Master Direction on Information Technology Governance, Risk, Controls and Assurance Practices, 2023",
		Expectation: "For entities within scope, documented change and patch management should assess business impact of applying or not applying patches, ensure secure and timely implementation with necessary approvals, and provide recovery from failed deployment or unexpected results. Audit trails should support audit and forensic use.",
		Evidence:    "Policy and procedures; impact/risk assessment; approvals; test and deployment records; rollback/recovery evidence; audit events."},
	{Framework: "RBI", Instrument: "Master Directions on Cyber Resilience and Digital Payment Security Controls for non-bank Payment System Operators, 2024",
		Expectation: "For in-scope non-bank PSOs, maintain patch/change lifecycle controls, apply relevant security patches within appropriate timelines, rapidly address critical patches, and test/validate production changes.",
		Evidence:    "Patch policy; risk/timeline record; emergency patch record; test evidence; production deployment; endpoint verification."},
	{Framework: "SEBI", Instrument: "Cybersecurity and Cyber Resilience Framework (CSCRF), 2024 and subsequent circulars/FAQs",
		Expectation: "The framework includes patch-management expectations for applicable SEBI regulated entities, including approved/reviewed policy, patch compliance tracking/reporting, post-patch performance, and stated maximum timelines by patch criticality in the framework. Entity category and subsequent clarifications must be checked.",
		Evidence:    "Approved patch policy and review; asset coverage; patch criticality and dates; compliance reports to IT Committee; post-update performance; DC/DR coverage where applicable."},
	{Framework: "IRDAI", Instrument: "Information and Cyber Security Guidelines (including 2023 guidance and applicable amendments)",
		Expectation: "Cybersecurity controls and assurance requirements may apply to insurers and insurance intermediaries; map current requirements for the specific entity and scope.",
		Evidence:    "Patch process, asset/vulnerability records, testing, audit checklist, corrective actions, evidence of governance."},
	{Framework: "CERT-In", Instrument: "Directions under Section 70B(6), dated 28 April 2022, and FAQs/amendments",
		Expectation: "These directions address cybersecurity practices, incident prevention/response/reporting, and specified log requirements. They are not a patch-timeline standard by themselves; patch records can support investigation and incident response.",
		Evidence:    "Relevant security logs and audit trails, incident evidence, time synchronization/logging evidence where applicable, vulnerability/patch context."},
	{Framework: "MeitY", Instrument: "Guidelines on Information Security Practices for Government Entities",
		Expectation: "For government entities within scope, guidance explicitly discusses current security patches, regular or critical patching, vulnerability assessment, and patch-management solutions/manual update processes for devices that cannot auto-update.",
		Evidence:    "Patch policy, inventory, vulnerability scans, deployment records, manual update process and exceptions."},
	{Framework: "PFRDA", Instrument: "PFRDA / other sector-specific regulator or critical-sector direction",
		Expectation: "Requirements may exist for the entity type, central recordkeeping agencies, critical infrastructure, or other regulated systems. Add the exact applicable instrument rather than relying on this generic row.",
		Evidence:    ""},
}

// DefaultSignoffRoles are the template §8 rows.
var DefaultSignoffRoles = []string{"Patch management owner", "Information security / CISO delegate", "Compliance/legal reviewer", "Independent auditor"}

// severityPriority maps the catalog severity to the deadline priority.
var severityPriority = map[string]string{"critical": "critical", "important": "high", "moderate": "moderate", "low": "low"}

// PriorityForSeverity is the deadline priority of a catalog severity
// (unknown severities are treated as critical: never a laxer deadline).
func PriorityForSeverity(sev string) string {
	if p, ok := severityPriority[sev]; ok {
		return p
	}
	return "critical"
}

func durationDays(d time.Duration) int {
	n := int((d + 24*time.Hour - 1) / (24 * time.Hour))
	if n < 1 {
		n = 1
	}
	return n
}

// DefaultDeadlineRules derives the deadline table from the configured
// patch_deadlines (emergency uses the critical deadline).
func (p Policy) DefaultDeadlineRules() []DeadlineRule {
	sevFor := map[string]string{"emergency": "critical", "critical": "critical", "high": "important", "moderate": "moderate", "low": "low"}
	out := make([]DeadlineRule, 0, len(DeadlinePriorities))
	for _, pr := range DeadlinePriorities {
		src := "DSS Patcher configured deadline (patch_deadlines." + sevFor[pr] + "); confirm against the approved entity policy"
		if pr == "emergency" {
			src = "DSS Patcher default: the critical deadline (no separate emergency deadline configured); confirm against the approved entity policy"
		}
		out = append(out, DeadlineRule{Priority: pr, MaxDays: durationDays(p.deadline(sevFor[pr])), Source: src, ClockStart: "release", ExceptionProcess: DefaultExceptionProcess})
	}
	return out
}

// DefaultReportProfile: deadlines from the policy, the template's
// regulatory rows (applicable unknown) and sign-off roles, nothing else.
func (p Policy) DefaultReportProfile() ReportProfile {
	rp := ReportProfile{Regulators: []string{}, Exclusions: []ReportExclusion{}, Deadlines: p.DefaultDeadlineRules(),
		RegulatoryMappings: make([]RegulatoryMapping, len(TemplateMappings)), Signoff: []Signoff{},
		ManualControls: map[string]ManualControl{}, ConfidentialityClass: "Confidential"}
	for i, m := range TemplateMappings {
		m.Applicable = "unknown"
		rp.RegulatoryMappings[i] = m
	}
	for _, r := range DefaultSignoffRoles {
		rp.Signoff = append(rp.Signoff, Signoff{Role: r})
	}
	return rp
}

// DeadlineFor returns the rule for a priority (the profile's, else the
// policy default).
func (rp ReportProfile) DeadlineFor(p Policy, priority string) DeadlineRule {
	for _, d := range rp.Deadlines {
		if d.Priority == priority {
			return d
		}
	}
	for _, d := range p.DefaultDeadlineRules() {
		if d.Priority == priority {
			return d
		}
	}
	return DeadlineRule{Priority: priority, MaxDays: 7, ClockStart: "release"}
}

const (
	maxProfileText  = 8000
	maxProfileItems = 200
)

func validDate(s string) bool {
	if s == "" {
		return true
	}
	if _, err := time.Parse("2006-01-02", s); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func oneOf(v string, set []string) (string, bool) {
	for _, s := range set {
		if strings.EqualFold(v, s) {
			return s, true
		}
	}
	return v, false
}

// Normalize validates the profile and fills defaults (missing deadline
// priorities, clock start, applicable "unknown", maps and slices).
func (rp *ReportProfile) Normalize(p Policy) error {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	// Length limits on every string field (reflection keeps this complete).
	var walk func(v reflect.Value, path string)
	walk = func(v reflect.Value, path string) {
		switch v.Kind() {
		case reflect.String:
			v.SetString(strings.TrimSpace(v.String()))
			if len(v.String()) > maxProfileText {
				bad("%s: at most %d characters", path, maxProfileText)
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				walk(v.Field(i), path+"."+v.Type().Field(i).Tag.Get("json"))
			}
		case reflect.Slice:
			if v.Len() > maxProfileItems {
				bad("%s: at most %d entries", path, maxProfileItems)
			}
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(reflect.ValueOf(rp).Elem(), "profile")

	regs := []string{}
	for _, r := range rp.Regulators {
		c, ok := oneOf(r, Regulators)
		if !ok {
			bad("regulators: %q is not one of %s", r, strings.Join(Regulators, ", "))
			continue
		}
		if !contains(regs, c) {
			regs = append(regs, c)
		}
	}
	rp.Regulators = regs
	if rp.Exclusions == nil {
		rp.Exclusions = []ReportExclusion{}
	}
	for i, x := range rp.Exclusions {
		if x.System == "" || x.Reason == "" {
			bad("exclusions[%d]: system and reason are required", i)
		}
		if !validDate(x.ReviewDate) {
			bad("exclusions[%d].review_date: use YYYY-MM-DD", i)
		}
	}
	seen := map[string]bool{}
	deadlines := []DeadlineRule{}
	for i, d := range rp.Deadlines {
		pr, ok := oneOf(d.Priority, DeadlinePriorities)
		if !ok {
			bad("deadlines[%d].priority: %q is not one of %s", i, d.Priority, strings.Join(DeadlinePriorities, ", "))
			continue
		}
		if seen[pr] {
			bad("deadlines: priority %s given twice", pr)
			continue
		}
		seen[pr] = true
		d.Priority = pr
		if d.MaxDays < 1 || d.MaxDays > 3650 {
			bad("deadlines[%d].max_days: 1-3650", i)
		}
		if d.ClockStart == "" {
			d.ClockStart = "release"
		}
		if c, ok := oneOf(d.ClockStart, ClockStarts); ok {
			d.ClockStart = c
		} else {
			bad("deadlines[%d].clock_start: one of %s", i, strings.Join(ClockStarts, ", "))
		}
		deadlines = append(deadlines, d)
	}
	for _, d := range p.DefaultDeadlineRules() {
		if !seen[d.Priority] {
			deadlines = append(deadlines, d)
		}
	}
	order := map[string]int{}
	for i, pr := range DeadlinePriorities {
		order[pr] = i
	}
	sort.SliceStable(deadlines, func(i, j int) bool { return order[deadlines[i].Priority] < order[deadlines[j].Priority] })
	rp.Deadlines = deadlines
	for _, f := range []struct{ name, v string }{{"policy.approved_at", rp.Policy.ApprovedAt}, {"policy.review_date", rp.Policy.ReviewDate}} {
		if !validDate(f.v) {
			bad("%s: use YYYY-MM-DD", f.name)
		}
	}
	if rp.RegulatoryMappings == nil {
		rp.RegulatoryMappings = []RegulatoryMapping{}
	}
	for i := range rp.RegulatoryMappings {
		m := &rp.RegulatoryMappings[i]
		if m.Framework == "" {
			bad("regulatory_mappings[%d].framework is required", i)
		}
		if m.Applicable == "" {
			m.Applicable = "unknown"
		}
		if a, ok := oneOf(m.Applicable, []string{"yes", "no", "unknown"}); ok {
			m.Applicable = a
		} else {
			bad("regulatory_mappings[%d].applicable: yes, no or unknown", i)
		}
		if m.Result != "" {
			if r, ok := oneOf(m.Result, ControlStatuses); ok {
				m.Result = r
			} else {
				bad("regulatory_mappings[%d].result: one of %s", i, strings.Join(ControlStatuses, ", "))
			}
		}
		if !validDate(m.ReviewedAt) {
			bad("regulatory_mappings[%d].reviewed_at: use YYYY-MM-DD", i)
		}
	}
	if rp.Signoff == nil {
		rp.Signoff = []Signoff{}
	}
	for i, so := range rp.Signoff {
		if so.Role == "" {
			bad("signoff[%d].role is required", i)
		}
		if !validDate(so.Date) {
			bad("signoff[%d].date: use YYYY-MM-DD", i)
		}
	}
	if rp.ManualControls == nil {
		rp.ManualControls = map[string]ManualControl{}
	}
	mc := map[string]ManualControl{}
	for id, c := range rp.ManualControls {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !contains(ControlIDs, id) {
			bad("manual_controls: %q is not a control id (PM-01..PM-17)", id)
			continue
		}
		c.Status, c.EvidenceRef, c.Note = strings.TrimSpace(c.Status), strings.TrimSpace(c.EvidenceRef), strings.TrimSpace(c.Note)
		if c.Status != "" {
			if st, ok := oneOf(c.Status, ControlStatuses); ok {
				c.Status = st
			} else {
				bad("manual_controls.%s.status: one of %s", id, strings.Join(ControlStatuses, ", "))
			}
		}
		if len(c.EvidenceRef) > maxProfileText || len(c.Note) > maxProfileText {
			bad("manual_controls.%s: at most %d characters per field", id, maxProfileText)
		}
		if c.Status != "" || c.EvidenceRef != "" || c.Note != "" {
			mc[id] = c
		}
	}
	rp.ManualControls = mc
	if rp.OverallAssessment.Status != "" {
		if st, ok := oneOf(rp.OverallAssessment.Status, ControlStatuses); ok && st != StatusNotApplicable {
			rp.OverallAssessment.Status = st
		} else {
			bad("overall_assessment.status: Compliant, Partially compliant, Non-compliant or Not assessed")
		}
	}
	if rp.ConfidentialityClass == "" {
		rp.ConfidentialityClass = "Confidential"
	}
	if len(errs) > 0 {
		return Errf(ErrInvalid, "%s", strings.Join(errs, "; "))
	}
	return nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func profileHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// GetReportProfile returns the latest saved version, or version 0 (the
// defaults) when none was saved.
func (s *Store) GetReportProfile(ctx context.Context) (ReportProfileRecord, error) {
	return s.reportProfile(ctx, `SELECT version, profile, sha256, edited_by, edited_at FROM report_profiles ORDER BY version DESC LIMIT 1`)
}

// GetReportProfileVersion returns one saved version (ErrNotFound).
func (s *Store) GetReportProfileVersion(ctx context.Context, version int) (ReportProfileRecord, error) {
	r, err := s.reportProfile(ctx, `SELECT version, profile, sha256, edited_by, edited_at FROM report_profiles WHERE version=?`, version)
	if err == nil && r.IsDefault {
		return r, Errf(ErrNotFound, "report profile version %d", version)
	}
	return r, err
}

func (s *Store) reportProfile(ctx context.Context, q string, args ...any) (ReportProfileRecord, error) {
	var r ReportProfileRecord
	var body string
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&r.Version, &body, &r.SHA256, &r.EditedBy, &r.EditedAt)
	if errors.Is(err, sql.ErrNoRows) {
		rp := s.Policy.DefaultReportProfile()
		b, _ := json.Marshal(rp)
		return ReportProfileRecord{IsDefault: true, Profile: rp, SHA256: profileHash(b)}, nil
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal([]byte(body), &r.Profile); err != nil {
		return r, fmt.Errorf("report profile version %d: %w", r.Version, err)
	}
	// Deadlines added to the policy later, nil maps from older versions.
	if err := r.Profile.Normalize(s.Policy); err != nil {
		return r, fmt.Errorf("stored report profile version %d no longer validates: %w", r.Version, err)
	}
	return r, nil
}

// ReportProfileHistory lists saved versions, newest first.
func (s *Store) ReportProfileHistory(ctx context.Context) ([]ReportProfileVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version, sha256, edited_by, edited_at FROM report_profiles ORDER BY version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportProfileVersion{}
	for rows.Next() {
		var v ReportProfileVersion
		if err := rows.Scan(&v.Version, &v.SHA256, &v.EditedBy, &v.EditedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// changedFields names the top-level profile fields that differ.
func changedFields(a, b ReportProfile) []string {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	var out []string
	for i := 0; i < va.NumField(); i++ {
		if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			out = append(out, va.Type().Field(i).Tag.Get("json"))
		}
	}
	return out
}

// SaveReportProfile validates and stores rp as a new version. baseVersion
// >= 0 makes it conditional: 409 if another version was saved since (-1 =
// unconditional).
func (s *Store) SaveReportProfile(ctx context.Context, actor string, rp ReportProfile, baseVersion int) (ReportProfileRecord, error) {
	if err := rp.Normalize(s.Policy); err != nil {
		return ReportProfileRecord{}, err
	}
	b, err := json.Marshal(rp)
	if err != nil {
		return ReportProfileRecord{}, err
	}
	rec := ReportProfileRecord{EditedBy: actor, EditedAt: s.now(), SHA256: profileHash(b), Profile: rp}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var last int
		var prevBody string
		err := tx.QueryRow(`SELECT version, profile FROM report_profiles ORDER BY version DESC LIMIT 1`).Scan(&last, &prevBody)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if baseVersion >= 0 && baseVersion != last {
			return Errf(ErrConflict, "the report profile was changed (version %d) since you loaded version %d; reload it", last, baseVersion)
		}
		prev := s.Policy.DefaultReportProfile()
		if prevBody != "" {
			json.Unmarshal([]byte(prevBody), &prev)
			prev.Normalize(s.Policy)
		}
		rec.Version = last + 1
		if _, err := tx.Exec(`INSERT INTO report_profiles(version, profile, sha256, edited_by, edited_at) VALUES(?,?,?,?,?)`,
			rec.Version, string(b), rec.SHA256, actor, rec.EditedAt); err != nil {
			return err
		}
		changed := changedFields(prev, rp)
		if changed == nil {
			changed = []string{}
		}
		return s.audit(tx, Ev{Actor: actor, Action: "report.profile_updated", ObjectType: "report_profile", ObjectID: fmt.Sprint(rec.Version),
			Details: map[string]any{"version": rec.Version, "sha256": rec.SHA256, "previous_version": last, "changed": changed}})
	})
	return rec, err
}
