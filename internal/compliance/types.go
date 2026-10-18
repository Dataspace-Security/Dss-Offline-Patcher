// Package compliance builds the auditor compliance report (the owner's
// "Patch Management Compliance Report" template, docs/10-compliance-
// report.md) from product data and the organisation's report profile: the
// JSON pack (GET /api/reports/compliance-pack), the filled Markdown report,
// evidence CSVs and a signed ZIP package.
//
// Principles from the template, enforced here: regulatory rows are
// candidate mappings until a reviewer concludes; missing or stale
// telemetry is never compliant; exceptions are reported separately and
// never counted as patched; every number comes from dated evidence and
// data gaps are disclosed.
package compliance

import (
	"time"

	"offpatch/internal/store"
)

// Product is the product name used in the report.
const Product = "DSS Patcher"

// Title is the report title (template heading).
const Title = "Patch Management Compliance Report"

// Disclaimer is the template's "Important" note, verbatim.
const Disclaimer = "This report organizes operational evidence and maps it to selected regulatory requirements. It is not a legal opinion, regulator approval, audit opinion, or certification of compliance. Applicability depends on the entity type, regulator, system scope, current circulars and directions, and any supervisory instructions. The organization’s compliance/legal team and auditor must validate the mapping and conclusions before relying on it."

// MappingBaselineDate is the template's "Regulatory review date": when the
// candidate mapping rows were prepared.
const MappingBaselineDate = "18 October 2026"

// NotAssessedReview is the conclusion of a mapping nobody reviewed yet.
const NotAssessedReview = "Not assessed — needs compliance review"

// Severities of findings, most severe first.
const (
	SevCritical = "Critical"
	SevHigh     = "High"
	SevMedium   = "Medium"
	SevLow      = "Low"
)

// Pair outcomes (template §5.2), plus verified_late: installed and
// verified, but after the deadline (a policy breach in the period).
const (
	OutcomeCompliant     = "compliant"
	OutcomeVerifiedLate  = "verified_late"
	OutcomeOverdue       = "overdue"
	OutcomePending       = "pending"
	OutcomeFailed        = "failed"
	OutcomeOffline       = "offline"
	OutcomeNotApplicable = "not_applicable"
	OutcomeException     = "exception"
)

// Outcomes in display order.
var Outcomes = []string{OutcomeCompliant, OutcomeVerifiedLate, OutcomeOverdue, OutcomePending, OutcomeFailed, OutcomeOffline, OutcomeException, OutcomeNotApplicable}

// User is who generated the report.
type User struct {
	User string `json:"user"`
	Role string `json:"role"`
}

// Settings are the server settings the controls look at.
type Settings struct {
	SeparationOfDuties   bool
	DeploymentApprovals  int
	ApprovalPolicy       map[string]int
	RequireMFA           bool
	SSO                  bool
	TLS                  bool
	MTLSAgents           bool
	InsecureHTTP         bool
	ScannerConfigured    bool
	AuditExportDir       bool
	AuditExportedSeq     int64
	AuditRetention       time.Duration
	AuditCheckpointEvery time.Duration
	OfflineAfter         time.Duration
	StaleAfter           time.Duration
}

// Input is everything Build reads. The server fills it (cached fleet views
// where they exist); Build does not touch the database.
type Input struct {
	Now            time.Time      // generation time
	Loc            *time.Location // report time zone (dates and generated_at)
	From, To       time.Time      // period [From, To): To is the day after the last day
	GeneratedBy    User
	ProductVersion string
	Redact         bool
	Filters        map[string]string
	Policy         store.Policy
	Profile        store.ReportProfileRecord
	ProfileHistory []store.ReportProfileVersion

	Endpoints    []store.Endpoint    // with honest status and Missing
	Packages     []store.Package     // with approvals
	Targets      []store.PackTarget  // every deployment target
	InstallTimes map[string]string   // "deployment/endpoint" → first installed report
	Needs        map[string][]string // package → endpoints that need it (inventory)
	Exceptions   []store.Exception
	Deployments  []store.Deployment // with approvals
	Bundles      []store.Bundle
	Receipts     []store.TransferReceipt
	Acquisitions []store.AcqRecord // received in the period
	Users        []store.User
	IntelAge     *store.IntelAge

	Chain               store.ChainResult
	AuditHeadSeq        int64
	PrivilegedEvents    []store.AuditEvent // privileged actions in the period
	PrivilegedTruncated bool
	DeploymentEvents    []store.AuditEvent // deployment.* in the period
	ReportEvents        []store.AuditEvent // report.* in the period
	BackupEvents        []store.AuditEvent // backup.* (any time)

	Settings Settings
}

// ---- the pack (GET /api/reports/compliance-pack) ----

type Pack struct {
	Meta               Meta                `json:"meta"`
	Disclaimer         string              `json:"disclaimer"`
	Profile            store.ReportProfile `json:"profile"`
	ProfileVersion     ProfileRef          `json:"profile_version"`
	ExecutiveSummary   ExecutiveSummary    `json:"executive_summary"`
	OverallAssessment  Assessment          `json:"overall_assessment"`
	KeyFindings        []Finding           `json:"key_findings"`
	Scope              Scope               `json:"scope"`
	Controls           []Control           `json:"controls"`
	RegulatoryMappings []Mapping           `json:"regulatory_mappings"`
	Timeliness         Timeliness          `json:"timeliness"`
	EvidenceRegister   []Evidence          `json:"evidence_register"`
	Findings           []Finding           `json:"findings"`
	Exceptions         []ExceptionRow      `json:"exceptions"`
	Signoff            []store.Signoff     `json:"signoff"`
	ScopeLimitations   ScopeLimitations    `json:"scope_limitations"`
	ManagementResponse string              `json:"management_response"`
	References         []Reference         `json:"references"`
	AuditChain         AuditChain          `json:"audit_chain"`

	pairs []pair // full population (evidence CSV); Timeliness.Pairs is a sample
	in    *Input
}

type Period struct {
	From     string `json:"from"`  // YYYY-MM-DD, first day
	To       string `json:"to"`    // YYYY-MM-DD, last day (inclusive)
	AsOf     string `json:"as_of"` // RFC 3339: state evaluated at min(generated_at, end of period)
	Timezone string `json:"timezone"`
}

type Meta struct {
	ReportID             string            `json:"report_id"`
	Title                string            `json:"title"`
	Product              string            `json:"product"`
	ProductVersion       string            `json:"product_version"`
	GeneratedAt          string            `json:"generated_at"` // RFC 3339 with the report time zone offset
	GeneratedBy          User              `json:"generated_by"`
	Period               Period            `json:"period"`
	Filters              map[string]string `json:"filters"`
	Redacted             bool              `json:"redacted"`
	ReportType           string            `json:"report_type"`
	ControlDomain        string            `json:"control_domain"`
	CoverageModel        string            `json:"coverage_model"`
	DocumentStatus       string            `json:"document_status"`
	RegulatoryReviewDate string            `json:"regulatory_review_date"`
	PreparedFor          string            `json:"prepared_for"`
}

type ProfileRef struct {
	Version   int    `json:"version"`
	EditedBy  string `json:"edited_by"`
	EditedAt  string `json:"edited_at"`
	SHA256    string `json:"sha256"`
	IsDefault bool   `json:"is_default"`
}

type CountPct struct {
	Count int     `json:"count"`
	Pct   float64 `json:"pct"` // of in_scope_endpoints; 0 when there are none
}

type ExecutiveSummary struct {
	InScopeEndpoints        int            `json:"in_scope_endpoints"`
	CurrentInventory        CountPct       `json:"current_inventory"`
	CompliantWithPolicy     CountPct       `json:"compliant_with_policy"`
	Overdue                 CountPct       `json:"overdue"`
	StaleInventory          CountPct       `json:"stale_inventory"`
	PendingRestart          int            `json:"pending_restart"`
	ActiveExceptions        int            `json:"active_exceptions"`
	EmergencyOpenPastTarget int            `json:"emergency_open_past_target"`
	FindingsBySeverity      map[string]int `json:"findings_by_severity"` // critical, high, medium, low
	EvidenceCompletenessPct float64        `json:"evidence_completeness_pct"`
}

// Assessment: Status is what the report shows (the profile's override, or
// the computed suggestion); Suggested is always the computed one.
type Assessment struct {
	Status             string `json:"status"`
	Rationale          string `json:"rationale"`
	Source             string `json:"source"` // computed | profile
	Suggested          string `json:"suggested"`
	SuggestedRationale string `json:"suggested_rationale"`
}

// Scope is the computed part of template §2.1.
type Scope struct {
	EndpointsTotal     int      `json:"endpoints_total"`  // enrolled, not retired
	RetiredExcluded    int      `json:"retired_excluded"` // retired endpoints (not in scope)
	OSFamilies         []string `json:"os_families"`      // e.g. "Windows 10 build 19045 (12)"
	ApplicationVendors []string `json:"application_vendors"`
	Sites              []string `json:"sites"`
	Groups             []string `json:"groups"`
}

type Control struct {
	ID              string   `json:"id"`
	Objective       string   `json:"objective"`
	AuditorEvidence string   `json:"auditor_evidence"` // template column
	SuggestedTest   string   `json:"suggested_test"`   // template column
	Evidence        string   `json:"evidence"`         // what the product data shows
	EvidenceIDs     []string `json:"evidence_ids"`
	TestPerformed   string   `json:"test_performed"`
	Status          string   `json:"status"`
	Source          string   `json:"source"` // automatic | manual | none
	Rationale       string   `json:"rationale"`
	// Manual is the reviewer's entry from the profile, if any (shown even
	// when the automatic result is used).
	Manual *store.ManualControl `json:"manual,omitempty"`
}

type Mapping struct {
	store.RegulatoryMapping
	Conclusion  string `json:"conclusion"`
	NeedsReview bool   `json:"needs_review"`
}

type PriorityStats struct {
	Priority         string  `json:"priority"`
	MaxDays          int     `json:"max_days"`
	Source           string  `json:"source"`
	ClockStart       string  `json:"clock_start"`
	ExceptionProcess string  `json:"exception_process"`
	Pairs            int     `json:"pairs"`
	Compliant        int     `json:"compliant"`
	VerifiedLate     int     `json:"verified_late"`
	Overdue          int     `json:"overdue"`
	Pending          int     `json:"pending"`
	Failed           int     `json:"failed"`
	Offline          int     `json:"offline"`
	Exception        int     `json:"exception"`
	NotApplicable    int     `json:"not_applicable"`
	PastDeadlineOpen int     `json:"past_deadline_open"`
	PctOnTime        float64 `json:"pct_on_time"` // compliant / (pairs - not_applicable - exception); 0 when none
}

// Pair is one applicable endpoint/update pair (template §5.2).
type Pair struct {
	EndpointID     string `json:"endpoint_id"`
	Hostname       string `json:"hostname"`
	PackageID      string `json:"package_id"`
	Title          string `json:"title"`
	KB             string `json:"kb"`
	Severity       string `json:"severity"`
	Priority       string `json:"priority"`
	ReleaseDate    string `json:"release_date"`
	AcquiredAt     string `json:"acquired_at"`
	ApprovedAt     string `json:"approved_at"`
	ClockStart     string `json:"clock_start"`
	Deadline       string `json:"deadline"`
	DeadlineSource string `json:"deadline_source"`
	InstalledAt    string `json:"installed_at"`
	VerifiedAt     string `json:"verified_at"`
	Outcome        string `json:"outcome"`
	PastDeadline   bool   `json:"past_deadline"` // deadline passed and not verified (exceptions excluded)
	DeploymentID   string `json:"deployment_id"`
	Evidence       string `json:"evidence"`
	ExceptionID    string `json:"exception_id"`
	Basis          string `json:"basis"` // targeted | needed (inventory, no target) | exception
}

type Timeliness struct {
	AsOf           string          `json:"as_of"`
	ByPriority     []PriorityStats `json:"by_priority"`
	OutcomeCounts  map[string]int  `json:"outcome_counts"`
	PairsTotal     int             `json:"pairs_total"`
	Pairs          []Pair          `json:"pairs"` // not compliant first, at most PairsLimit
	PairsLimit     int             `json:"pairs_limit"`
	PairsTruncated bool            `json:"pairs_truncated"`
}

type Evidence struct {
	ID              string `json:"id"`
	Item            string `json:"item"`
	SourceSystem    string `json:"source_system"`
	Period          string `json:"period"`
	Scope           string `json:"scope"`
	SHA256          string `json:"sha256"`
	Records         int    `json:"records"`
	Confidentiality string `json:"confidentiality"`
	Included        string `json:"included"` // evidence/... path in the package, or a reference
	Complete        bool   `json:"complete"`
	Note            string `json:"note"`
}

type Finding struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Control          string   `json:"control"`
	Source           string   `json:"source"`
	Observation      string   `json:"observation"`
	EvidenceIDs      []string `json:"evidence_ids"`
	Risk             string   `json:"risk"`
	Severity         string   `json:"severity"`
	RootCause        string   `json:"root_cause"`
	CorrectiveAction string   `json:"corrective_action"`
	Owner            string   `json:"owner"`
	DueDate          string   `json:"due_date"`
	Status           string   `json:"status"`
	AffectedCount    int      `json:"affected_count"`
	Affected         []string `json:"affected"` // sample (at most 20)
}

type ExceptionRow struct {
	ExceptionID          string `json:"exception_id"`
	EndpointID           string `json:"endpoint_id"`
	Scope                string `json:"scope"` // hostname
	PackageID            string `json:"package_id"`
	Patch                string `json:"patch"` // package id or "all updates"
	Reason               string `json:"reason"`
	CompensatingControls string `json:"compensating_controls"`
	Owner                string `json:"owner"`
	Approver             string `json:"approver"`
	Opened               string `json:"opened"`
	Expires              string `json:"expires"`
	Status               string `json:"status"` // Active | Expired | Revoked
}

type ScopeLimitations struct {
	Auto    []string `json:"auto"`    // gaps the product discloses
	Profile string   `json:"profile"` // the organisation's text
}

type Reference struct {
	N     int    `json:"n"`
	Label string `json:"label"` // e.g. "RBI"
	Title string `json:"title"`
	URL   string `json:"url"`
	Note  string `json:"note,omitempty"`
}

type AuditChain struct {
	OK          bool   `json:"ok"`
	Events      int64  `json:"events"`
	FirstBadSeq int64  `json:"first_bad_seq"`
	Error       string `json:"error"`
	HeadSeq     int64  `json:"head_seq"`
}
