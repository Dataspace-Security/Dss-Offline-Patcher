// Auditor compliance report: profile (GET/PUT /api/reports/profile) and the
// generated pack (GET /api/reports/compliance-pack). Field names follow the
// server API doc (internal/compliance/types.go). The report renders defensively:
// missing data reads "Not assessed", never compliant.

export const REGULATORS = ["RBI", "SEBI", "IRDAI", "PFRDA", "MeitY", "CERT-In", "other"] as const;

export const PRIORITIES = ["emergency", "critical", "high", "moderate", "low"] as const;
export type Priority = (typeof PRIORITIES)[number];

export const CLOCK_STARTS = ["release", "acquired", "approved"] as const;
export type ClockStart = (typeof CLOCK_STARTS)[number];

export const APPLICABLE = ["yes", "no", "unknown"] as const;
export type Applicable = (typeof APPLICABLE)[number];

/** Canonical keys used for display (badges); see format.normStatus. */
export const CONTROL_STATUSES = ["compliant", "partially_compliant", "non_compliant", "not_applicable", "not_assessed"] as const;
export type ControlStatus = (typeof CONTROL_STATUSES)[number];

/** Exact status strings the server stores and returns ("" = not set). */
export const STATUS_VALUES = ["Compliant", "Partially compliant", "Non-compliant", "Not applicable", "Not assessed"] as const;

export const OUTCOMES = ["compliant", "verified_late", "overdue", "pending", "failed", "offline", "exception", "not_applicable"] as const;
export type Outcome = (typeof OUTCOMES)[number];

export type Exclusion = { system: string; reason: string; approved_by: string; review_date: string };

export type OfflineModel = {
  acquisition_zone: string;
  transfer_boundary: string;
  quarantine: string;
  repository: string;
  endpoint_comms: string;
  egress_evidence: string;
};

export type DeadlineRule = {
  priority: Priority;
  max_days: number;
  source: string;
  clock_start: ClockStart;
  exception_process: string;
};

export type PolicyInfo = { version: string; approved_by: string; approved_at: string; review_date: string; reference: string };

export type RegulatoryMapping = {
  framework: string;
  instrument: string;
  /** Template §4 column 2 (prefilled for template rows). */
  expectation: string;
  /** Template §4 column 3 (prefilled for template rows). */
  evidence: string;
  clause_ref: string;
  applicable: Applicable;
  rationale: string;
  reviewer: string;
  reviewed_at: string;
  /** "" or a STATUS_VALUES string. */
  result: string;
  notes: string;
};

export type SignOff = { role: string; name: string; comments: string; date: string };

/** status: "" or a STATUS_VALUES string. */
export type ManualControl = { status: string; evidence_ref: string; note: string };

/** PUT body (strict on the server: exactly these fields). */
export type ReportProfile = {
  legal_entity: string;
  regulated_activity: string;
  regulators: string[];
  entity_category: string;
  assessment_owner: string;
  independent_reviewer: string;
  systems_in_scope: string;
  endpoint_types: string;
  exclusions: Exclusion[];
  offline_model: OfflineModel;
  deadlines: DeadlineRule[];
  policy: PolicyInfo;
  regulatory_mappings: RegulatoryMapping[];
  signoff: SignOff[];
  scope_limitations: string;
  management_response: string;
  manual_controls: Record<string, ManualControl>;
  /** Optional override of the computed overall assessment; status "" = use the computed one. */
  overall_assessment: { status: string; rationale: string };
  confidentiality_class: string;
};

/** GET /api/reports/profile (ReportProfileRecord). */
export type ProfileRecord = {
  profile: ReportProfile;
  version: number;
  edited_by: string;
  edited_at: string;
  sha256: string;
  is_default: boolean;
};

export type ProfileVersion = { version: number; edited_by: string; edited_at: string; sha256: string };

export type CountPct = { count: number; pct?: number | null };

export type ExecutiveSummary = {
  in_scope_endpoints: number;
  current_inventory: CountPct;
  compliant_with_policy: CountPct;
  overdue: CountPct;
  stale_inventory: CountPct;
  pending_restart: number;
  active_exceptions: number;
  emergency_open_past_target: number;
  findings_by_severity: { critical: number; high: number; medium: number; low: number };
  evidence_completeness_pct: number | null;
};

export type Assessment = {
  status: string;
  rationale: string;
  source: string;
  /** The computed suggestion (shown when the profile overrides it). */
  suggested: string;
  suggested_rationale: string;
};

export type Finding = {
  id: string;
  title: string;
  control: string;
  source: string;
  observation: string;
  evidence_ids: string[];
  risk: string;
  severity: string;
  root_cause: string;
  corrective_action: string;
  owner: string;
  due_date: string;
  status: string;
  affected_count: number;
  affected: string[];
};

export type PackScope = {
  endpoints_total: number;
  retired_excluded: number;
  os_families: string[];
  application_vendors: string[];
  sites: string[];
  groups: string[];
};

export type Control = {
  id: string;
  objective: string;
  auditor_evidence: string;
  suggested_test: string;
  evidence: string;
  evidence_ids: string[];
  test_performed: string;
  status: string;
  source: string;
  rationale: string;
};

export type PackMapping = RegulatoryMapping & { conclusion: string; needs_review: boolean };

export type PriorityTimeliness = {
  priority: string;
  max_days: number;
  source: string;
  clock_start: string;
  exception_process: string;
  pairs: number;
  compliant: number;
  verified_late: number;
  overdue: number;
  pending: number;
  failed: number;
  offline: number;
  exception: number;
  not_applicable: number;
  past_deadline_open: number;
  pct_on_time: number | null;
};

export type TimelinessPair = {
  endpoint_id: string;
  hostname: string;
  package_id: string;
  title: string;
  kb: string;
  severity: string;
  priority: string;
  release_date: string;
  acquired_at: string;
  approved_at: string;
  deadline: string;
  deadline_source: string;
  installed_at: string;
  verified_at: string;
  outcome: string;
  past_deadline: boolean;
};

export type Timeliness = {
  as_of: string;
  by_priority: PriorityTimeliness[];
  pairs_total: number;
  pairs: TimelinessPair[];
  pairs_limit: number;
  pairs_truncated: boolean;
};

export type EvidenceItem = {
  id: string;
  item: string;
  source_system: string;
  period: string;
  scope: string;
  sha256: string;
  records: number | null;
  confidentiality: string;
  included: string;
  complete: boolean | null;
  note: string;
};

export type ExceptionEntry = {
  exception_id: string;
  endpoint_id: string;
  scope: string;
  package_id: string;
  patch: string;
  reason: string;
  compensating_controls: string;
  owner: string;
  approver: string;
  opened: string;
  expires: string;
  status: string;
};

export type Reference = { n?: number; label: string; title: string; url: string; note?: string };

export type AuditChain = { ok: boolean | null; events: number; first_bad_seq: number; error: string; head_seq: number };

export type PackMeta = {
  report_id: string;
  title: string;
  product_version: string;
  generated_at: string;
  generated_by: { user: string; role: string };
  period: { from: string; to: string; as_of: string; timezone: string };
  filters: Record<string, unknown>;
  redacted: boolean;
  report_type: string;
  control_domain: string;
  coverage_model: string;
  document_status: string;
  regulatory_review_date: string;
  prepared_for: string;
};

export type CompliancePack = {
  meta: PackMeta;
  disclaimer: string;
  profile: ReportProfile;
  profile_version: { version: number; edited_by: string; edited_at: string; sha256: string; is_default: boolean };
  executive_summary: ExecutiveSummary;
  overall_assessment: Assessment;
  key_findings: Finding[];
  scope: PackScope;
  controls: Control[];
  regulatory_mappings: PackMapping[];
  timeliness: Timeliness;
  evidence_register: EvidenceItem[];
  findings: Finding[];
  exceptions: ExceptionEntry[];
  signoff: SignOff[];
  scope_limitations: { auto: string[]; profile: string };
  management_response: string;
  references: Reference[];
  audit_chain: AuditChain | null;
};
