// Defensive mapping of server JSON into the report types: missing arrays and
// objects become empty values so a partial response still renders, and
// missing statuses read "Not assessed" (never compliant). toProfilePayload
// builds the strict PUT body (exactly the server's fields).
import type {
  AuditChain, CompliancePack, Control, CountPct, DeadlineRule, ExceptionEntry, ExecutiveSummary, Finding, ManualControl,
  PackMapping, PriorityTimeliness, ProfileRecord, ProfileVersion, RegulatoryMapping, ReportProfile, TimelinessPair,
} from "./types";
import { PRIORITIES, STATUS_VALUES } from "./types";
import { asLines } from "./format";
import { REFERENCES, REGULATORY_ROWS, SIGNOFF_ROLES } from "./templateText";

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {};
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function str(v: unknown): string {
  if (v === null || v === undefined) return "";
  return typeof v === "string" ? v : String(v);
}
function num(v: unknown, d = 0): number {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : d;
}
function numOrNull(v: unknown): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function boolOrNull(v: unknown): boolean | null {
  return typeof v === "boolean" ? v : null;
}
function strList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(str).filter(Boolean);
  if (typeof v === "string") return v.split(",").map((x) => x.trim()).filter(Boolean);
  return [];
}

/** Exact server status string ("" when unset or unknown). */
export function statusValue(v: unknown): string {
  const s = str(v).trim();
  const hit = STATUS_VALUES.find((x) => x.toLowerCase() === s.toLowerCase().replace(/_/g, " ").replace("non compliant", "non-compliant"));
  return hit ?? "";
}

/** Lower-case letters and digits only (tolerant framework-name matching). */
export function normName(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

/** The template §4 row a mapping came from (same regulator and instrument), if any. */
export function templateRowFor(m: { framework: string; instrument: string }) {
  const fw = normName(m.framework);
  const ins = normName(m.instrument);
  return REGULATORY_ROWS.find((d) => normName(d.framework) === fw && normName(d.instrument) === ins);
}

export function emptyMapping(framework: string, instrument = "", expectation = "", evidence = ""): RegulatoryMapping {
  return {
    framework, instrument, expectation, evidence, clause_ref: "",
    applicable: "unknown", rationale: "", reviewer: "", reviewed_at: "", result: "", notes: "",
  };
}

function defaultDeadlines(): DeadlineRule[] {
  const days: Record<string, number> = { emergency: 2, critical: 7, high: 14, moderate: 30, low: 90 };
  return PRIORITIES.map((p) => ({ priority: p, max_days: days[p], source: "", clock_start: "release", exception_process: "" }));
}

export function emptyProfile(): ReportProfile {
  return {
    legal_entity: "", regulated_activity: "", regulators: [], entity_category: "", assessment_owner: "", independent_reviewer: "",
    systems_in_scope: "", endpoint_types: "", exclusions: [],
    offline_model: { acquisition_zone: "", transfer_boundary: "", quarantine: "", repository: "", endpoint_comms: "", egress_evidence: "" },
    deadlines: defaultDeadlines(),
    policy: { version: "", approved_by: "", approved_at: "", review_date: "", reference: "" },
    regulatory_mappings: REGULATORY_ROWS.map((r) => emptyMapping(r.framework, r.instrument, r.expectation, r.evidence)),
    signoff: SIGNOFF_ROLES.map(([role]) => ({ role, name: "", comments: "", date: "" })),
    scope_limitations: "", management_response: "", manual_controls: {},
    overall_assessment: { status: "", rationale: "" },
    confidentiality_class: "Confidential",
  };
}

function normMapping(v: unknown): RegulatoryMapping {
  const m = obj(v);
  const a = str(m.applicable).toLowerCase();
  return {
    framework: str(m.framework), instrument: str(m.instrument), expectation: str(m.expectation), evidence: str(m.evidence),
    clause_ref: str(m.clause_ref), applicable: a === "yes" || a === "no" ? a : "unknown",
    rationale: str(m.rationale), reviewer: str(m.reviewer), reviewed_at: str(m.reviewed_at), result: statusValue(m.result), notes: str(m.notes),
  };
}

export function normalizeProfile(raw: unknown): ReportProfile {
  const p = obj(raw);
  const base = emptyProfile();
  const om = obj(p.offline_model);
  const pol = obj(p.policy);
  const manual: Record<string, ManualControl> = {};
  for (const [id, v] of Object.entries(obj(p.manual_controls))) {
    const m = obj(v);
    manual[id] = { status: statusValue(m.status), evidence_ref: str(m.evidence_ref), note: str(m.note) };
  }
  const byPriority = new Map(arr(p.deadlines).map((d) => [str(obj(d).priority), obj(d)]));
  const deadlines = base.deadlines.map((def) => {
    const o = byPriority.get(def.priority);
    if (!o) return def;
    const cs = str(o.clock_start);
    return {
      priority: def.priority, max_days: num(o.max_days, def.max_days), source: str(o.source),
      clock_start: (cs === "acquired" || cs === "approved" ? cs : "release") as DeadlineRule["clock_start"],
      exception_process: str(o.exception_process),
    };
  });
  const mappings = arr(p.regulatory_mappings).map(normMapping);
  const signoff = arr(p.signoff).map((s) => { const o = obj(s); return { role: str(o.role), name: str(o.name), comments: str(o.comments), date: str(o.date) }; });
  const ov = obj(p.overall_assessment);
  return {
    legal_entity: str(p.legal_entity), regulated_activity: str(p.regulated_activity), regulators: strList(p.regulators),
    entity_category: str(p.entity_category), assessment_owner: str(p.assessment_owner), independent_reviewer: str(p.independent_reviewer),
    systems_in_scope: str(p.systems_in_scope), endpoint_types: str(p.endpoint_types),
    exclusions: arr(p.exclusions).map((e) => { const o = obj(e); return { system: str(o.system), reason: str(o.reason), approved_by: str(o.approved_by), review_date: str(o.review_date) }; }),
    offline_model: {
      acquisition_zone: str(om.acquisition_zone), transfer_boundary: str(om.transfer_boundary), quarantine: str(om.quarantine),
      repository: str(om.repository), endpoint_comms: str(om.endpoint_comms), egress_evidence: str(om.egress_evidence),
    },
    deadlines,
    policy: { version: str(pol.version), approved_by: str(pol.approved_by), approved_at: str(pol.approved_at), review_date: str(pol.review_date), reference: str(pol.reference) },
    regulatory_mappings: mappings.length ? mappings : base.regulatory_mappings,
    signoff: signoff.length ? signoff : base.signoff,
    scope_limitations: str(p.scope_limitations),
    management_response: str(p.management_response),
    manual_controls: manual,
    overall_assessment: { status: statusValue(ov.status), rationale: str(ov.rationale) },
    confidentiality_class: str(p.confidentiality_class) || base.confidentiality_class,
  };
}

/** Exactly the server's ReportProfile fields (PUT is strict: unknown fields → 400); empty manual entries dropped. */
export function toProfilePayload(p: ReportProfile): ReportProfile {
  const manual = Object.fromEntries(
    Object.entries(p.manual_controls)
      .filter(([, m]) => m.status || m.evidence_ref.trim() || m.note.trim())
      .map(([id, m]) => [id, { status: m.status, evidence_ref: m.evidence_ref, note: m.note }]),
  );
  return {
    legal_entity: p.legal_entity, regulated_activity: p.regulated_activity, regulators: [...p.regulators],
    entity_category: p.entity_category, assessment_owner: p.assessment_owner, independent_reviewer: p.independent_reviewer,
    systems_in_scope: p.systems_in_scope, endpoint_types: p.endpoint_types,
    exclusions: p.exclusions.map(({ system, reason, approved_by, review_date }) => ({ system, reason, approved_by, review_date })),
    offline_model: { ...p.offline_model },
    deadlines: p.deadlines.map(({ priority, max_days, source, clock_start, exception_process }) => ({ priority, max_days, source, clock_start, exception_process })),
    policy: { ...p.policy },
    regulatory_mappings: p.regulatory_mappings.map(({ framework, instrument, expectation, evidence, clause_ref, applicable, rationale, reviewer, reviewed_at, result, notes }) =>
      ({ framework, instrument, expectation, evidence, clause_ref, applicable, rationale, reviewer, reviewed_at, result, notes })),
    signoff: p.signoff.map(({ role, name, comments, date }) => ({ role, name, comments, date })),
    scope_limitations: p.scope_limitations, management_response: p.management_response,
    manual_controls: manual,
    overall_assessment: { status: p.overall_assessment.status, rationale: p.overall_assessment.rationale },
    confidentiality_class: p.confidentiality_class,
  };
}

/** Problems the server would reject (400), checked before saving. */
export function profileProblems(p: ReportProfile): string[] {
  const out: string[] = [];
  p.exclusions.forEach((e, i) => { if (!e.system.trim() || !e.reason.trim()) out.push(`Exclusion ${i + 1}: system and reason are required.`); });
  p.deadlines.forEach((d) => { if (!Number.isInteger(d.max_days) || d.max_days < 1 || d.max_days > 3650) out.push(`Deadline “${d.priority}”: maximum time must be 1–3650 days.`); });
  p.regulatory_mappings.forEach((m, i) => { if (!m.framework.trim()) out.push(`Regulatory mapping ${i + 1}: framework name is required.`); });
  p.signoff.forEach((s, i) => { if (!s.role.trim()) out.push(`Sign-off row ${i + 1}: role is required.`); });
  return out;
}

export function normalizeProfileRecord(raw: unknown): ProfileRecord {
  const r = obj(raw);
  return {
    profile: normalizeProfile(r.profile ?? r),
    version: num(r.version),
    edited_by: str(r.edited_by),
    edited_at: str(r.edited_at),
    sha256: str(r.sha256),
    is_default: r.is_default === true || num(r.version) === 0,
  };
}

export function normalizeVersions(raw: unknown): ProfileVersion[] {
  const list = Array.isArray(raw) ? raw : arr(obj(raw).versions);
  return list.map((v) => {
    const o = obj(v);
    return { version: num(o.version), edited_by: str(o.edited_by), edited_at: str(o.edited_at), sha256: str(o.sha256) };
  }).sort((a, b) => b.version - a.version);
}

function countPct(v: unknown): CountPct {
  if (typeof v === "number") return { count: v, pct: null };
  const o = obj(v);
  return { count: num(o.count), pct: numOrNull(o.pct) };
}

function normSummary(v: unknown): ExecutiveSummary {
  const s = obj(v);
  const f = obj(s.findings_by_severity);
  return {
    in_scope_endpoints: num(s.in_scope_endpoints),
    current_inventory: countPct(s.current_inventory),
    compliant_with_policy: countPct(s.compliant_with_policy),
    overdue: countPct(s.overdue),
    stale_inventory: countPct(s.stale_inventory),
    pending_restart: num(s.pending_restart),
    active_exceptions: num(s.active_exceptions),
    emergency_open_past_target: num(s.emergency_open_past_target),
    findings_by_severity: { critical: num(f.critical), high: num(f.high), medium: num(f.medium), low: num(f.low) },
    evidence_completeness_pct: numOrNull(s.evidence_completeness_pct),
  };
}

function normControl(v: unknown): Control {
  const c = obj(v);
  return {
    id: str(c.id), objective: str(c.objective), auditor_evidence: str(c.auditor_evidence), suggested_test: str(c.suggested_test),
    evidence: str(c.evidence), evidence_ids: strList(c.evidence_ids), test_performed: str(c.test_performed),
    status: str(c.status) || "Not assessed", source: str(c.source), rationale: str(c.rationale),
  };
}

function normFinding(v: unknown): Finding {
  const f = obj(v);
  return {
    id: str(f.id), title: str(f.title), control: str(f.control), source: str(f.source), observation: str(f.observation),
    evidence_ids: strList(f.evidence_ids), risk: str(f.risk), severity: str(f.severity), root_cause: str(f.root_cause),
    corrective_action: str(f.corrective_action), owner: str(f.owner), due_date: str(f.due_date), status: str(f.status),
    affected_count: num(f.affected_count), affected: strList(f.affected),
  };
}

function normPriority(v: unknown): PriorityTimeliness {
  const o = obj(v);
  return {
    priority: str(o.priority), max_days: num(o.max_days), source: str(o.source), clock_start: str(o.clock_start),
    exception_process: str(o.exception_process), pairs: num(o.pairs), compliant: num(o.compliant), verified_late: num(o.verified_late),
    overdue: num(o.overdue), pending: num(o.pending), failed: num(o.failed), offline: num(o.offline), exception: num(o.exception),
    not_applicable: num(o.not_applicable), past_deadline_open: num(o.past_deadline_open), pct_on_time: numOrNull(o.pct_on_time),
  };
}

function normPair(v: unknown): TimelinessPair {
  const o = obj(v);
  return {
    endpoint_id: str(o.endpoint_id), hostname: str(o.hostname), package_id: str(o.package_id), title: str(o.title), kb: str(o.kb),
    severity: str(o.severity), priority: str(o.priority), release_date: str(o.release_date), acquired_at: str(o.acquired_at),
    approved_at: str(o.approved_at), deadline: str(o.deadline), deadline_source: str(o.deadline_source), installed_at: str(o.installed_at),
    verified_at: str(o.verified_at), outcome: str(o.outcome), past_deadline: o.past_deadline === true,
  };
}

function normException(v: unknown): ExceptionEntry {
  const o = obj(v);
  return {
    exception_id: str(o.exception_id), endpoint_id: str(o.endpoint_id), scope: str(o.scope), package_id: str(o.package_id),
    patch: str(o.patch), reason: str(o.reason), compensating_controls: str(o.compensating_controls), owner: str(o.owner),
    approver: str(o.approver), opened: str(o.opened), expires: str(o.expires), status: str(o.status),
  };
}

function normAuditChain(v: unknown): AuditChain | null {
  if (!v || typeof v !== "object") return null;
  const o = obj(v);
  return { ok: boolOrNull(o.ok), events: num(o.events), first_bad_seq: num(o.first_bad_seq), error: str(o.error), head_seq: num(o.head_seq) };
}

export function normalizePack(raw: unknown): CompliancePack {
  const r = obj(raw);
  const meta = obj(r.meta);
  const gb = obj(meta.generated_by);
  const period = obj(meta.period);
  const oa = obj(r.overall_assessment);
  const tl = obj(r.timeliness);
  const sc = obj(r.scope);
  const pv = obj(r.profile_version);
  const sl = r.scope_limitations;
  const profile = normalizeProfile(r.profile);
  const refs = arr(r.references).map((x) => { const o = obj(x); return { n: numOrNull(o.n) ?? undefined, label: str(o.label), title: str(o.title), url: str(o.url), note: str(o.note) }; });
  const regs: PackMapping[] = arr(r.regulatory_mappings).map((m) => {
    const o = obj(m);
    return { ...normMapping(m), conclusion: str(o.conclusion), needs_review: o.needs_review !== false };
  });
  const signoff = arr(r.signoff).map((s) => { const o = obj(s); return { role: str(o.role), name: str(o.name), comments: str(o.comments), date: str(o.date) }; });
  const pairs = arr(tl.pairs).map(normPair);
  return {
    meta: {
      report_id: str(meta.report_id), title: str(meta.title), product_version: str(meta.product_version), generated_at: str(meta.generated_at),
      generated_by: { user: str(gb.user ?? meta.generated_by), role: str(gb.role) },
      period: { from: str(period.from), to: str(period.to), as_of: str(period.as_of), timezone: str(period.timezone) },
      filters: obj(meta.filters), redacted: meta.redacted === true,
      report_type: str(meta.report_type), control_domain: str(meta.control_domain), coverage_model: str(meta.coverage_model),
      document_status: str(meta.document_status), regulatory_review_date: str(meta.regulatory_review_date), prepared_for: str(meta.prepared_for),
    },
    disclaimer: str(r.disclaimer),
    profile,
    profile_version: { version: num(pv.version), edited_by: str(pv.edited_by), edited_at: str(pv.edited_at), sha256: str(pv.sha256), is_default: pv.is_default === true },
    executive_summary: normSummary(r.executive_summary),
    overall_assessment: {
      status: str(oa.status) || "Not assessed", rationale: str(oa.rationale), source: str(oa.source),
      suggested: str(oa.suggested), suggested_rationale: str(oa.suggested_rationale),
    },
    key_findings: arr(r.key_findings).map(normFinding),
    scope: {
      endpoints_total: num(sc.endpoints_total), retired_excluded: num(sc.retired_excluded), os_families: strList(sc.os_families),
      application_vendors: strList(sc.application_vendors), sites: strList(sc.sites), groups: strList(sc.groups),
    },
    controls: arr(r.controls).map(normControl),
    regulatory_mappings: regs.length ? regs : profile.regulatory_mappings.map((m) => ({ ...m, conclusion: "", needs_review: true })),
    timeliness: {
      as_of: str(tl.as_of), by_priority: arr(tl.by_priority).map(normPriority),
      pairs_total: num(tl.pairs_total, pairs.length), pairs, pairs_limit: num(tl.pairs_limit), pairs_truncated: tl.pairs_truncated === true,
    },
    evidence_register: arr(r.evidence_register).map((e) => {
      const o = obj(e);
      return {
        id: str(o.id), item: str(o.item), source_system: str(o.source_system), period: str(o.period), scope: str(o.scope), sha256: str(o.sha256),
        records: numOrNull(o.records), confidentiality: str(o.confidentiality), included: str(o.included), complete: boolOrNull(o.complete), note: str(o.note),
      };
    }),
    findings: arr(r.findings).map(normFinding),
    exceptions: arr(r.exceptions).map(normException),
    signoff: signoff.length ? signoff : profile.signoff,
    scope_limitations: Array.isArray(sl) || typeof sl === "string"
      ? { auto: asLines(sl as string | string[]), profile: "" }
      : { auto: strList(obj(sl).auto), profile: str(obj(sl).profile) },
    management_response: str(r.management_response) || profile.management_response,
    references: refs.length ? refs : REFERENCES.map((x, i) => ({ n: i + 1, label: x.org, title: x.title, url: x.url, note: x.note })),
    audit_chain: normAuditChain(r.audit_chain),
  };
}
