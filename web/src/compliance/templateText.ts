// Fixed wording of the owner's "Patch Management Compliance Report" template
// (Downloads/patch-management-compliance-report.md). Reproduced verbatim:
// headings, disclaimers, control objectives, evidence items and references.
// §10 "Product requirements" is intentionally not rendered.

export const REPORT_TITLE = "Patch Management Compliance Report";

export const COVER_FIELDS: [string, string][] = [
  ["Report type", "Auditor export template"],
  ["Control domain", "Endpoint and server patch management"],
  ["Coverage model", "Common controls with regulator-specific mappings"],
  ["Document status", "Product/report specification and export template"],
  ["Regulatory review date", "18 October 2026"],
];

export const IMPORTANT_DISCLAIMER =
  "This report organizes operational evidence and maps it to selected regulatory requirements. It is not a legal opinion, regulator approval, audit opinion, or certification of compliance. Applicability depends on the entity type, regulator, system scope, current circulars and directions, and any supervisory instructions. The organization’s compliance/legal team and auditor must validate the mapping and conclusions before relying on it.";

export const ASSESSMENT_RATIONALE_NOTE = "Do not infer compliance solely from a high patch percentage.";

export const OFFLINE_MODEL_INTRO = "How the organization acquires and distributes updates without endpoints connecting to the internet.";

export const OFFLINE_MODEL_LABELS: [key: "acquisition_zone" | "transfer_boundary" | "quarantine" | "repository" | "endpoint_comms" | "egress_evidence", label: string, hint: string][] = [
  ["acquisition_zone", "Connected acquisition zone", "Systems and operators that obtain vendor packages"],
  ["transfer_boundary", "Transfer boundary", "One-way gateway / data diode / controlled transfer broker and interface"],
  ["quarantine", "Quarantine and verification", "Where bundles are received, scanned, signature/hash checked, and held"],
  ["repository", "Internal patch service/repository", "Service and locations"],
  ["endpoint_comms", "Endpoint communications", "Internal-only protocols and destinations"],
  ["egress_evidence", "Network egress enforcement evidence", "Firewall, routing, proxy, or network-control evidence reference"],
];

export const METHOD_INTRO = "For each control, the report should record:";
export const METHOD_STEPS = [
  "Whether the source applies to this entity and system scope.",
  "The control requirement or the organization’s policy implementing it.",
  "The test performed and period sampled.",
  "Evidence references, collection time, and integrity/hash where available.",
  "Result and rationale.",
  "Finding severity, owner, corrective action, and due date if not met.",
];

export const STATUS_DEFINITIONS: [label: string, text: string][] = [
  ["Compliant", "Evidence demonstrates the control operated as required for the tested scope and period."],
  ["Partially compliant", "Control exists but coverage, timeliness, evidence, or execution has gaps."],
  ["Non-compliant", "Required control is absent or failed materially."],
  ["Not applicable", "Documented rationale shows the requirement does not apply to this entity or system."],
  ["Not assessed", "Evidence or testing is insufficient to conclude."],
];
export const TELEMETRY_NOTE =
  "Do not treat missing endpoint telemetry as compliant. Classify it as stale, offline, or not assessed until independently resolved.";

export const CONTROL_MATRIX_INTRO =
  "The following baseline is designed to support audit work across sectors. It is a product control framework, not a claim that every row is explicitly mandated in identical wording by every Indian regulator.";

export type ControlDef = { id: string; objective: string; evidence: string; test: string };

export const CONTROLS: ControlDef[] = [
  { id: "PM-01", objective: "Approved patch and change policy defines scope, roles, risk priorities, timelines, approvals, exceptions, and recovery.", evidence: "Current policy version; approval record; review date; role matrix; exception policy.", test: "Inspect approval and review history; confirm policy covers in-scope asset classes." },
  { id: "PM-02", objective: "Asset and software inventory is complete enough to identify patch exposure.", evidence: "Endpoint list, software inventory, ownership, criticality, last-seen timestamp, discovery source.", test: "Reconcile a sample against independent endpoint/network/CMDB sources; examine stale assets." },
  { id: "PM-03", objective: "Patch sources and acquisition activities are controlled and traceable.", evidence: "Vendor/source, acquisition timestamp, package ID/version, operator, source signature/catalog.", test: "Trace sampled packages to an approved vendor source and acquisition record." },
  { id: "PM-04", objective: "Updates cross into the isolated network through a defined, controlled boundary.", evidence: "Gateway/broker configuration, transfer receipt, directionality and network diagrams, access logs.", test: "Confirm only approved transfer types cross; validate endpoint network egress restrictions." },
  { id: "PM-05", objective: "Imported packages are quarantined and verified before they can be deployed.", evidence: "Manifest, signature validation, hashes, malware scan result, quarantine state transitions.", test: "Attempted tamper/replay test results; sample package hash comparison from acquisition through repository." },
  { id: "PM-06", objective: "Patch priority reflects vulnerability risk, asset criticality, exploitation, and operational impact.", evidence: "Severity/risk record, affected assets, prioritization rationale, deadline, mitigation.", test: "Reperform prioritization on sampled critical/high patches; inspect overdue exceptions." },
  { id: "PM-07", objective: "Production deployment is approved and change-controlled.", evidence: "Change ticket, approvers, deployment scope, maintenance window, test and recovery plan.", test: "Sample deployments; verify approvals precede production and separation of duties where required." },
  { id: "PM-08", objective: "Patches are tested before broad production rollout, proportionate to risk and system criticality.", evidence: "Pilot group, test results, compatibility and health checks, go/no-go approval.", test: "Trace a sample from test to production; inspect emergency-path rationale." },
  { id: "PM-09", objective: "Deployment is staged and can be paused when failures or operational risks occur.", evidence: "Ring/wave configuration, thresholds, pause events, retries, rollout logs.", test: "Review a deployment with failures or simulate configured stop condition." },
  { id: "PM-10", objective: "Endpoint installation and health are independently verified after deployment.", evidence: "Endpoint result, installed version/KB/package, reboot status, fresh inventory, health evidence.", test: "Compare reported status with endpoint or independent configuration evidence." },
  { id: "PM-11", objective: "Failures, unavailable patches, and patch exceptions are owned and time-bound.", evidence: "Failed endpoint list, tickets, exception owner, rationale, compensating controls, expiry/review.", test: "Sample exceptions and verify approval, risk acceptance, review, and closure evidence." },
  { id: "PM-12", objective: "Failed or harmful changes have documented recovery arrangements.", evidence: "Rollback/uninstall support, restore/reimage procedure, backup status, recovery test, incident record.", test: "Inspect recovery plan and evidence of exercise; verify it is appropriate for sampled patch types." },
  { id: "PM-13", objective: "Privileged access to patch policy, package approval, deployment, and keys is restricted and logged.", evidence: "Role assignments, MFA/access logs, key custody/rotation, admin activity audit trail.", test: "Sample privileged accounts/actions; verify authorization and periodic review." },
  { id: "PM-14", objective: "Patch records and audit trails are complete, protected, searchable, and retained under policy.", evidence: "Append-only/tamper-evident audit events, retention settings, export manifest, access logs.", test: "Trace patch lifecycle end to end; verify log retention and integrity against applicable requirements." },
  { id: "PM-15", objective: "Patch compliance is measured and reported to appropriate governance forums.", evidence: "Compliance reports, overdue metrics, risk exceptions, meeting packs/minutes, action tracking.", test: "Recalculate a sample metric and trace reporting/escalation." },
  { id: "PM-16", objective: "Patch management service and repository are secured, backed up, monitored, and recoverable.", evidence: "Hardening baseline, vulnerability results, backup records, restore tests, capacity and monitoring alerts.", test: "Inspect system controls and restore evidence; confirm management systems themselves are patched." },
  { id: "PM-17", objective: "Unsupported and end-of-life software is identified and risk-managed.", evidence: "EOL inventory, upgrade/removal plan, risk acceptance, compensating controls.", test: "Sample end-of-life assets and inspect remediation/exception ownership." },
];

export const APPLICABILITY_NOTE_1 =
  "Regulations apply to the regulated entity, not automatically to every customer of a patch-management product. Configure this section from the entity’s legal/regulatory profile. Product-generated mappings should be treated as ";
export const APPLICABILITY_NOTE_BOLD = "candidate mappings";
export const APPLICABILITY_NOTE_2 = " until reviewed against the current instrument, amendments, entity category, and supervisory directions.";

export type RegulatoryRowDef = { framework: string; instrument: string; expectation: string; evidence: string; placeholder: string };

/** §4 rows, stored like the server defaults: framework = regulator, instrument = the direction / guideline title. */
export const REGULATORY_ROWS: RegulatoryRowDef[] = [
  { framework: "RBI", instrument: "Master Direction on Information Technology Governance, Risk, Controls and Assurance Practices, 2023", expectation: "For entities within scope, documented change and patch management should assess business impact of applying or not applying patches, ensure secure and timely implementation with necessary approvals, and provide recovery from failed deployment or unexpected results. Audit trails should support audit and forensic use.", evidence: "Policy and procedures; impact/risk assessment; approvals; test and deployment records; rollback/recovery evidence; audit events.", placeholder: "Applicable? Entity/category. Clause reference verified by reviewer. Result." },
  { framework: "RBI", instrument: "Master Directions on Cyber Resilience and Digital Payment Security Controls for non-bank Payment System Operators, 2024", expectation: "For in-scope non-bank PSOs, maintain patch/change lifecycle controls, apply relevant security patches within appropriate timelines, rapidly address critical patches, and test/validate production changes.", evidence: "Patch policy; risk/timeline record; emergency patch record; test evidence; production deployment; endpoint verification.", placeholder: "Applicable? Category and source clause. Result." },
  { framework: "SEBI", instrument: "Cybersecurity and Cyber Resilience Framework (CSCRF), 2024 and subsequent circulars/FAQs", expectation: "The framework includes patch-management expectations for applicable SEBI regulated entities, including approved/reviewed policy, patch compliance tracking/reporting, post-patch performance, and stated maximum timelines by patch criticality in the framework. Entity category and subsequent clarifications must be checked.", evidence: "Approved patch policy and review; asset coverage; patch criticality and dates; compliance reports to IT Committee; post-update performance; DC/DR coverage where applicable.", placeholder: "Applicable? SEBI RE type/category; current clause/version confirmed; result." },
  { framework: "IRDAI", instrument: "Information and Cyber Security Guidelines (including 2023 guidance and applicable amendments)", expectation: "Cybersecurity controls and assurance requirements may apply to insurers and insurance intermediaries; map current requirements for the specific entity and scope.", evidence: "Patch process, asset/vulnerability records, testing, audit checklist, corrective actions, evidence of governance.", placeholder: "Applicable? Insurer/intermediary classification; current instrument checked; result." },
  { framework: "CERT-In", instrument: "Directions under Section 70B(6), dated 28 April 2022, and FAQs/amendments", expectation: "These directions address cybersecurity practices, incident prevention/response/reporting, and specified log requirements. They are not a patch-timeline standard by themselves; patch records can support investigation and incident response.", evidence: "Relevant security logs and audit trails, incident evidence, time synchronization/logging evidence where applicable, vulnerability/patch context.", placeholder: "Applicability and obligations confirmed by legal/compliance; result." },
  { framework: "MeitY", instrument: "Guidelines on Information Security Practices for Government Entities", expectation: "For government entities within scope, guidance explicitly discusses current security patches, regular or critical patching, vulnerability assessment, and patch-management solutions/manual update processes for devices that cannot auto-update.", evidence: "Patch policy, inventory, vulnerability scans, deployment records, manual update process and exceptions.", placeholder: "Government entity scope and adoption/mandate confirmed; result." },
  { framework: "PFRDA", instrument: "PFRDA / other sector-specific regulator or critical-sector direction", expectation: "Requirements may exist for the entity type, central recordkeeping agencies, critical infrastructure, or other regulated systems. Add the exact applicable instrument rather than relying on this generic row.", evidence: "", placeholder: "Applicability and reviewed clause." },
];

export const MAPPING_FIELDS_INTRO = "Each mapped obligation should be stored as a versioned record with:";
export const MAPPING_FIELDS = [
  "Regulator and framework name.",
  "Circular/direction title, identifier, publication date, effective date, amendment/version, and official source URL.",
  "Exact section/paragraph/control reference, captured for review and not paraphrase alone.",
  "Entity categories and system scopes to which the obligation applies.",
  "Applicability rationale and reviewer/approval date.",
  "Mapped product controls and evidence fields.",
  "Assessment result, findings, owner, corrective action, due date, and evidence references.",
  "Last legal/compliance review date and next review trigger/date.",
];
export const MAPPING_FIELDS_OUTRO =
  "The product should support custom frameworks and customer control mappings; it should not label an organization “RBI compliant” or “SEBI compliant” based solely on patch status.";

export const NOT_ASSESSED_REVIEW = "Not assessed — needs compliance review";

export const DEADLINES_INTRO =
  "Deadlines must be configurable by entity policy and applicable regulation. Do not hard-code one universal timeline across all customers or systems.";
export const SEBI_NOTE =
  "The 2024 CSCRF source contains maximum timelines for high, moderate, and low criticality patches and separate treatment for emergency patching. The applicable entity category, exact implementation requirements, and amendments/FAQs must be confirmed. Where a binding deadline applies, the stricter applicable obligation should be reflected in the customer’s configured policy after compliance review.";

export const CALC_INTRO = "For each applicable endpoint/update pair, retain:";
export const CALC_RULES = [
  "Patch release/availability date and the date the organization became aware of the patch.",
  "Date the update was acquired and made available internally.",
  "Applicability result and rationale.",
  "Required deadline and source of that deadline.",
  "Installation and verification timestamps.",
  "Current outcome: compliant, overdue, pending, failed, offline, not applicable, or approved exception.",
];
export const COMPLIANT_ON_TIME =
  "means the applicable update (or approved superseding update) was installed and verified by the configured deadline. An approved exception is reported separately and must not be counted as patched.";

export const EVIDENCE_INTRO =
  "Every export should include an evidence index. The evidence files themselves may be included in a ZIP package or provided through a controlled repository link, subject to the auditor’s access permissions.";

export const EVIDENCE_ITEMS: [id: string, item: string][] = [
  ["E-001", "Approved patch policy"],
  ["E-002", "In-scope endpoint and software inventory"],
  ["E-003", "Patch catalog and risk priority"],
  ["E-004", "Transfer manifest and gateway receipt"],
  ["E-005", "Signature/hash/scan verification"],
  ["E-006", "Change approvals and pilot results"],
  ["E-007", "Endpoint install/reboot/health results"],
  ["E-008", "Exceptions, failures, recovery actions"],
  ["E-009", "Privileged access and audit events"],
  ["E-010", "Governance reporting and corrective actions"],
];

export const EXPORT_INTEGRITY_INTRO = "The exported package should contain:";
export const EXPORT_INTEGRITY = [
  "This report in PDF and/or Markdown/CSV as requested by the organization.",
  "A machine-readable summary (JSON or CSV) of findings, control statuses, and metrics.",
  "An evidence index with object IDs, timestamps, source system, and hashes.",
  "Report-generation timestamp, reporting period, filters, and product version.",
  "A signed export manifest or verifiable digital signature where supported.",
  "Redaction and access controls for sensitive hostnames, IP addresses, user IDs, vulnerability details, and infrastructure topology.",
];
export const EXPORT_DISCLOSURE =
  "The report should state whether evidence is sampled or population-wide and disclose omitted records, unsupported platforms, stale agents, and data-collection gaps.";

export const SIGNOFF_ROLES: [role: string, commentsHint: string][] = [
  ["Patch management owner", "Comments"],
  ["Information security / CISO delegate", "Comments"],
  ["Compliance/legal reviewer", "Applicability and mapping confirmation"],
  ["Independent auditor", "Audit conclusion, if issued"],
];

export const REFERENCES_INTRO =
  "These sources were consulted to prepare the candidate mapping. Compliance owners should check the official source for amendments and applicability before each reporting cycle.";

export const REFERENCES: { org: string; title: string; url: string; note?: string }[] = [
  { org: "RBI", title: "Master Direction on Information Technology Governance, Risk, Controls and Assurance Practices, 2023", url: "https://systemhealth.rbi.org.in/Scripts/BS_ViewMasDirections.aspx_id%3D12562%283%29.html" },
  { org: "RBI", title: "Master Directions on Cyber Resilience and Digital Payment Security Controls for non-bank Payment System Operators", url: "https://systemhealth.rbi.org.in/Scripts/BS_ViewMasDirections.aspx_id%3D12715%281%29.html" },
  { org: "SEBI", title: "Cybersecurity and Cyber Resilience Framework (CSCRF) for SEBI Regulated Entities, circular dated 20 August 2024", url: "https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res-_85964.html" },
  { org: "SEBI", title: "CSCRF framework document", url: "https://www.sebi.gov.in/sebi_data/attachdocs/aug-2024/1724326790365.pdf" },
  { org: "SEBI", title: "CSCRF FAQs, June 2025", url: "https://www.sebi.gov.in/sebi_data/faqfiles/jun-2025/1749647139924.pdf" },
  { org: "CERT-In", title: "Directions under Section 70B", url: "https://www.cert-in.org.in/Directions70B.jsp" },
  { org: "MeitY", title: "Guidelines on Information Security Practices for Government Entities", url: "https://www.meity.gov.in/writereaddata/files/Guidelines%20on%20Information%20Security%20Practices%20for%20Government%20Entities.pdf" },
  { org: "IRDAI", title: "Information and Cyber Security Guidelines, 2023 document page", url: "https://irdai.gov.in/document-detail?documentId=3314780" },
  { org: "IRDAI", title: "Guidelines on Information and Cyber Security for insurance intermediaries, 2022", url: "https://irdai.gov.in/document-detail?documentId=1354286" },
  { org: "NIST", title: "SP 800-40 Rev. 4: Guide to Enterprise Patch Management Planning", url: "https://csrc.nist.gov/pubs/sp/800/40/r4/final", note: "useful process guidance, not an Indian regulation." },
];

export const PRIORITY_LABELS: Record<string, string> = {
  emergency: "Emergency / actively exploited",
  critical: "Critical",
  high: "High",
  moderate: "Moderate",
  low: "Low",
};

export const CLOCK_START_LABELS: Record<string, string> = {
  release: "Vendor release / availability date",
  acquired: "Date acquired into the isolated zone",
  approved: "Date approved for deployment",
};

/** Template §4 "Framework / source" text: "RBI — Master Direction …" (the instrument alone when it already names the regulator). */
export function mappingTitle(m: { framework: string; instrument: string }): string {
  const fw = m.framework.trim();
  const ins = m.instrument.trim();
  if (!ins) return fw;
  if (!fw || ins.toLowerCase().startsWith(fw.toLowerCase())) return ins;
  return fw === "CERT-In" && ins.startsWith("Directions") ? `${fw} ${ins}` : `${fw} — ${ins}`;
}
