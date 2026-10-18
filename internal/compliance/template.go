package compliance

// Template text (owner's template §3, §8, §9), kept verbatim.

type controlDef struct{ id, objective, evidence, test string }

var controlDefs = []controlDef{
	{"PM-01", "Approved patch and change policy defines scope, roles, risk priorities, timelines, approvals, exceptions, and recovery.",
		"Current policy version; approval record; review date; role matrix; exception policy.",
		"Inspect approval and review history; confirm policy covers in-scope asset classes."},
	{"PM-02", "Asset and software inventory is complete enough to identify patch exposure.",
		"Endpoint list, software inventory, ownership, criticality, last-seen timestamp, discovery source.",
		"Reconcile a sample against independent endpoint/network/CMDB sources; examine stale assets."},
	{"PM-03", "Patch sources and acquisition activities are controlled and traceable.",
		"Vendor/source, acquisition timestamp, package ID/version, operator, source signature/catalog.",
		"Trace sampled packages to an approved vendor source and acquisition record."},
	{"PM-04", "Updates cross into the isolated network through a defined, controlled boundary.",
		"Gateway/broker configuration, transfer receipt, directionality and network diagrams, access logs.",
		"Confirm only approved transfer types cross; validate endpoint network egress restrictions."},
	{"PM-05", "Imported packages are quarantined and verified before they can be deployed.",
		"Manifest, signature validation, hashes, malware scan result, quarantine state transitions.",
		"Attempted tamper/replay test results; sample package hash comparison from acquisition through repository."},
	{"PM-06", "Patch priority reflects vulnerability risk, asset criticality, exploitation, and operational impact.",
		"Severity/risk record, affected assets, prioritization rationale, deadline, mitigation.",
		"Reperform prioritization on sampled critical/high patches; inspect overdue exceptions."},
	{"PM-07", "Production deployment is approved and change-controlled.",
		"Change ticket, approvers, deployment scope, maintenance window, test and recovery plan.",
		"Sample deployments; verify approvals precede production and separation of duties where required."},
	{"PM-08", "Patches are tested before broad production rollout, proportionate to risk and system criticality.",
		"Pilot group, test results, compatibility and health checks, go/no-go approval.",
		"Trace a sample from test to production; inspect emergency-path rationale."},
	{"PM-09", "Deployment is staged and can be paused when failures or operational risks occur.",
		"Ring/wave configuration, thresholds, pause events, retries, rollout logs.",
		"Review a deployment with failures or simulate configured stop condition."},
	{"PM-10", "Endpoint installation and health are independently verified after deployment.",
		"Endpoint result, installed version/KB/package, reboot status, fresh inventory, health evidence.",
		"Compare reported status with endpoint or independent configuration evidence."},
	{"PM-11", "Failures, unavailable patches, and patch exceptions are owned and time-bound.",
		"Failed endpoint list, tickets, exception owner, rationale, compensating controls, expiry/review.",
		"Sample exceptions and verify approval, risk acceptance, review, and closure evidence."},
	{"PM-12", "Failed or harmful changes have documented recovery arrangements.",
		"Rollback/uninstall support, restore/reimage procedure, backup status, recovery test, incident record.",
		"Inspect recovery plan and evidence of exercise; verify it is appropriate for sampled patch types."},
	{"PM-13", "Privileged access to patch policy, package approval, deployment, and keys is restricted and logged.",
		"Role assignments, MFA/access logs, key custody/rotation, admin activity audit trail.",
		"Sample privileged accounts/actions; verify authorization and periodic review."},
	{"PM-14", "Patch records and audit trails are complete, protected, searchable, and retained under policy.",
		"Append-only/tamper-evident audit events, retention settings, export manifest, access logs.",
		"Trace patch lifecycle end to end; verify log retention and integrity against applicable requirements."},
	{"PM-15", "Patch compliance is measured and reported to appropriate governance forums.",
		"Compliance reports, overdue metrics, risk exceptions, meeting packs/minutes, action tracking.",
		"Recalculate a sample metric and trace reporting/escalation."},
	{"PM-16", "Patch management service and repository are secured, backed up, monitored, and recoverable.",
		"Hardening baseline, vulnerability results, backup records, restore tests, capacity and monitoring alerts.",
		"Inspect system controls and restore evidence; confirm management systems themselves are patched."},
	{"PM-17", "Unsupported and end-of-life software is identified and risk-managed.",
		"EOL inventory, upgrade/removal plan, risk acceptance, compensating controls.",
		"Sample end-of-life assets and inspect remediation/exception ownership."},
}

// References is template §9.
var References = []Reference{
	{1, "RBI", "Master Direction on Information Technology Governance, Risk, Controls and Assurance Practices, 2023", "https://systemhealth.rbi.org.in/Scripts/BS_ViewMasDirections.aspx_id%3D12562%283%29.html", ""},
	{2, "RBI", "Master Directions on Cyber Resilience and Digital Payment Security Controls for non-bank Payment System Operators", "https://systemhealth.rbi.org.in/Scripts/BS_ViewMasDirections.aspx_id%3D12715%281%29.html", ""},
	{3, "SEBI", "Cybersecurity and Cyber Resilience Framework (CSCRF) for SEBI Regulated Entities, circular dated 20 August 2024", "https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res-_85964.html", ""},
	{4, "SEBI", "CSCRF framework document", "https://www.sebi.gov.in/sebi_data/attachdocs/aug-2024/1724326790365.pdf", ""},
	{5, "SEBI", "CSCRF FAQs, June 2025", "https://www.sebi.gov.in/sebi_data/faqfiles/jun-2025/1749647139924.pdf", ""},
	{6, "CERT-In", "Directions under Section 70B", "https://www.cert-in.org.in/Directions70B.jsp", ""},
	{7, "MeitY", "Guidelines on Information Security Practices for Government Entities", "https://www.meity.gov.in/writereaddata/files/Guidelines%20on%20Information%20Security%20Practices%20for%20Government%20Entities.pdf", ""},
	{8, "IRDAI", "Information and Cyber Security Guidelines, 2023 document page", "https://irdai.gov.in/document-detail?documentId=3314780", ""},
	{9, "IRDAI", "Guidelines on Information and Cyber Security for insurance intermediaries, 2022", "https://irdai.gov.in/document-detail?documentId=1354286", ""},
	{10, "NIST", "SP 800-40 Rev. 4: Guide to Enterprise Patch Management Planning", "https://csrc.nist.gov/pubs/sp/800/40/r4/final", "useful process guidance, not an Indian regulation."},
}

// evidenceDefs is template §6: id, item, file in the package.
var evidenceDefs = []struct{ id, item, file string }{
	{"E-001", "Approved patch policy", "evidence/E-001-policy.csv"},
	{"E-002", "In-scope endpoint and software inventory", "evidence/E-002-inventory.csv"},
	{"E-003", "Patch catalog and risk priority", "evidence/E-003-catalog.csv"},
	{"E-004", "Transfer manifest and gateway receipt", "evidence/E-004-transfers.csv"},
	{"E-005", "Signature/hash/scan verification", "evidence/E-005-verification.csv"},
	{"E-006", "Change approvals and pilot results", "evidence/E-006-approvals.csv"},
	{"E-007", "Endpoint install/reboot/health results", "evidence/E-007-endpoint-results.csv"},
	{"E-008", "Exceptions, failures, recovery actions", "evidence/E-008-exceptions-failures.csv"},
	{"E-009", "Privileged access and audit events", "evidence/E-009-privileged-access.csv"},
	{"E-010", "Governance reporting and corrective actions", "evidence/E-010-governance.csv"},
}

// templateSignoffRows are the template §8 placeholders per role.
var templateSignoffComment = map[string]string{
	"Compliance/legal reviewer": "Applicability and mapping confirmation",
	"Independent auditor":       "Audit conclusion, if issued",
}
