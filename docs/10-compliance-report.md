# 10 — Auditor compliance report

DSS Patcher generates the owner's **Patch Management Compliance Report** template for an auditor:
the report itself (Markdown; the console prints it to PDF), a machine-readable summary, the
evidence files and a signed manifest. This page explains what the report contains, which parts
the product computes and which the organisation records, and how to verify an evidence package.

The report **never** says an organisation is "RBI compliant" or "SEBI compliant". Regulatory rows
are *candidate mappings* until a compliance reviewer records applicability and a result; until then
their conclusion is **"Not assessed — needs compliance review"**. Missing or stale endpoint
telemetry is never counted as compliant. Approved exceptions are reported separately and never
counted as patched. Every number comes from dated records in the server, and gaps are listed under
"Scope limitations".

## Where it is

| What | API | Role |
|---|---|---|
| Report profile (organisation facts, deadlines, mappings, manual controls, sign-off) | `GET /api/reports/profile`, `PUT /api/reports/profile`, `GET /api/reports/profile/history` | read: viewer; write: admin, super admin |
| Report (JSON, what the console renders) | `GET /api/reports/compliance-pack?from=YYYY-MM-DD&to=YYYY-MM-DD[&redact=1][&tz=Area/City]` | viewer |
| Evidence package (signed ZIP) | `GET /api/reports/compliance-pack.zip?…` (same parameters) | viewer |
| Report as a PDF file | `GET /api/reports/compliance-pack.pdf?…` (same parameters) | viewer |

**Who can generate it: every signed-in role** (viewer and up) generates the report, the PDF and
the signed evidence package; only admins and the super admin edit the report profile.

Console: Reports → **Compliance report** (period picker, Generate, Download PDF, Download evidence
package, Redact hostnames; **Download PDF** fetches a real PDF made by the server, named
`DSS-Patcher-compliance-report-<from>_<to>-<report id>.pdf`, no browser print dialog) and Reports → **Report profile**. Exact JSON fields: docs/05-api.md
"v1.9 additions — auditor compliance report".

Every generation (JSON, PDF or ZIP) is audited as `report.compliance_generated` with who, the period, the
report ID, the profile version and, for the ZIP, the SHA-256 of `manifest.json`.

## The report profile

What the product cannot know is recorded once by an admin and versioned: each save is a new
version (who, when, SHA-256; audited `report.profile_updated` with the changed fields). The report
states the profile version it used.

| Field | Used in |
|---|---|
| `legal_entity`, `regulated_activity`, `regulators` (RBI, SEBI, IRDAI, PFRDA, MeitY, CERT-In, other), `entity_category`, `assessment_owner`, `independent_reviewer`, `systems_in_scope`, `endpoint_types`, `exclusions` | §2.1 (the operating systems and application vendors are computed) |
| `offline_model` (acquisition zone, transfer boundary, quarantine, repository, endpoint communications, egress evidence) | §2.2, PM-04 |
| `deadlines` (per priority emergency / critical / high / moderate / low: `max_days`, `source`, `clock_start` release / acquired / approved, `exception_process`) | §5.1 and every deadline computation. **Defaults** come from `patch_deadlines` (critical 7 d, important → high 30 d, moderate 60 d, low 90 d; emergency = the critical value) with a source that says they are product defaults to be confirmed. |
| `policy` (version, approved by, approved at, review date, reference) | PM-01, E-001, findings |
| `regulatory_mappings` | §4. Prefilled with the template's seven rows, `applicable: "unknown"`. A row is concluded only when `applicable` is yes/no **and** a `reviewer` is recorded. |
| `manual_controls` (`PM-01` … `PM-17`: status, evidence reference, note) | Controls the product cannot conclude (see below) |
| `overall_assessment` (status, rationale) | Optional reviewer conclusion; the computed suggestion stays visible |
| `signoff`, `scope_limitations`, `management_response`, `confidentiality_class` | §8, §6 |

## How the numbers are computed

**Scope.** In-scope endpoints are all enrolled endpoints that are not retired. Everything is
population-wide; nothing is sampled.

**Endpoint/update pairs (§5.2).** For every catalog package that is approved or still quarantined
(rejected and revoked packages are not required), a pair exists for each in-scope endpoint that is
targeted by an install deployment, needs the package according to its inventory, or has an
exception for it. Per pair:

- *Priority*: from the package severity (critical → critical, important → high, moderate, low);
  **emergency** when an emergency deployment exists for the package.
- *Deadline*: clock start (vendor release date, the date the bundle was received, or the approval
  date, per the profile) + the priority's `max_days`. No clock start → no deadline (disclosed).
- *Outcome*, evaluated at **as-of** = the end of the period (or now, if the period has not ended):
  `compliant` (installed and verified by inventory by the deadline), `verified_late` (verified
  after the deadline), `exception` (an active approved exception; never counted as patched),
  `not_applicable` (the deployment found it not applicable, or the package is superseded — the
  superseding update carries the requirement), `failed`, `offline` (the endpoint has no current
  inventory), `overdue` (past the deadline) or `pending` (within the deadline).
- `past_deadline` marks pairs whose deadline has passed and that are not verified (failed and
  offline pairs included; exceptions excluded).
- Installation time is the first `installed` / `pending_reboot` report from the agent;
  verification time is when inventory proved the install (the evidence line is kept).

**Executive summary (§1).**

| Measure | Definition |
|---|---|
| In-scope endpoints | enrolled, not retired |
| Endpoints with current inventory | not stale, offline, awaiting first check-in or lost after install |
| Endpoints compliant with applicable patch policy | current inventory, not on an unsupported OS build, and no pair that is overdue, failed, offline, under exception, verified late or otherwise past its deadline |
| Endpoints overdue | at least one pair past its deadline |
| Endpoints with stale inventory | the complement of "current inventory" |
| Endpoints pending restart | reboot pending |
| Approved patch exceptions still active | active (not revoked, not expired) |
| Emergency patches open past target | packages handled as emergency with at least one pair past its deadline |
| Findings by severity | from the generated findings (below) |
| Evidence completeness | share of E-001 … E-010 that have evidence (rules in the evidence register) |

Percentages are of in-scope endpoints, with one decimal; with nothing to measure they are 0, never 100.

**Overall assessment (suggestion).** Not assessed when no endpoints are enrolled or more than half
of the controls are not assessed; Non-compliant when a control is non-compliant or a critical
finding is open; Compliant only when every control is compliant (or not applicable) and no high or
medium finding is open; otherwise Partially compliant. The rationale always repeats the key numbers
and the warning that a high patch percentage alone does not establish compliance. The profile can
set the reviewer's conclusion; the report then shows both.

## Controls: automatic and manual

A control is **automatic** where the product holds the evidence. When the automatic result is
"Not assessed" (no data in the period), the reviewer's `manual_controls` entry is used (source
`manual`). A manual entry never overrides an automatic result; its note and evidence reference are
shown next to it. Some automatic checks also accept a manual **evidence reference** as the missing
outside evidence (noted below).

| Control | Source | How it is evaluated |
|---|---|---|
| PM-01 Policy | **manual** | Product shows the profile's policy record and deadline table; status comes from the reviewer. |
| PM-02 Inventory | automatic | All in-scope endpoints current → Compliant (reconciliation with a CMDB is still the auditor's); up to 10 % without current inventory → Partially; more → Non-compliant. Stale update intelligence (> 8 days) caps it at Partially. |
| PM-03 Acquisition | automatic | Packages received in the period: vendor, source URL, SHA-256, vendor signature status, signed bundle. Invalid vendor signature → Non-compliant; missing source or unchecked signature → Partially. |
| PM-04 Transfer boundary | automatic + evidence ref | Bundles reconciled with signed transfer receipts. Unsigned receipts → Non-compliant; bundles without receipt → Partially; no egress-enforcement evidence (profile `offline_model.egress_evidence` or the PM-04 evidence reference) → Partially. |
| PM-05 Quarantine and verification | automatic | Intake checks of every bundle in the period (signature, payload hashes, replay, content scan). Without a configured scanner → Partially. |
| PM-06 Priority and deadlines | automatic | Emergency/critical pairs past deadline → Non-compliant; other overdue pairs or deadlines still citing the product default → Partially. |
| PM-07 Approval and change control | automatic | Every deployment and rollback that reached production in the period: the required number of distinct approvers, none the creator, every approval before activation, the package approved before the deployment, and (with `separation_of_duties`) the package approver not deploying. All good → Compliant; none → Non-compliant; some → Partially. Deployments created before approvals existed have no approval record and count as problems. |
| PM-08 Testing before broad rollout | **manual** | Product shows ring use and health checks; test results and go/no-go are outside the product. |
| PM-09 Staging and pause | automatic | Multi-ring deployments with an effective failure threshold (auto-pause); single-ring non-emergency deployments or no threshold → Partially. Pause events are listed. |
| PM-10 Verification | automatic | Verified pairs backed by an inventory evidence line; verifications without evidence or endpoints lost after install → Partially. |
| PM-11 Failures and exceptions | automatic | Exceptions complete (owner, reason, compensating controls, expiry; enforced at creation), not longer than a year; failed pairs past deadline → Partially. Nothing to sample → Not assessed. |
| PM-12 Recovery | automatic + evidence ref | Rollback support of approved packages; a completed rollback in the period or a recovery evidence reference → Compliant, else Partially. |
| PM-13 Privileged access | automatic + evidence ref | Admin and super admin accounts: MFA; privileged audit events. Compliant needs every privileged account with MFA **and** an access-review / key-custody evidence reference; otherwise Partially. |
| PM-14 Audit trail | automatic | Hash chain verified (a full walk at most hourly, incremental otherwise; `GET /api/audit/verify` always walks everything); broken → Non-compliant; no signed off-box export → Partially. |
| PM-15 Governance reporting | automatic + evidence ref | Earlier report generations in the period, plus a governance-pack evidence reference → Compliant; generations only → Partially; none → Not assessed (manual fallback). |
| PM-16 The patch service | automatic + evidence ref | Insecure lab mode → Non-compliant; recorded backups (`pmserver backup` audits `backup.created`) and a hardening / restore-test evidence reference → Compliant; otherwise Partially. |
| PM-17 End of life | automatic | Endpoints on a Windows build the vendor no longer updates (update intelligence). None, or all covered by an all-updates exception → Compliant; otherwise Partially; no intelligence → Not assessed. Application end-of-life is not tracked. |

## Findings (§7)

Generated from the data, numbered F-001… by severity: updates past deadline per priority
(emergency/critical → Critical, high → High, moderate → Medium, low → Low), updates verified late
(Medium), failed installations (High), endpoints without current inventory (High above 10 %, else
Medium), unsupported OS builds (High), deployments without complete approval evidence (High),
transfers without valid receipts (Medium), audit chain failure (Critical) or no off-box export
(Medium), privileged accounts without MFA (Medium), insecure lab mode (High), no approved policy
(Medium) or policy review overdue (Low), exceptions expiring within 7 days (Low), stale update
intelligence (Medium). Owner = the profile's assessment owner; due date = as-of + the deadline of
the matching priority; root cause "To be determined by the owner"; status Open. The three most
severe are the key findings in §1.

## Evidence register and package (§6)

| ID | File | Content | Complete when |
|---|---|---|---|
| E-001 | `evidence/E-001-policy.csv` | policy record and deadline table | an approver or reference is recorded |
| E-002 | `evidence/E-002-inventory.csv` | every endpoint: status, OS, groups, owner, criticality, last seen, inventory time, support status | endpoints exist |
| E-003 | `evidence/E-003-catalog.csv` | every catalog package: severity, priority, dates, approvals, hash, source, vendor signature | packages exist |
| E-004 | `evidence/E-004-transfers.csv` | receipts and bundles of the period, reconciled | records exist |
| E-005 | `evidence/E-005-verification.csv` | intake checks of every bundle of the period | records exist |
| E-006 | `evidence/E-006-approvals.csv` | deployments of the period: approvers and times, activation, rings, threshold, approval verdict | records exist |
| E-007 | `evidence/E-007-endpoint-results.csv` | every endpoint/update pair (the JSON lists at most 1000, worst first) | pairs exist |
| E-008 | `evidence/E-008-exceptions-failures.csv` | exceptions, failed targets, rollbacks, backups | always (none is a valid population) |
| E-009 | `evidence/E-009-privileged-access.csv` | accounts (role, MFA) and privileged audit events of the period (at most 50 000; the signed audit export has all) | chain verified and accounts exist |
| E-010 | `evidence/E-010-governance.csv` | report generations, profile versions, findings | report history or a governance reference |

The ZIP also holds `report.pdf` and `report.md` (sections 1–9 of the template, same headings and
order; section 10 is product requirements and is not part of a report; the PDF has a cover with the
DSS Patcher logo, the title block and the Important note, and a footer "DSS Patcher · <report id> ·
page N of M" on every page), `summary.json` (the JSON pack), `manifest.json`
(SHA-256 and size of every file, report ID, period, generation time, generated by, filters,
redaction flag, product version, signing key ID and fingerprint) and `manifest.sig` (Ed25519
signature of `manifest.json`, base64) made with the server's **audit-signing key**
(`<data_dir>/audit-signing.key`, the key that signs audit-export checkpoints; created on first use).
`signing-key.pub` is included for convenience only.

Verify a package offline with the public key obtained independently (`<data_dir>/audit-signing.pub`
of the server, or the key fingerprint recorded in runbook 07):

```bash
pmserver verify-report -zip compliance-CR-1A2B3C4D5E6F.zip -pub audit-signing.pub
# compliance package OK: report CR-…, period … to …, generated … by …, 13 files, key <fingerprint>
```

Any changed, added or removed file (`report.pdf` included: it is listed in `manifest.json`), or a
different key, fails verification. The evidence-register
hashes in `report.md` and `summary.json` are the same as in the manifest.

**Redaction** (`redact=1`): hostnames, endpoint IDs, IP addresses and product user IDs (actors,
approvers, creators, account names) become stable pseudonyms (`host-…`, `ep-…`, `ip-…`,
`user-…`): HMAC-SHA-256 with a random per-server salt, so the same host has the same pseudonym in
every report and names cannot be recovered by hashing guesses. Measures are identical; the
manifest and register say the copy is redacted.

## Scale

The pack reads cached fleet views (endpoint status and package needs) and one query per data set;
pairs are kept compact and evidence files are streamed into the ZIP (hashed once to fill the
register, written once). A 20 000-endpoint fleet with ten updates (200 000 pairs) builds in a few
seconds in the unit tests.

## Limits (disclosed in every report)

Endpoint status is the state at generation time; deadlines and verification times are evaluated
at the end of the period. Application end-of-life, vulnerability scan results, asset-criticality
rationale, network egress enforcement, test results, governance minutes and restore tests are not
recorded by the product and rely on the evidence references in the profile.
