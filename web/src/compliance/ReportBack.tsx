// Sections 5–9 of the auditor report.
import { useState } from "react";
import type { CompliancePack, DeadlineRule, EvidenceItem, PriorityTimeliness, TimelinessPair } from "./types";
import { asLines, fmtDate, fmtStamp, OutcomeBadge, safeHttpUrl, SeverityBadge, Txt } from "./format";
import { EvidenceIds, Section } from "./ReportFront";
import {
  CALC_INTRO, CALC_RULES, CLOCK_START_LABELS, COMPLIANT_ON_TIME, DEADLINES_INTRO, EVIDENCE_INTRO, EVIDENCE_ITEMS, EXPORT_DISCLOSURE,
  EXPORT_INTEGRITY, EXPORT_INTEGRITY_INTRO, PRIORITY_LABELS, REFERENCES_INTRO, SEBI_NOTE, SIGNOFF_ROLES,
} from "./templateText";

type OutcomeKey = "compliant" | "verified_late" | "overdue" | "pending" | "failed" | "offline" | "exception" | "not_applicable";
const OUTCOME_COLS: OutcomeKey[] = ["compliant", "verified_late", "overdue", "pending", "failed", "offline", "exception", "not_applicable"];
const OUTCOME_HEAD: Record<OutcomeKey, string> = {
  compliant: "Compliant on time", verified_late: "Verified late", overdue: "Overdue", pending: "Pending", failed: "Failed",
  offline: "Offline / stale", exception: "Approved exception", not_applicable: "Not applicable",
};

/** Template §5.1 rows; "High / critical" covers both priorities. */
const DEADLINE_ROWS: { label: string; priorities: string[] }[] = [
  { label: "Emergency / actively exploited", priorities: ["emergency"] },
  { label: "High / critical", priorities: ["critical", "high"] },
  { label: "Moderate", priorities: ["moderate"] },
  { label: "Low", priorities: ["low"] },
];

/** One value, or "critical: x; high: y" when the merged priorities differ. */
function merged(rules: DeadlineRule[], get: (d: DeadlineRule) => string): string {
  const vals = rules.map(get);
  if (vals.every((v) => v === vals[0])) return vals[0] ?? "";
  return rules.map((d, i) => `${PRIORITY_LABELS[d.priority] ?? d.priority}: ${vals[i] || "—"}`).join("; ");
}

function days(n: number): string {
  return `${n} day${n === 1 ? "" : "s"}`;
}

function PairsTable({ pairs }: { pairs: TimelinessPair[] }) {
  return (
    <div className="crep-wide">
      <table className="crep-table crep-pairs">
        <thead>
          <tr>
            <th>Endpoint</th><th>Update</th><th>Priority</th><th>Released</th><th>Acquired</th><th>Approved</th>
            <th>Deadline</th><th>Installed</th><th>Verified</th><th>Outcome</th>
          </tr>
        </thead>
        <tbody>
          {pairs.map((p, i) => (
            <tr key={`${p.endpoint_id}|${p.package_id}|${i}`}>
              <td className="crep-wrap">{p.hostname || p.endpoint_id}</td>
              <td className="crep-wrap">{p.title || p.package_id}{p.kb && <div className="crep-cell-muted">{p.kb}</div>}</td>
              <td>{PRIORITY_LABELS[p.priority] ?? p.priority}</td>
              <td className="nowrap">{fmtDate(p.release_date) || "—"}</td>
              <td className="nowrap">{fmtDate(p.acquired_at) || "—"}</td>
              <td className="nowrap">{fmtDate(p.approved_at) || "—"}</td>
              <td className="nowrap">{fmtDate(p.deadline) || "—"}{p.deadline_source && <div className="crep-cell-muted">{p.deadline_source}</div>}</td>
              <td className="nowrap">{fmtDate(p.installed_at) || "—"}</td>
              <td className="nowrap">{fmtDate(p.verified_at) || "—"}</td>
              <td><OutcomeBadge outcome={p.outcome} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TimelinessTable({ rows }: { rows: PriorityTimeliness[] }) {
  const sum = (k: OutcomeKey | "pairs" | "past_deadline_open") => rows.reduce((s, r) => s + r[k], 0);
  const total = sum("pairs");
  const onTime = total ? (sum("compliant") / total) * 100 : null;
  const pct = (p: number | null) => (p === null ? "—" : `${p.toFixed(1)}%`);
  return (
    <div className="crep-wide">
      <table className="crep-table crep-timeliness">
        <thead>
          <tr>
            <th>Priority</th><th className="num">Endpoint/update pairs</th>
            {OUTCOME_COLS.map((k) => <th key={k} className="num">{OUTCOME_HEAD[k]}</th>)}
            <th className="num">Open past deadline</th><th className="num">On time</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && <tr><td colSpan={OUTCOME_COLS.length + 4} className="crep-empty">No applicable endpoint/update pairs in this period.</td></tr>}
          {rows.map((r) => (
            <tr key={r.priority}>
              <td>{PRIORITY_LABELS[r.priority] ?? r.priority}</td>
              <td className="num">{r.pairs}</td>
              {OUTCOME_COLS.map((k) => <td key={k} className={`num ${(k === "overdue" || k === "verified_late") && r[k] ? "crep-bad" : ""}`}>{r[k]}</td>)}
              <td className={`num ${r.past_deadline_open ? "crep-bad" : ""}`}>{r.past_deadline_open}</td>
              <td className="num">{r.pairs ? pct(r.pct_on_time) : "—"}</td>
            </tr>
          ))}
          {rows.length > 1 && (
            <tr className="crep-total">
              <td>Total</td><td className="num">{total}</td>
              {OUTCOME_COLS.map((k) => <td key={k} className="num">{sum(k)}</td>)}
              <td className="num">{sum("past_deadline_open")}</td>
              <td className="num">{pct(onTime)}</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export function TimelinessSection({ pack, printing }: { pack: CompliancePack; printing: boolean }) {
  const [open, setOpen] = useState(false);
  const deadlines = pack.profile.deadlines;
  const tl = pack.timeliness;
  return (
    <Section n={5} title="Patch timeliness and compliance calculation">
      <h3 className="crep-h3">5.1 Policy-defined deadlines</h3>
      <p>{DEADLINES_INTRO}</p>
      <table className="crep-table">
        <thead>
          <tr><th>Priority / classification</th><th className="num">Organization-defined maximum time</th><th>Source / policy</th><th>Clock start definition</th><th>Allowed exception process</th></tr>
        </thead>
        <tbody>
          {DEADLINE_ROWS.map((row) => {
            const rules = row.priorities.map((p) => deadlines.find((d) => d.priority === p)).filter((d): d is DeadlineRule => !!d);
            if (rules.length === 0) return <tr key={row.label}><td>{row.label}</td><td colSpan={4} className="crep-empty">Not configured</td></tr>;
            return (
              <tr key={row.label}>
                <td>{row.label}</td>
                <td className="num">{merged(rules, (d) => days(d.max_days))}</td>
                <td><Txt v={merged(rules, (d) => d.source)} /></td>
                <td>{merged(rules, (d) => CLOCK_START_LABELS[d.clock_start] ?? d.clock_start)}</td>
                <td><Txt v={merged(rules, (d) => d.exception_process)} /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="crep-callout"><b>Important SEBI note:</b> {SEBI_NOTE}</p>

      <h3 className="crep-h3">5.2 Calculation rules</h3>
      <p>{CALC_INTRO}</p>
      <ul className="crep-list crep-list-tight">{CALC_RULES.map((r) => <li key={r}>{r}</li>)}</ul>
      <p><b>Compliant on time</b> {COMPLIANT_ON_TIME}</p>

      <h3 className="crep-h3">Timeliness summary {tl.as_of && <span className="crep-muted">· as of {fmtStamp(tl.as_of)}</span>}</h3>
      <TimelinessTable rows={tl.by_priority} />
      <p className="crep-note">
        Approved exceptions are reported separately and are not counted as patched. “Verified late” means installed and verified after the
        deadline: a breach, not compliant on time. Offline or stale endpoints are not counted as compliant.
      </p>

      <h3 className="crep-h3">
        Endpoint/update detail <span className="crep-muted">· {tl.pairs_total} pair{tl.pairs_total === 1 ? "" : "s"}, population-wide, worst first</span>
      </h3>
      {tl.pairs_truncated && (
        <p className="crep-note">Showing the first {tl.pairs.length} of {tl.pairs_total}. The evidence package (E-007) lists every pair.</p>
      )}
      {tl.pairs.length === 0 ? <p className="crep-empty">No endpoint/update pairs.</p> : (
        <>
          <button type="button" className="btn btn-sm crep-screen-only" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
            {open ? "Hide" : "Show"} per endpoint/update table
          </button>
          {(open || printing) && <PairsTable pairs={tl.pairs} />}
        </>
      )}
    </Section>
  );
}

function evidenceRows(items: EvidenceItem[]): EvidenceItem[] {
  const byId = new Map(items.map((e) => [e.id, e]));
  const fixed = EVIDENCE_ITEMS.map(([id, item]) => byId.get(id) ?? {
    id, item, source_system: "", period: "", scope: "", sha256: "", records: null, confidentiality: "", included: "Not provided", complete: false, note: "",
  });
  const extra = items.filter((e) => !EVIDENCE_ITEMS.some(([id]) => id === e.id));
  return [...fixed, ...extra];
}

export function EvidenceSection({ pack }: { pack: CompliancePack }) {
  const rows = evidenceRows(pack.evidence_register);
  const ac = pack.audit_chain;
  return (
    <Section n={6} title="Evidence register and export manifest">
      <p>{EVIDENCE_INTRO}</p>
      <div className="crep-wide">
        <table className="crep-table crep-evidence">
          <colgroup><col className="w-eid" /><col /><col /><col /><col /><col className="w-hash" /><col /><col /></colgroup>
          <thead>
            <tr><th>Evidence ID</th><th>Evidence item</th><th>Source system</th><th>Period / timestamp</th><th>Scope</th><th>Integrity hash (SHA-256)</th><th>Confidentiality class</th><th>Included / link</th></tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td className="crep-mono nowrap"><b>{e.id}</b></td>
                <td>
                  {e.item}
                  {e.records !== null && <div className="crep-cell-muted">{e.records} record{e.records === 1 ? "" : "s"}</div>}
                  {e.complete === false && <div className="crep-cell-warn">Incomplete{e.note ? `: ${e.note}` : ""}</div>}
                  {e.complete !== false && e.note && <div className="crep-cell-muted">{e.note}</div>}
                </td>
                <td><Txt v={e.source_system} /></td>
                <td><Txt v={e.period} /></td>
                <td><Txt v={e.scope} /></td>
                <td>{e.sha256 ? <code className="crep-hash">{e.sha256}</code> : <span className="crep-empty">—</span>}</td>
                <td><Txt v={e.confidentiality} /></td>
                <td className="crep-wrap"><Txt v={e.included} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 className="crep-h3">Export integrity and handling</h3>
      <p>{EXPORT_INTEGRITY_INTRO}</p>
      <ul className="crep-list crep-list-tight">{EXPORT_INTEGRITY.map((x) => <li key={x}>{x}</li>)}</ul>
      <p>{EXPORT_DISCLOSURE}</p>
      <div className="crep-callout">
        <p><b>This report:</b> endpoint/update evidence is population-wide for the reporting period (all enrolled endpoints).
          {pack.meta.redacted ? " Hostnames, IP addresses and user IDs are pseudonymised." : " Hostnames are shown unredacted; handle as confidential."}
          {" "}The evidence package (ZIP) contains report.md, summary.json, the E-001 to E-010 CSV files, manifest.json with the SHA-256 of every
          file, and manifest.sig (Ed25519 signature with the audit-signing key). Gaps are disclosed under Scope limitations (section 8).</p>
        {ac && (
          <p>
            <b>Audit trail integrity:</b>{" "}
            {ac.ok === true && <>hash chain verified ({ac.events} events, head sequence {ac.head_seq}).</>}
            {ac.ok === false && <span className="crep-bad">hash chain verification failed at sequence {ac.first_bad_seq}{ac.error ? ` (${ac.error})` : ""}.</span>}
            {ac.ok === null && <>not verified{ac.error ? ` (${ac.error})` : ""}.</>}
          </p>
        )}
      </div>
    </Section>
  );
}

export function FindingsSection({ pack }: { pack: CompliancePack }) {
  return (
    <Section n={7} title="Findings and corrective action plan">
      <div className="crep-wide">
        <table className="crep-table crep-findings">
          <thead>
            <tr>
              <th>Finding ID</th><th>Control / source</th><th>Observation and evidence</th><th>Risk / impact</th><th>Severity</th>
              <th>Root cause</th><th>Corrective action</th><th>Owner</th><th>Due date</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {pack.findings.length === 0 && <tr><td colSpan={10} className="crep-empty">No findings recorded for this period.</td></tr>}
            {pack.findings.map((f) => (
              <tr key={f.id}>
                <td className="crep-mono nowrap">{f.id}</td>
                <td><span className="crep-mono">{f.control}</span>{f.source && <div className="crep-cell-muted">{f.source}</div>}</td>
                <td>
                  {f.title && <b>{f.title}. </b>}{f.observation}
                  {f.affected_count > 0 && (
                    <div className="crep-cell-muted">
                      Affected: {f.affected_count}{f.affected.length ? ` (${f.affected.join(", ")}${f.affected_count > f.affected.length ? ", …" : ""})` : ""}
                    </div>
                  )}
                  <EvidenceIds ids={f.evidence_ids} />
                </td>
                <td><Txt v={f.risk} /></td>
                <td><SeverityBadge severity={f.severity} /></td>
                <td><Txt v={f.root_cause} /></td>
                <td><Txt v={f.corrective_action} /></td>
                <td><Txt v={f.owner} /></td>
                <td className="nowrap"><Txt v={fmtDate(f.due_date) || f.due_date} /></td>
                <td><Txt v={f.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 className="crep-h3">Risk acceptance / exception register</h3>
      <div className="crep-wide">
        <table className="crep-table crep-exceptions">
          <thead>
            <tr>
              <th>Exception ID</th><th>Endpoint/system scope</th><th>Patch / vulnerability</th><th>Reason patch is not applied</th>
              <th>Compensating controls</th><th>Risk owner / approver</th><th>Opened</th><th>Expiry / review date</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {pack.exceptions.length === 0 && <tr><td colSpan={9} className="crep-empty">No patch exceptions in this period.</td></tr>}
            {pack.exceptions.map((x, i) => (
              <tr key={x.exception_id || i}>
                <td className="crep-mono crep-wrap">{x.exception_id}</td>
                <td className="crep-wrap">{x.scope || x.endpoint_id}</td>
                <td className="crep-wrap">{x.patch || x.package_id}</td>
                <td>{x.reason}</td>
                <td><Txt v={x.compensating_controls} /></td>
                <td><Txt v={[x.owner, x.approver].filter(Boolean).join(" / ")} /></td>
                <td className="nowrap">{fmtDate(x.opened) || "—"}</td>
                <td className="nowrap">{fmtDate(x.expires) || "—"}</td>
                <td><Txt v={x.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

export function SignOffSection({ pack }: { pack: CompliancePack }) {
  const byRole = new Map(pack.signoff.map((s) => [s.role.trim().toLowerCase(), s]));
  const fixed = SIGNOFF_ROLES.map(([role, hint]) => ({ hint, row: byRole.get(role.toLowerCase()) ?? { role, name: "", comments: "", date: "" } }));
  const extra = pack.signoff.filter((s) => !SIGNOFF_ROLES.some(([r]) => r.toLowerCase() === s.role.trim().toLowerCase()));
  const rows = [...fixed, ...extra.map((row) => ({ hint: "Comments", row }))];
  const limitations = [...pack.scope_limitations.auto, ...asLines(pack.scope_limitations.profile)];
  return (
    <Section n={8} title="Auditor review and sign-off">
      <table className="crep-table crep-signoff">
        <thead><tr><th>Role</th><th>Name</th><th>Conclusion / comments</th><th>Date</th></tr></thead>
        <tbody>
          {rows.map(({ hint, row }, i) => (
            <tr key={`${row.role}|${i}`}>
              <td><b>{row.role}</b></td>
              <td>{row.name || <span className="crep-blank" aria-label="blank" />}</td>
              <td>{row.comments || <span className="crep-empty crep-hint">{hint}</span>}</td>
              <td className="nowrap">{fmtDate(row.date) || row.date || <span className="crep-blank" aria-label="blank" />}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p><b>Scope limitations:</b></p>
      {limitations.length === 0 ? <p className="crep-empty">None recorded.</p> : (
        <ul className="crep-list crep-list-tight">{limitations.map((s, i) => <li key={i}>{s}</li>)}</ul>
      )}
      <p><b>Management response:</b> {pack.management_response || <span className="crep-empty">No management response recorded.</span>}</p>
    </Section>
  );
}

export function ReferencesSection({ pack }: { pack: CompliancePack }) {
  return (
    <Section n={9} title="Official references for mapping maintenance">
      <p>{REFERENCES_INTRO}</p>
      <ol className="crep-list crep-refs">
        {pack.references.map((r, i) => {
          const url = safeHttpUrl(r.url);
          return (
            <li key={i}>
              {r.label ? `${r.label}, ` : ""}<span className="crep-ref-title">{r.title}</span>{r.note ? <> — {r.note}</> : "."}
              {url && <div><a href={url} target="_blank" rel="noopener noreferrer" className="crep-url">{url}</a></div>}
              {!url && r.url && <div className="crep-url">{r.url}</div>}
            </li>
          );
        })}
      </ol>
      <p className="crep-end">End of report · {pack.meta.report_id || "—"} · generated {fmtStamp(pack.meta.generated_at) || "—"}</p>
    </Section>
  );
}
