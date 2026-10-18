import { useEffect, useMemo, useState } from "react";
import { api, ApiError, errMsg } from "../api";
import { personName, useCan } from "../auth";
import { ErrorBanner, PageHeader, Time } from "../components/ui";
import { shortHash, useLoad } from "../util";
import type { DeadlineRule, Exclusion, ManualControl, ProfileRecord, ReportProfile, SignOff } from "../compliance/types";
import { CLOCK_STARTS, REGULATORS, STATUS_VALUES } from "../compliance/types";
import { emptyProfile, normalizeProfileRecord, normalizeVersions, profileProblems, toProfilePayload } from "../compliance/normalize";
import { MappingsEditor } from "../compliance/MappingsEditor";
import { CLOCK_START_LABELS, CONTROLS, OFFLINE_MODEL_LABELS, PRIORITY_LABELS } from "../compliance/templateText";
import { RowsEditor, TextField, type Column } from "../compliance/ProfileParts";
import "../compliance/compliance.css";

const PROFILE_PATH = "/api/reports/profile";
const HISTORY_PATH = "/api/reports/profile/history";
/** Controls the product cannot evidence by itself (policy, pre-production testing): always offered. */
const DEFAULT_MANUAL = ["PM-01", "PM-08"];
const STATUS_OPTIONS = [{ value: "", label: "Not set" }, ...STATUS_VALUES.map((s) => ({ value: s, label: s }))];

const EXCLUSION_COLS: Column<Exclusion>[] = [
  { key: "system", label: "System (required)", placeholder: "Host, group or zone" },
  { key: "reason", label: "Reason (required)" },
  { key: "approved_by", label: "Approved by" },
  { key: "review_date", label: "Expiry / review date", kind: "date", width: "150px" },
];

const DEADLINE_COLS: Column<DeadlineRule>[] = [
  { key: "max_days", label: "Maximum time (days)", kind: "number", width: "110px" },
  { key: "source", label: "Source / policy", placeholder: "policy / regulator / OEM" },
  { key: "clock_start", label: "Clock start", kind: "select", options: CLOCK_STARTS.map((c) => ({ value: c, label: CLOCK_START_LABELS[c] })), width: "220px" },
  { key: "exception_process", label: "Allowed exception process", placeholder: "approval + compensating controls" },
];

const SIGNOFF_COLS: Column<SignOff>[] = [
  { key: "role", label: "Role (required)" },
  { key: "name", label: "Name" },
  { key: "comments", label: "Conclusion / comments", kind: "textarea" },
  { key: "date", label: "Date", kind: "date", width: "150px" },
];

type ManualRow = ManualControl & { id: string };
const MANUAL_COLS: Column<ManualRow>[] = [
  { key: "status", label: "Status", kind: "select", options: STATUS_OPTIONS, width: "180px" },
  { key: "evidence_ref", label: "Evidence reference", placeholder: "e.g. E-001, policy document v3" },
  { key: "note", label: "Rationale / note", kind: "textarea" },
];

export default function ReportProfilePage() {
  const canEdit = useCan("admin"); // PUT is admin / super_admin; everyone else reads
  const ro = !canEdit;
  const loaded = useLoad(async () => normalizeProfileRecord(await api.get<unknown>(PROFILE_PATH)), []);
  const history = useLoad(async () => normalizeVersions(await api.get<unknown>(HISTORY_PATH)), []);
  const [draft, setDraft] = useState<ReportProfile | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [allControls, setAllControls] = useState(false);

  const server: ProfileRecord | null = loaded.data;
  useEffect(() => { if (server && !draft) setDraft(server.profile); }, [server, draft]);
  const p = draft ?? server?.profile ?? emptyProfile();
  const dirty = useMemo(
    () => !!draft && !!server && JSON.stringify(toProfilePayload(draft)) !== JSON.stringify(toProfilePayload(server.profile)),
    [draft, server],
  );
  const problems = useMemo(() => (dirty ? profileProblems(p) : []), [dirty, p]);

  const set = <K extends keyof ReportProfile>(k: K, v: ReportProfile[K]) => {
    setSaved(null);
    setDraft((d) => ({ ...(d ?? p), [k]: v }));
  };

  const manualIds = CONTROLS.map((c) => c.id).filter((id) => allControls || DEFAULT_MANUAL.includes(id) || !!p.manual_controls[id]);
  const manualRows: ManualRow[] = manualIds.map((id) => ({ id, ...(p.manual_controls[id] ?? { status: "", evidence_ref: "", note: "" }) }));
  const setManual = (rows: ManualRow[]) => {
    const next = { ...p.manual_controls };
    for (const { id, ...rest } of rows) next[id] = rest;
    set("manual_controls", next);
  };

  const save = async () => {
    if (!draft || ro || problems.length) return;
    setSaving(true);
    setSaveError(null);
    try {
      const base = server && !server.is_default ? `?base_version=${server.version}` : "";
      const res = await api.put<unknown>(`${PROFILE_PATH}${base}`, toProfilePayload(draft));
      const next = normalizeProfileRecord(res);
      loaded.setData(next);
      setDraft(null);
      void history.reload();
      setSaved(`Saved as version ${next.version}.`);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setSaveError(`Someone else saved the profile since you opened it (${e.message}). Copy your changes, press Discard to load the latest version, then edit again.`);
      } else {
        setSaveError(`Save failed: ${errMsg(e)}`);
      }
    } finally {
      setSaving(false);
    }
  };

  const toggleRegulator = (r: string) =>
    set("regulators", p.regulators.includes(r) ? p.regulators.filter((x) => x !== r) : [...p.regulators, r]);

  return (
    <div className={`rprof ${ro ? "rprof-ro" : ""}`}>
      <PageHeader
        title="Report profile"
        sub={<>Organization details, deadlines, regulatory mapping and sign-off used by the compliance report. {ro ? "Read-only: only Admins can change it." : "Each save is kept as a new version."}</>}
      />
      <ErrorBanner error={loaded.error} />
      {server && (
        <div className="muted small">
          {server.is_default
            ? "Not saved yet: showing defaults (template rows and the policy deadlines)."
            : <>Version {server.version} · saved by {personName(server.edited_by) || "—"} · <Time value={server.edited_at} /> · <span className="mono" title={server.sha256}>{shortHash(server.sha256)}</span></>}
        </div>
      )}

      <section className="card">
        <h2>2.1 Organization and regulatory profile</h2>
        <div className="rprof-grid">
          <TextField label="Legal entity" value={p.legal_entity} onChange={(v) => set("legal_entity", v)} ro={ro} />
          <TextField label="Business / regulated activity" value={p.regulated_activity} onChange={(v) => set("regulated_activity", v)} ro={ro}
                     placeholder="Bank / NBFC / payment system operator / SEBI regulated entity / insurer / …" />
          <div className="field rprof-full">
            <span>Applicable regulator(s)</span>
            <div className="rprof-regs" role="group" aria-label="Applicable regulators">
              {REGULATORS.map((r) => (
                <button key={r} type="button" className={`chip ${p.regulators.includes(r) ? "chip-on" : ""}`} aria-pressed={p.regulators.includes(r)}
                        disabled={ro} onClick={() => toggleRegulator(r)}>{r}</button>
              ))}
            </div>
          </div>
          <TextField label="Entity category / size category" value={p.entity_category} onChange={(v) => set("entity_category", v)} ro={ro} />
          <TextField label="Assessment owner" value={p.assessment_owner} onChange={(v) => set("assessment_owner", v)} ro={ro} hint="Name / role. Also the owner of every generated finding." />
          <TextField label="Independent reviewer" value={p.independent_reviewer} onChange={(v) => set("independent_reviewer", v)} ro={ro} hint="Name / role" />
          <TextField label="Evidence confidentiality class" value={p.confidentiality_class} onChange={(v) => set("confidentiality_class", v)} ro={ro} hint="Shown in the evidence register (default Confidential)." />
          <TextField label="Systems in scope" value={p.systems_in_scope} onChange={(v) => set("systems_in_scope", v)} ro={ro} multiline hint="Sites, business units, network zones" />
          <TextField label="Endpoint types in scope" value={p.endpoint_types} onChange={(v) => set("endpoint_types", v)} ro={ro} multiline hint="Workstations, servers, OT, appliances, etc. Operating systems come from inventory." />
        </div>
        <h3>Exclusions</h3>
        <RowsEditor rows={p.exclusions} columns={EXCLUSION_COLS} ro={ro} onChange={(v) => set("exclusions", v)} addLabel="Add exclusion"
                    blank={() => ({ system: "", reason: "", approved_by: "", review_date: "" })} empty="No exclusions." />
      </section>

      <section className="card">
        <h2>2.2 Offline update-delivery model</h2>
        <div className="rprof-grid">
          {OFFLINE_MODEL_LABELS.map(([key, label, hint]) => (
            <TextField key={key} label={label} hint={hint} multiline value={p.offline_model[key]} ro={ro}
                       onChange={(v) => set("offline_model", { ...p.offline_model, [key]: v })} />
          ))}
        </div>
      </section>

      <section className="card">
        <h2>Patch policy <span className="muted small">· evidence E-001</span></h2>
        <div className="rprof-grid rprof-grid-3">
          <TextField label="Policy version" value={p.policy.version} onChange={(v) => set("policy", { ...p.policy, version: v })} ro={ro} />
          <TextField label="Approved by" value={p.policy.approved_by} onChange={(v) => set("policy", { ...p.policy, approved_by: v })} ro={ro} />
          <TextField label="Approved on" type="date" value={p.policy.approved_at.slice(0, 10)} onChange={(v) => set("policy", { ...p.policy, approved_at: v })} ro={ro} />
          <TextField label="Next review date" type="date" value={p.policy.review_date.slice(0, 10)} onChange={(v) => set("policy", { ...p.policy, review_date: v })} ro={ro} />
          <TextField label="Reference" value={p.policy.reference} onChange={(v) => set("policy", { ...p.policy, reference: v })} ro={ro} hint="Document ID or repository link" full />
        </div>
      </section>

      <section className="card">
        <h2>5.1 Policy-defined deadlines</h2>
        <p className="hint">Defaults come from the deployment policy deadlines per severity. Set them from the entity's approved policy and any binding regulation (1–3650 days).</p>
        <RowsEditor rows={p.deadlines} columns={DEADLINE_COLS} ro={ro} fixedRows onChange={(v) => set("deadlines", v)}
                    lead={{ label: "Priority", render: (r) => <b>{PRIORITY_LABELS[r.priority] ?? r.priority}</b> }} />
      </section>

      <section className="card">
        <h2>4. Regulatory mappings</h2>
        <p className="hint">Candidate mappings. The report shows “Not assessed — needs compliance review” until Applicable is Yes or No and a reviewer is recorded.</p>
        <MappingsEditor rows={p.regulatory_mappings} ro={ro} onChange={(v) => set("regulatory_mappings", v)} />
      </section>

      <section className="card">
        <div className="section-head">
          <div>
            <h2>3. Manual control assessments</h2>
            <div className="hint">For controls the product cannot evidence on its own (PM-01 policy, PM-08 pre-production testing, …). Anything not set is reported as “Not assessed”.</div>
          </div>
          <button type="button" className="btn btn-sm" onClick={() => setAllControls((a) => !a)}>{allControls ? "Show only PM-01, PM-08 and filled-in" : "Show all 17 controls"}</button>
        </div>
        <RowsEditor rows={manualRows} columns={MANUAL_COLS} ro={ro} fixedRows onChange={setManual}
                    lead={{ label: "Control", render: (r) => <div><span className="rprof-ctl-id">{r.id}</span><div className="hint">{CONTROLS.find((c) => c.id === r.id)?.objective}</div></div> }} />
      </section>

      <section className="card">
        <h2>1. Overall assessment override</h2>
        <p className="hint">Leave “Use the computed assessment” unless the reviewer has concluded otherwise; the report then also shows the computed suggestion.</p>
        <div className="rprof-grid">
          <label className="field">
            <span>Overall assessment</span>
            <select value={p.overall_assessment.status} disabled={ro} onChange={(e) => set("overall_assessment", { ...p.overall_assessment, status: e.target.value })}>
              <option value="">Use the computed assessment</option>
              {STATUS_VALUES.filter((s) => s !== "Not applicable").map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <TextField label="Rationale" multiline value={p.overall_assessment.rationale} ro={ro}
                     onChange={(v) => set("overall_assessment", { ...p.overall_assessment, rationale: v })} />
        </div>
      </section>

      <section className="card">
        <h2>8. Auditor review and sign-off</h2>
        <RowsEditor rows={p.signoff} columns={SIGNOFF_COLS} ro={ro} onChange={(v) => set("signoff", v)} addLabel="Add sign-off row"
                    blank={() => ({ role: "", name: "", comments: "", date: "" })} />
        <div className="rprof-grid" style={{ marginTop: 12 }}>
          <TextField label="Scope limitations" multiline value={p.scope_limitations} onChange={(v) => set("scope_limitations", v)} ro={ro}
                     hint="One per line. Exclusions, unavailable evidence, sampling, platform limitations, reliance on third parties. Gaps the product detects are added automatically." />
          <TextField label="Management response" multiline value={p.management_response} onChange={(v) => set("management_response", v)} ro={ro} hint="Response and target dates." />
        </div>
      </section>

      <section className="card">
        <h2>Version history</h2>
        <ErrorBanner error={history.error} />
        {(history.data ?? []).length === 0 ? <div className="muted small">No saved versions yet.</div> : (
          <ul className="rprof-versions">
            {(history.data ?? []).map((v) => (
              <li key={v.version}>
                <b>v{v.version}</b><span>{personName(v.edited_by) || "—"}</span><Time value={v.edited_at} />
                {v.sha256 && <span className="mono muted" title={v.sha256}>{shortHash(v.sha256)}</span>}
              </li>
            ))}
          </ul>
        )}
      </section>

      {canEdit && (
        <div className="rprof-savebar">
          <div className="rprof-savebar-msg">
            <ErrorBanner error={saveError} />
            {problems.length > 0 && <ul className="problems">{problems.map((x) => <li key={x}>{x}</li>)}</ul>}
            {saved && !dirty && <span className="text-green">{saved}</span>}
            {dirty && problems.length === 0 && !saveError && <span className="muted">Unsaved changes</span>}
          </div>
          <button type="button" className="btn" disabled={(!dirty && !saveError) || saving} onClick={async () => { setSaveError(null); await loaded.reload(); setDraft(null); }}>Discard</button>
          <button type="button" className="btn btn-primary" disabled={!dirty || saving || problems.length > 0} onClick={() => void save()}>{saving ? "Saving…" : "Save"}</button>
        </div>
      )}
    </div>
  );
}
