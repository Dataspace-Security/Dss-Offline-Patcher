import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, ApiError, enc, errMsg } from "../api";
import { paths } from "../paths";
import { useCan } from "../auth";
import { TargetPreview } from "../components/TargetPreview";
import { STAGES_HINT, stageLabel } from "../components/deployLabels";
import { CountsBar, Empty, ErrorBanner, Mono, PageHeader, Pill, Time, patchScore, scoreTone } from "../components/ui";
import type { Deployment, DeploymentOperation, HealthCheck, NewDeployment, Package, RebootPolicy } from "../types";
import { splitList, toRFC3339, useLoad } from "../util";
import {
  autoName, decodeRings, fetchEndpoints, fetchFleet, fetchPolicy, humanDuration, localToUtcHHMM, policyDeadline,
  REBOOT_VALUES, ringCounts, ringMembers, toLocalInput, utcToLocalHHMM,
} from "../components/patchPlan";
import "../patch.css";

export function ringLabel(d: Deployment): string {
  const total = d.rings?.length ?? 0;
  if (total === 0) return "—";
  // current_ring is treated as a 0-based index into rings.
  const idx = Math.min(Math.max(d.current_ring, 0), total - 1);
  return `${idx + 1} / ${total}`;
}

/** "Stage N · <name>" of the current stage, or "" when there are no stages. */
function currentStageName(d: Deployment): string {
  const total = d.rings?.length ?? 0;
  if (total === 0) return "";
  const idx = Math.min(Math.max(d.current_ring, 0), total - 1);
  return stageLabel(d.rings?.[idx]?.name, idx);
}

export function DeploymentList() {
  const canCreate = useCan("operator");
  const { data, error } = useLoad(() => api.get<Deployment[]>("/api/deployments"), [], 5000);
  const pkgs = useLoad(() => api.get<Package[]>("/api/packages"), []);
  const fleet = useLoad(fetchFleet, []);
  const title = (id: string) => pkgs.data?.find((p) => p.package_id === id)?.title;
  const readyCount = (pkgs.data ?? []).filter((p) => p.state === "approved" && (fleet.data?.[p.package_id]?.needed ?? 0) > 0).length;

  return (
    <>
      <PageHeader title="Deployments" sub="Staged rollouts of approved packages · auto-refresh every 5s">
        {canCreate && <Link className="btn btn-primary" to="/deployments/new">New deployment</Link>}
      </PageHeader>
      <ErrorBanner error={error} />
      {data && data.length === 0 && (
        <Empty>
          No deployments yet.{" "}
          <Link to={`${paths.catalog()}?state=approved&needed=1`}>
            Catalog · approved &amp; needed{fleet.data && pkgs.data ? ` (${readyCount})` : ""}
          </Link>{" "}
          — open a package there and use <b>Patch this…</b>.
        </Empty>
      )}
      {data && data.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th><th>Package</th><th>State</th><th>Stage</th><th style={{ width: "28%" }}>Progress</th><th>Created</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.deployment_id}>
                <td>
                  <Link to={`/deployments/${enc(d.deployment_id)}`} className="cell-title">{d.name || d.deployment_id}</Link>
                  {d.emergency && <span className="flag-emergency">EMERGENCY</span>}
                  {d.operation === "rollback" && <span className="flag-emergency flag-rollback">ROLLBACK</span>}
                  <div className="cell-sub"><Mono>{d.deployment_id}</Mono></div>
                </td>
                <td>
                  <Link to={paths.catalog(d.package_id)}>{title(d.package_id) ?? <Mono>{d.package_id}</Mono>}</Link>
                </td>
                <td><Pill state={d.state} /></td>
                <td className="nowrap">
                  {ringLabel(d)}
                  {currentStageName(d) && <div className="cell-sub">{currentStageName(d)}</div>}
                </td>
                <td><CountsBar counts={d.counts ?? {}} compact /><SmallCounts d={d} /></td>
                <td><Time value={d.created_at} hideRel /><div className="cell-sub">{d.created_by}</div></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function SmallCounts({ d }: { d: Deployment }) {
  const c = d.counts ?? {};
  const total = Object.values(c).reduce<number>((a, v) => a + (v ?? 0), 0);
  if (!total) return null;
  const done = (c.verified ?? 0) + (c.not_applicable ?? 0);
  const sc = patchScore(c);
  return (
    <div className="cell-sub">
      <b className={`text-${scoreTone(sc.pct)}`}>{sc.pct}% {d.operation === "rollback" ? "removed" : "patched"}</b> · {done}/{total} done
      {(c.failed ?? 0) > 0 && <span className="text-red"> · {c.failed} failed</span>}
      {(c.pending_reboot ?? 0) > 0 && <span className="text-amber"> · {c.pending_reboot} reboot</span>}
      {(c.lost_after_install ?? 0) > 0 && <span className="text-red"> · {c.lost_after_install} lost</span>}
      {(c.deferred ?? 0) > 0 && <span className="text-amber"> · {c.deferred} deferred</span>}
    </div>
  );
}

type RingDraft = { name: string; groups: string };

export const REBOOT_POLICIES: { value: RebootPolicy; label: string; hint: string }[] = [
  { value: "never", label: "Never", hint: "The agent never reboots; endpoints report pending reboot." },
  { value: "in_window", label: "In a maintenance window", hint: "Reboot only inside a group maintenance window that allows reboots." },
  { value: "at_deadline", label: "At the deadline", hint: "Reboot when the deadline passes, even outside windows." },
];

function validPort(s: string): boolean {
  return /^\d+$/.test(s) && Number(s) >= 1 && Number(s) <= 65535;
}

export function NewDeploymentPage() {
  const [sp] = useSearchParams();
  const navigate = useNavigate();
  const canCreate = useCan("operator");
  const pkgs = useLoad(() => api.get<Package[]>("/api/packages"), []);
  const [operation, setOperation] = useState<DeploymentOperation>(sp.get("operation") === "rollback" ? "rollback" : "install");
  const rollback = operation === "rollback";

  const policy = useLoad(fetchPolicy, []);
  const eps = useLoad(fetchEndpoints, []);
  // Every setting can be prefilled from the query string (Patch this → Custom…).
  const qDeadline = sp.get("deadline");
  const qReboot = sp.get("reboot_policy") as RebootPolicy | null;
  const qNum = (k: string, def: string) => {
    const v = sp.get(k);
    return v !== null && /^\d+(\.\d+)?$/.test(v) ? v : def;
  };
  const [packageId, setPackageId] = useState(sp.get("package_id") ?? "");
  const [name, setName] = useState(sp.get("name") ?? "");
  const [nameTouched, setNameTouched] = useState(sp.has("name"));
  const [rings, setRings] = useState<RingDraft[]>(decodeRings(sp.get("rings")) ?? [
    { name: "Test machines", groups: "pilot" },
    { name: "All machines", groups: "all" },
  ]);
  const [maxFail, setMaxFail] = useState(qNum("max_failure_pct", "10"));
  const [maxRetries, setMaxRetries] = useState(qNum("max_retries", "2"));
  // Shown and edited in local time; the server stores HH:MM UTC.
  const [winStart, setWinStart] = useState(utcToLocalHHMM(sp.get("window_start") ?? ""));
  const [winEnd, setWinEnd] = useState(utcToLocalHHMM(sp.get("window_end") ?? ""));
  const [emergency, setEmergency] = useState(sp.get("emergency") === "1");
  const [justification, setJustification] = useState(sp.get("justification") ?? "");
  const [deadline, setDeadline] = useState(qDeadline && !isNaN(new Date(qDeadline).getTime()) ? toLocalInput(new Date(qDeadline)) : "");
  const [deadlineTouched, setDeadlineTouched] = useState(sp.has("deadline"));
  const [maxConcurrent, setMaxConcurrent] = useState(qNum("max_concurrent", "0"));
  const [rebootPolicy, setRebootPolicy] = useState<RebootPolicy>(qReboot && REBOOT_VALUES.includes(qReboot) ? qReboot : "never");
  const [ignoreWindows, setIgnoreWindows] = useState(sp.get("ignore_windows") === "1");
  const [checks, setChecks] = useState<HealthCheck[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  // Risky settings that came from the link rather than from the person filling in the form.
  const prefilled = [
    sp.get("emergency") === "1" && "emergency",
    sp.get("ignore_windows") === "1" && "ignore maintenance windows",
    sp.has("rings") && "stages",
  ].filter((x): x is string => !!x);

  // Rollbacks may also target revoked packages (removing a bad patch is often why it was revoked).
  const approved = (pkgs.data ?? []).filter((p) => p.state === "approved" || (rollback && p.state === "revoked"));
  const selected = approved.find((p) => p.package_id === packageId);
  const dlPolicy = rollback ? null : policyDeadline(selected, policy.data);
  const ringNames = rings.map((r) => r.name.trim()).filter(Boolean).join(" → ");

  // Auto-name until the user types a name.
  useEffect(() => {
    if (!nameTouched) setName(autoName(selected, rollback ? "rollback" : emergency ? "emergency" : ringNames || "rollout"));
  }, [selected?.package_id, rollback, emergency, ringNames, nameTouched]); // eslint-disable-line react-hooks/exhaustive-deps

  // Deadline defaults to release date + the policy deadline for the severity.
  useEffect(() => {
    if (!deadlineTouched) setDeadline(dlPolicy ? toLocalInput(dlPolicy) : "");
  }, [selected?.package_id, policy.data, rollback, deadlineTouched]); // eslint-disable-line react-hooks/exhaustive-deps

  const counts = eps.data ? ringCounts(rings.map((r) => ({ groups: splitList(r.groups) })), eps.data) : null;
  const members = eps.data ? ringMembers(rings.map((r) => ({ groups: splitList(r.groups) })), eps.data) : null;
  const emptyRings = counts ? rings.map((_, i) => i).filter((i) => counts[i] === 0 && splitList(rings[i].groups).length > 0) : [];

  const setRing = (i: number, patch: Partial<RingDraft>) =>
    setRings(rings.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  const problems: string[] = [];
  if (!packageId) problems.push("Choose an approved package.");
  if (rollback && selected?.rollback_unsupported) problems.push(`Rollback not supported: ${selected.rollback_unsupported}`);
  if (rollback && !justification.trim()) problems.push("Rollback deployments require a justification (e.g. the change ticket).");
  if (!name.trim()) problems.push("Name is required.");
  if (rings.length === 0) problems.push("At least one stage is required.");
  rings.forEach((r, i) => {
    if (!r.name.trim()) problems.push(`Stage ${i + 1} needs a name.`);
    if (splitList(r.groups).length === 0) problems.push(`Stage ${i + 1} needs at least one group.`);
  });
  const mf = Number(maxFail);
  const mr = Number(maxRetries);
  if (!(mf >= 0 && mf <= 100)) problems.push("Max failure % must be 0–100.");
  if (!(Number.isInteger(mr) && mr >= 0)) problems.push("Max retries must be a whole number ≥ 0.");
  if (!!winStart !== !!winEnd) problems.push("Set both window start and end, or neither.");
  if (emergency && !justification.trim()) problems.push("Emergency deployments require a justification.");
  const mc = Number(maxConcurrent);
  if (!(Number.isInteger(mc) && mc >= 0)) problems.push("Max concurrent installs must be a whole number ≥ 0 (0 = unlimited).");
  if (deadline && isNaN(new Date(deadline).getTime())) problems.push("Deadline is not a valid date/time.");
  if (rebootPolicy === "at_deadline" && !deadline) problems.push("Reboot policy “at the deadline” requires a deadline.");
  checks.forEach((c, i) => {
    if (!c.name.trim()) problems.push(`Health check ${i + 1} needs a ${c.type === "tcp_listening" ? "port" : "service name"}.`);
    else if (c.type === "tcp_listening" && !validPort(c.name.trim())) problems.push(`Health check ${i + 1}: port must be a number 1–65535.`);
  });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problems.length || busy) return;
    setBusy(true);
    setError(null);
    setConflict(false);
    const body: NewDeployment = {
      package_id: packageId,
      name: name.trim(),
      rings: rings.map((r) => ({ name: r.name.trim(), groups: splitList(r.groups) })),
      max_failure_pct: mf,
      max_retries: mr,
      window_start: localToUtcHHMM(winStart),
      window_end: localToUtcHHMM(winEnd),
      emergency,
      justification: emergency || rollback ? justification.trim() : "",
      deadline: deadline ? toRFC3339(deadline) : "",
      max_concurrent: mc,
      reboot_policy: rebootPolicy,
      ignore_windows: ignoreWindows,
      health_checks: checks.map((c) => ({ type: c.type, name: c.name.trim() })),
      operation,
    };
    try {
      const d = await api.post<Deployment>("/api/deployments", body);
      navigate(`/deployments/${enc(d.deployment_id)}`);
    } catch (err) {
      setError(errMsg(err));
      setConflict(err instanceof ApiError && err.status === 409);
      setBusy(false);
    }
  };

  if (!canCreate) {
    return (
      <>
        <PageHeader title="New deployment" />
        <div className="banner banner-error">Creating deployments requires the operator role.</div>
      </>
    );
  }

  return (
    <>
      <PageHeader title={rollback ? "New rollback deployment" : "New deployment"} sub={<Link to="/deployments">← Deployments</Link>} />
      <ErrorBanner error={pkgs.error} />
      {prefilled.length > 0 && (
        <div className="banner banner-info">
          <b>Prefilled from link:</b> {prefilled.join(", ")}. Check these settings before creating the deployment.
        </div>
      )}
      <form className="form card" onSubmit={submit}>
        <div className="form-grid">
          <label className="field span-2">
            <span>Operation</span>
            <select value={operation} onChange={(e) => setOperation(e.target.value as DeploymentOperation)}>
              <option value="install">Install the package</option>
              <option value="rollback">Roll back (uninstall) the package</option>
            </select>
            {rollback && (
              <small className="hint">
                Agents uninstall it stage by stage (.msu: <Mono>wusa /uninstall /kb:N</Mono>, .msi: <Mono>msiexec /x {"{ProductCode}"}</Mono>,
                .deb/.rpm: <Mono>dpkg -r</Mono> / <Mono>rpm -e</Mono>). Only endpoints whose inventory shows the package are targeted;
                verified = inventory no longer shows it. macOS .pkg installers have no uninstall and cannot be rolled back.
              </small>
            )}
          </label>
          <label className="field span-2">
            <span>Package <em className="req">{rollback ? "approved or revoked" : "approved only"}</em></span>
            <select value={packageId} onChange={(e) => setPackageId(e.target.value)}>
              <option value="">— select an approved package —</option>
              {approved.map((p) => (
                <option key={p.package_id} value={p.package_id} disabled={rollback && !!p.rollback_unsupported}>
                  {p.title || p.package_id} {p.kb ? `(${p.kb})` : ""} · {p.severity}{p.state === "revoked" ? " · revoked" : ""}
                  {rollback && p.rollback_unsupported ? " — rollback not supported" : ""}
                </option>
              ))}
              {packageId && !selected && pkgs.data && (
                <option value={packageId} disabled>{packageId} (not approved)</option>
              )}
            </select>
          </label>
          <label className="field span-2">
            <span>Name</span>
            <input value={name} onChange={(e) => { setName(e.target.value); setNameTouched(true); }}
                   placeholder={selected ? `${selected.kb || selected.title} rollout` : "e.g. October cumulative update"} />
          </label>
        </div>

        <fieldset className="fieldset">
          <legend>Stages <span className="muted">— rolled out in order; only the current stage receives assignments</span></legend>
          <p className="hint" style={{ marginTop: 0 }}>{STAGES_HINT}</p>
          <table className="table table-compact rings">
            <thead><tr><th style={{ width: 40 }}>#</th><th>Name</th><th>Groups (comma-separated)</th><th title="Machines that fall in this stage (first matching stage wins); the preview below shows what happens on each">Machines</th><th style={{ width: 120 }} /></tr></thead>
            <tbody>
              {rings.map((r, i) => (
                <tr key={i}>
                  <td className="muted">{i + 1}</td>
                  <td><input value={r.name} onChange={(e) => setRing(i, { name: e.target.value })} /></td>
                  <td><input value={r.groups} onChange={(e) => setRing(i, { groups: e.target.value })} /></td>
                  <td>
                    {counts && members ? (
                      <span title={members[i].map((e) => e.hostname).join(", ")}>
                        <b className={counts[i] === 0 ? "text-red" : undefined}>{counts[i]}</b>
                        {members[i].length > 0 && <span className="muted"> · {members[i].slice(0, 3).map((e) => e.hostname).join(", ")}{members[i].length > 3 ? ` +${members[i].length - 3} more` : ""}</span>}
                      </span>
                    ) : "…"}
                  </td>
                  <td className="nowrap right">
                    <button type="button" className="btn btn-sm" disabled={i === 0}
                      onClick={() => { const n = [...rings]; [n[i - 1], n[i]] = [n[i], n[i - 1]]; setRings(n); }}>↑</button>
                    <button type="button" className="btn btn-sm" disabled={i === rings.length - 1}
                      onClick={() => { const n = [...rings]; [n[i + 1], n[i]] = [n[i], n[i + 1]]; setRings(n); }}>↓</button>
                    <button type="button" className="btn btn-sm btn-danger-ghost" disabled={rings.length <= 1}
                      onClick={() => setRings(rings.filter((_, j) => j !== i))}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button type="button" className="btn btn-sm" onClick={() => setRings([...rings, { name: "", groups: "" }])}>+ Add stage</button>
          {emptyRings.length > 0 && (
            <div className="banner banner-warn" style={{ marginTop: 8 }}>
              <b>{emptyRings.length === 1 ? `Stage ${emptyRings[0] + 1} has` : `Stages ${emptyRings.map((i) => i + 1).join(", ")} have`} no endpoints.</b>{" "}
              An empty stage gets no targets and the rollout waits there until someone starts the next stage.{" "}
              {rings.length > emptyRings.length && (
                <button type="button" className="btn btn-sm" onClick={() => setRings(rings.filter((_, j) => !emptyRings.includes(j)))}>
                  Remove empty stage{emptyRings.length === 1 ? "" : "s"}
                </button>
              )}
            </div>
          )}
        </fieldset>

        {rollback && selected?.rollback_unsupported && (
          <div className="banner banner-error"><b>Rollback not supported for {selected.kind}:</b> {selected.rollback_unsupported}</div>
        )}
        {!rollback && <TargetPreview pkg={selected} rings={rings} />}

        <div className="form-grid">
          <label className="field">
            <span>Max failure %</span>
            <input type="number" min={0} max={100} value={maxFail} onChange={(e) => setMaxFail(e.target.value)} />
            <small className="hint">Auto-pause when exceeded in the current stage.</small>
          </label>
          <label className="field">
            <span>Max retries</span>
            <input type="number" min={0} step={1} value={maxRetries} onChange={(e) => setMaxRetries(e.target.value)} />
          </label>
        </div>

        <fieldset className="fieldset">
          <legend>Schedule &amp; reboots</legend>
          <div className="form-grid">
            <label className="field">
              <span>Deadline <em className="muted">optional · your local time</em></span>
              <input type="datetime-local" value={deadline} onChange={(e) => { setDeadline(e.target.value); setDeadlineTouched(true); }} />
              <small className="hint">
                After the deadline, maintenance windows no longer hold installs back.
                {dlPolicy && selected && <> Policy default: release date + {humanDuration(policy.data?.deadlines?.[selected.severity])} ({selected.severity}).</>}
                {deadlineTouched && dlPolicy && (
                  <> <button type="button" className="btn-link" onClick={() => setDeadlineTouched(false)}>Use policy default</button></>
                )}
              </small>
              {deadline && new Date(deadline).getTime() < Date.now() && (
                <small className="hint text-amber">This deadline has already passed: installs start as soon as endpoints are assigned.</small>
              )}
            </label>
            <label className="field">
              <span>Reboot policy</span>
              <select value={rebootPolicy} onChange={(e) => setRebootPolicy(e.target.value as RebootPolicy)}>
                {REBOOT_POLICIES.map((r) => (
                  <option key={r.value} value={r.value} disabled={r.value === "at_deadline" && !deadline}>
                    {r.label}{r.value === "at_deadline" && !deadline ? " (set a deadline first)" : ""}
                  </option>
                ))}
              </select>
              <small className="hint">{REBOOT_POLICIES.find((r) => r.value === rebootPolicy)?.hint}</small>
            </label>
            <label className="check setup-ca">
              <input type="checkbox" checked={ignoreWindows} onChange={(e) => setIgnoreWindows(e.target.checked)} />
              <span><b>Ignore maintenance windows</b> — install as soon as assigned</span>
            </label>
          </div>
        </fieldset>

        <details className="fieldset advanced" open={!!(winStart || winEnd || Number(maxConcurrent) > 0)}>
          <summary>Advanced <span className="muted">— deployment window, concurrency</span></summary>
          <div className="form-grid">
            <label className="field">
              <span>Window start <em className="muted">optional · your local time</em></span>
              <input type="time" value={winStart} onChange={(e) => setWinStart(e.target.value)} />
              {winStart && <small className="hint">= <b>{localToUtcHHMM(winStart)} UTC</b></small>}
            </label>
            <label className="field">
              <span>Window end <em className="muted">optional · your local time</em></span>
              <input type="time" value={winEnd} onChange={(e) => setWinEnd(e.target.value)} />
              {winEnd && <small className="hint">= <b>{localToUtcHHMM(winEnd)} UTC</b></small>}
              <small className="hint">
                Both empty = install any time. Stored in UTC
                {winStart && winEnd && <> ({localToUtcHHMM(winStart)}–{localToUtcHHMM(winEnd)} UTC)</>}.
                Group maintenance windows (<Link to={paths.windows}>Deployments → Maintenance windows</Link>) also apply.
              </small>
            </label>
            <label className="field">
              <span>Max concurrent installs</span>
              <input type="number" min={0} step={1} value={maxConcurrent} onChange={(e) => setMaxConcurrent(e.target.value)} />
              <small className="hint">0 = unlimited. Caps how many endpoints download/install at once.</small>
            </label>
          </div>
        </details>

        <fieldset className="fieldset">
          <legend>Health checks <span className="muted">— after install; a failed check counts as a failure and can auto-pause the rollout</span></legend>
          {checks.length > 0 && (
            <table className="table table-compact rings">
              <thead><tr><th style={{ width: 40 }}>#</th><th style={{ width: 200 }}>Type</th><th>Service name / TCP port</th><th style={{ width: 90 }} /></tr></thead>
              <tbody>
                {checks.map((c, i) => {
                  const bad = c.type === "tcp_listening" && c.name.trim() !== "" && !validPort(c.name.trim());
                  return (
                    <tr key={i}>
                      <td className="muted">{i + 1}</td>
                      <td>
                        <select value={c.type}
                                onChange={(e) => setChecks(checks.map((x, j) => (j === i ? { ...x, type: e.target.value as HealthCheck["type"] } : x)))}>
                          <option value="service_running">service running</option>
                          <option value="tcp_listening">TCP port listening</option>
                        </select>
                      </td>
                      <td>
                        <input value={c.name} className={bad ? "input-bad" : ""}
                               inputMode={c.type === "tcp_listening" ? "numeric" : undefined}
                               placeholder={c.type === "tcp_listening" ? "e.g. 443" : "e.g. W3SVC"}
                               onChange={(e) => setChecks(checks.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))} />
                      </td>
                      <td className="right">
                        <button type="button" className="btn btn-sm btn-danger-ghost"
                                onClick={() => setChecks(checks.filter((_, j) => j !== i))}>Remove</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <button type="button" className="btn btn-sm" onClick={() => setChecks([...checks, { type: "service_running", name: "" }])}>
            + Add health check
          </button>
        </fieldset>

        <label className="check">
          <input type="checkbox" checked={emergency} onChange={(e) => setEmergency(e.target.checked)} />
          <span><b>Emergency deployment</b> — flagged in the audit log and the UI</span>
        </label>
        {(emergency || rollback) && (
          <label className="field">
            <span>Justification <em className="req">required</em>{rollback && <em className="muted"> — why roll back (change ticket, incident)</em>}</span>
            <textarea rows={3} value={justification} onChange={(e) => setJustification(e.target.value)} />
          </label>
        )}

        {error && (
          <div className="banner banner-error">
            {error}
            {conflict && (
              <div className="small" style={{ marginTop: 4 }}>
                The server refused this deployment. If <b>separation of duties</b> is enabled, someone who approved the
                package cannot also deploy it — ask another operator to create the deployment.
              </div>
            )}
          </div>
        )}
        {problems.length > 0 && (
          <ul className="problems">{problems.map((p) => <li key={p}>{p}</li>)}</ul>
        )}
        <div className="form-actions">
          <Link to="/deployments" className="btn">Cancel</Link>
          <button className={`btn ${emergency || rollback ? "btn-danger" : "btn-primary"}`} disabled={problems.length > 0 || busy}>
            {busy ? "Creating…" : rollback ? "Create rollback deployment" : emergency ? "Create emergency deployment" : "Create deployment"}
          </button>
        </div>
      </form>
    </>
  );
}
