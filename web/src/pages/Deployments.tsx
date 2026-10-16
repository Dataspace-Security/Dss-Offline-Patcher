import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, ApiError, enc, errMsg, qs } from "../api";
import { useCan } from "../auth";
import { TargetPreview } from "../components/TargetPreview";
import { CountsBar, Empty, ErrorBanner, Mono, PageHeader, Pill, Time, patchScore, scoreTone } from "../components/ui";
import type { Deployment, HealthCheck, NewDeployment, Package, RebootPolicy } from "../types";
import { splitList, toRFC3339, useLoad } from "../util";

export function ringLabel(d: Deployment): string {
  const total = d.rings?.length ?? 0;
  if (total === 0) return "—";
  // current_ring is treated as a 0-based index into rings.
  const idx = Math.min(Math.max(d.current_ring, 0), total - 1);
  return `${idx + 1} / ${total}`;
}

export function DeploymentList() {
  const canCreate = useCan("operator");
  const { data, error } = useLoad(() => api.get<Deployment[]>("/api/deployments"), [], 5000);
  const pkgs = useLoad(() => api.get<Package[]>("/api/packages"), []);
  const title = (id: string) => pkgs.data?.find((p) => p.package_id === id)?.title;

  return (
    <>
      <PageHeader title="Deployments" sub="Ring-based rollouts of approved packages · auto-refresh every 5s">
        {canCreate && <Link className="btn btn-primary" to="/deployments/new">New deployment</Link>}
      </PageHeader>
      <ErrorBanner error={error} />
      {data && data.length === 0 && <Empty>No deployments yet. Approve a package in the Catalog, then deploy it.</Empty>}
      {data && data.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th><th>Package</th><th>State</th><th>Ring</th><th style={{ width: "28%" }}>Progress</th><th>Created</th>
            </tr>
          </thead>
          <tbody>
            {data.map((d) => (
              <tr key={d.deployment_id}>
                <td>
                  <Link to={`/deployments/${enc(d.deployment_id)}`} className="cell-title">{d.name || d.deployment_id}</Link>
                  {d.emergency && <span className="flag-emergency">EMERGENCY</span>}
                  <div className="cell-sub"><Mono>{d.deployment_id}</Mono></div>
                </td>
                <td>
                  <Link to={`/catalog/${enc(d.package_id)}`}>{title(d.package_id) ?? <Mono>{d.package_id}</Mono>}</Link>
                </td>
                <td><Pill state={d.state} /></td>
                <td className="nowrap">
                  {ringLabel(d)}
                  <div className="cell-sub">{d.rings?.[Math.min(d.current_ring, (d.rings?.length ?? 1) - 1)]?.name}</div>
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
      <b className={`text-${scoreTone(sc.pct)}`}>{sc.pct}% patched</b> · {done}/{total} done
      {(c.failed ?? 0) > 0 && <span className="text-red"> · {c.failed} failed</span>}
      {(c.pending_reboot ?? 0) > 0 && <span className="text-amber"> · {c.pending_reboot} reboot</span>}
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
  const pkgs = useLoad(() => api.get<Package[]>(`/api/packages${qs({ state: "approved" })}`), []);

  const [packageId, setPackageId] = useState(sp.get("package_id") ?? "");
  const [name, setName] = useState("");
  const [rings, setRings] = useState<RingDraft[]>([
    { name: "pilot", groups: "pilot" },
    { name: "broad", groups: "all" },
  ]);
  const [maxFail, setMaxFail] = useState("20");
  const [maxRetries, setMaxRetries] = useState("2");
  const [winStart, setWinStart] = useState("");
  const [winEnd, setWinEnd] = useState("");
  const [emergency, setEmergency] = useState(false);
  const [justification, setJustification] = useState("");
  const [deadline, setDeadline] = useState("");
  const [maxConcurrent, setMaxConcurrent] = useState("0");
  const [rebootPolicy, setRebootPolicy] = useState<RebootPolicy>("never");
  const [ignoreWindows, setIgnoreWindows] = useState(false);
  const [checks, setChecks] = useState<HealthCheck[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);

  const approved = (pkgs.data ?? []).filter((p) => p.state === "approved");
  const selected = approved.find((p) => p.package_id === packageId);

  const setRing = (i: number, patch: Partial<RingDraft>) =>
    setRings(rings.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  const problems: string[] = [];
  if (!packageId) problems.push("Choose an approved package.");
  if (!name.trim()) problems.push("Name is required.");
  if (rings.length === 0) problems.push("At least one ring is required.");
  rings.forEach((r, i) => {
    if (!r.name.trim()) problems.push(`Ring ${i + 1} needs a name.`);
    if (splitList(r.groups).length === 0) problems.push(`Ring ${i + 1} needs at least one group.`);
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
      window_start: winStart,
      window_end: winEnd,
      emergency,
      justification: emergency ? justification.trim() : "",
      deadline: deadline ? toRFC3339(deadline) : "",
      max_concurrent: mc,
      reboot_policy: rebootPolicy,
      ignore_windows: ignoreWindows,
      health_checks: checks.map((c) => ({ type: c.type, name: c.name.trim() })),
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
      <PageHeader title="New deployment" sub={<Link to="/deployments">← Deployments</Link>} />
      <ErrorBanner error={pkgs.error} />
      <form className="form card" onSubmit={submit}>
        <div className="form-grid">
          <label className="field span-2">
            <span>Package <em className="req">approved only</em></span>
            <select value={packageId} onChange={(e) => setPackageId(e.target.value)}>
              <option value="">— select an approved package —</option>
              {approved.map((p) => (
                <option key={p.package_id} value={p.package_id}>
                  {p.title || p.package_id} {p.kb ? `(${p.kb})` : ""} · {p.severity}
                </option>
              ))}
              {packageId && !selected && pkgs.data && (
                <option value={packageId} disabled>{packageId} (not approved)</option>
              )}
            </select>
          </label>
          <label className="field span-2">
            <span>Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)}
                   placeholder={selected ? `${selected.kb || selected.title} rollout` : "e.g. October cumulative update"} />
          </label>
        </div>

        <fieldset className="fieldset">
          <legend>Rings <span className="muted">— rolled out in order; only the current ring receives assignments</span></legend>
          <table className="table table-compact rings">
            <thead><tr><th style={{ width: 40 }}>#</th><th>Name</th><th>Groups (comma-separated)</th><th style={{ width: 120 }} /></tr></thead>
            <tbody>
              {rings.map((r, i) => (
                <tr key={i}>
                  <td className="muted">{i + 1}</td>
                  <td><input value={r.name} onChange={(e) => setRing(i, { name: e.target.value })} /></td>
                  <td><input value={r.groups} onChange={(e) => setRing(i, { groups: e.target.value })} /></td>
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
          <button type="button" className="btn btn-sm" onClick={() => setRings([...rings, { name: "", groups: "" }])}>+ Add ring</button>
        </fieldset>

        <TargetPreview pkg={selected} rings={rings} />

        <div className="form-grid">
          <label className="field">
            <span>Max failure %</span>
            <input type="number" min={0} max={100} value={maxFail} onChange={(e) => setMaxFail(e.target.value)} />
            <small className="hint">Auto-pause when exceeded in the current ring.</small>
          </label>
          <label className="field">
            <span>Max retries</span>
            <input type="number" min={0} step={1} value={maxRetries} onChange={(e) => setMaxRetries(e.target.value)} />
          </label>
          <label className="field">
            <span>Window start (UTC) <em className="muted">optional</em></span>
            <input type="time" value={winStart} onChange={(e) => setWinStart(e.target.value)} />
          </label>
          <label className="field">
            <span>Window end (UTC) <em className="muted">optional</em></span>
            <input type="time" value={winEnd} onChange={(e) => setWinEnd(e.target.value)} />
            <small className="hint">Both empty = install any time. Group maintenance windows (Windows page) also apply.</small>
          </label>
        </div>

        <fieldset className="fieldset">
          <legend>Schedule &amp; reboots</legend>
          <div className="form-grid">
            <label className="field">
              <span>Deadline <em className="muted">optional · your local time</em></span>
              <input type="datetime-local" value={deadline} onChange={(e) => setDeadline(e.target.value)} />
              <small className="hint">After the deadline, maintenance windows no longer hold installs back.</small>
            </label>
            <label className="field">
              <span>Max concurrent installs</span>
              <input type="number" min={0} step={1} value={maxConcurrent} onChange={(e) => setMaxConcurrent(e.target.value)} />
              <small className="hint">0 = unlimited. Caps how many endpoints download/install at once.</small>
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
        {emergency && (
          <label className="field">
            <span>Justification <em className="req">required</em></span>
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
          <button className={`btn ${emergency ? "btn-danger" : "btn-primary"}`} disabled={problems.length > 0 || busy}>
            {busy ? "Creating…" : emergency ? "Create emergency deployment" : "Create deployment"}
          </button>
        </div>
      </form>
    </>
  );
}
