import { useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, ApiError, enc, errMsg } from "../api";
import { deploymentApprovalsRequired, needsApprovalsText, othersMustApprove, useCan, useMe } from "../auth";
import { paths } from "../paths";
import { networkLimitsText } from "../netlimits";
import type { Deployment, Endpoint, NewDeployment, Package, PackageFleet, Policy } from "../types";
import { fmtTime, useLoad } from "../util";
import { REBOOT_LABELS, STAGES_HINT, stageLabel } from "./deployLabels";
import {
  approvalsRequired, approvedBy, buildPreset, customHref, fetchEndpoints, fetchFleet, fetchPolicy, fetchWindows,
  groupSize, humanDuration, isFirstWavePlan, pickFirstWave, policyDeadline, ringCounts, windowsAllowReboot, type ChosenTarget, type PresetKind,
} from "./patchPlan";
import { TargetPreview, nothingToDo, type TargetSummary } from "./TargetPreview";
import { CopyBox, ErrorBanner, Modal, Mono, Pill } from "./ui";
import "../patch.css";

/** "needs it 37 · up to date 12 · not installed 4 · deploying 3 · verified 20". */
export function FleetLine({ fleet }: { fleet: PackageFleet | undefined | null }) {
  if (!fleet) return <span className="muted">fleet status unknown</span>;
  const part = (n: number | undefined, label: string, tone?: string) => (
    <span className={`fleet-part ${n && tone ? `text-${tone}` : ""}`}>{label} <b>{n ?? 0}</b></span>
  );
  return (
    <span className="fleet-line">
      {part(fleet.needed, "needs it", "amber")}
      {part(fleet.up_to_date, "up to date")}
      {part(fleet.not_installed, "not installed")}
      {part(fleet.deploying, "deploying", "blue")}
      {part(fleet.verified, "verified", "green")}
      {(fleet.failed ?? 0) > 0 && part(fleet.failed, "failed", "red")}
      {(fleet.exception ?? 0) > 0 && part(fleet.exception, "exception")}
    </span>
  );
}

export type PatchThisProps = {
  packageId: string;
  /** Opened from an endpoint: offers "This endpoint only". */
  endpoint?: { id: string; hostname: string };
  onClose: () => void;
  /** Called after the package changed (approval recorded). */
  onChanged?: (p: Package) => void;
};

const PRESETS: { kind: PresetKind; label: string; hint: string }[] = [
  { kind: "one_ring", label: "Every compatible machine that needs it", hint: "policy deadline; pauses above 10 % failures" },
  { kind: "standard", label: "Test machines first, then all", hint: "group pilot installs first; you check it, then start the rest" },
  { kind: "endpoint", label: "This endpoint only", hint: "just this machine" },
  { kind: "chosen", label: "Chosen machines", hint: "a group, a site or one endpoint you pick" },
  { kind: "emergency", label: "Emergency", hint: "all machines now, ignores windows, 24 h deadline" },
];

/** Plain-words explanation of the two automatic stages. */
export function firstWaveText(first: number): string {
  return `Starts on ${first} machine${first === 1 ? "" : "s"} first. The rest follow automatically once they succeed; it pauses if too many fail.`;
}

/** Shown when no maintenance window allows restarts (reboot policy "never"). */
export const NO_REBOOT_WINDOW_NOTE = "Machines that need a restart will show 'Restart needed' until someone restarts them.";

/** "2 machines" / "nothing to do" from the live preview (machines decided at check-in count as possible installs). */
function willInstallText(s: TargetSummary): string {
  if (nothingToDo(s)) return "nothing to do";
  const n = s.willInstall + s.unknown;
  return `${n} machine${n === 1 ? "" : "s"}`;
}

/** Server 409 for a second deployment of the same package: "deployment <id> of this package is already running; ...". */
export function runningDeploymentFrom(message: string): string {
  return /deployment (\S+) of this package is already running/.exec(message)?.[1] ?? "";
}

/** "A deployment of this package is already running -> Open it" (instead of offering Create). */
export function AlreadyRunning({ deploymentId, onOpen }: { deploymentId: string; onOpen?: () => void }) {
  return (
    <div className="banner banner-info">
      <b>A deployment of this package is already running</b> (<Mono>{deploymentId}</Mono>) →{" "}
      <Link className="btn btn-sm btn-primary" to={`/deployments/${enc(deploymentId)}`} onClick={onOpen}>Open it</Link>
      <div className="small">It already targets every machine that needs the package. Wait for it to finish, or cancel it there first.</div>
    </div>
  );
}

/** True when every machine in the stages is outside the package's applicability (e.g. a 24H2 package and 25H2 machines). */
function notApplicableToAll(s: TargetSummary | null): boolean {
  return !!s && s.targeted > 0 && (s.notApplicable ?? 0) === s.targeted;
}

/** Guided drawer: approve (if needed) → choose a preset → preview → create. */
export function PatchThis({ packageId, endpoint, onClose, onChanged }: PatchThisProps) {
  const navigate = useNavigate();
  const me = useMe();
  const canApprove = useCan("user");
  const canDeploy = useCan("user");
  const pkgL = useLoad(() => api.get<Package>(`/api/packages/${enc(packageId)}`), [packageId]);
  const policyL = useLoad(fetchPolicy, []);
  const fleetL = useLoad(fetchFleet, [packageId]);
  const epsL = useLoad(fetchEndpoints, []);
  const winL = useLoad(fetchWindows, []);
  // Default plan: all machines at once (the organisation has no test machines).
  const [preset, setPreset] = useState<PresetKind>("one_ring");
  const [summary, setSummary] = useState<TargetSummary | null>(null);
  const [runningFromServer, setRunningFromServer] = useState("");
  const [justification, setJustification] = useState("");
  const [atOnce, setAtOnce] = useState("0");
  const [chosen, setChosen] = useState<ChosenTarget>({ by: "group", value: "" });
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const pkg = pkgL.data;
  const policy = policyL.data;
  const fleet = fleetL.data?.[packageId];

  const approve = async () => {
    if (!pkg || busy || !reason.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      const updated = await api.post<Package>(`/api/packages/${enc(pkg.package_id)}/approve`, { reason: reason.trim() });
      pkgL.setData(updated);
      setReason("");
      setNotice(updated.state === "approved" ? "Approved and published." : null);
      onChanged?.(updated);
      void fleetL.reload();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const create = async (body: NewDeployment) => {
    if (busy) return;
    setBusy(true);
    setErr(null);
    setConflict(false);
    try {
      const d = await api.post<Deployment>("/api/deployments", body);
      navigate(`/deployments/${enc(d.deployment_id)}`);
    } catch (e) {
      const msg = errMsg(e);
      const is409 = e instanceof ApiError && e.status === 409;
      const running = is409 ? runningDeploymentFrom(msg) : "";
      setRunningFromServer(running);
      setErr(running ? null : msg);
      setConflict(is409 && !running);
      setBusy(false);
    }
  };

  const title = <>Patch this{pkg ? <>: {pkg.title || pkg.package_id}</> : null}</>;
  if (!pkg) {
    return (
      <Modal title={title} onClose={onClose} xwide>
        <ErrorBanner error={pkgL.error} />
        {!pkgL.error && <div className="muted">Loading…</div>}
      </Modal>
    );
  }

  const required = approvalsRequired(pkg, policy);
  const approvals = pkg.approvals ?? [];
  const iApproved = approvedBy(pkg, me);
  const sodBlocks = !!policy?.separation_of_duties && iApproved;
  const quarantined = pkg.state === "quarantined";
  const approved = pkg.state === "approved";
  const eps = epsL.data ?? [];
  const pilotN = groupSize("pilot", eps);
  const pilotEmpty = !!epsL.data && pilotN === 0;
  const runningId = fleet?.active_deployment_id || runningFromServer;
  // Many machines need it: start on a few first, the rest follow by themselves.
  const firstWave = preset === "one_ring" && fleet && epsL.data ? pickFirstWave(fleet.endpoint_ids ?? [], epsL.data) : [];
  // No window lets machines restart: don't promise restarts that never happen.
  const rebootInWindow = winL.data ? windowsAllowReboot(winL.data) : true;
  const atOnceN = Math.max(0, Math.floor(Number(atOnce) || 0));
  const draft = { ...buildPreset(preset, pkg, { policy, endpointId: endpoint?.id, hostname: endpoint?.hostname, justification, firstWave, rebootInWindow, chosen, endpoints: eps }), max_concurrent: atOnceN };
  const counts = ringCounts(draft.rings, eps);
  const dl = policyDeadline(pkg, policy);
  const deployApprovals = deploymentApprovalsRequired(policy);

  const problems: string[] = [];
  if (!approved) problems.push("The package must be approved first.");
  if (preset === "standard" && pilotEmpty) problems.push("No test machines: no endpoint is in group pilot. Choose Every compatible machine that needs it, or put 2–5 machines in group pilot first.");
  if (preset === "emergency" && !justification.trim()) problems.push("Emergency deployments require a justification.");
  if (preset === "chosen" && !chosen.value) problems.push(`Choose the ${chosen.by} to deploy to.`);
  if (epsL.data && counts.every((c) => c === 0)) problems.push("No endpoint is in these stages.");
  else if (nothingToDo(summary)) problems.push(notApplicableToAll(summary)
    ? `This package doesn't apply to any machine in these stages (${summary!.naReasons?.join("; ") || "not applicable"}). Nothing can be installed: import the update built for their Windows version from Patches → Needed.`
    : "Nothing to do: every machine is already up to date or doesn't need it.");
  // The plan (deadline, stage sizes) depends on the policy and the endpoint
  // list: never create from a half-loaded plan (e.g. silently without the
  // policy deadline).
  // Maintenance windows (restart default) and the machines that need it
  // (first machines) refine the plan; if they fail to load the plan falls
  // back to restarts in a window / one stage rather than blocking.
  const planLoaded = !!policyL.data && !!epsL.data && (!!winL.data || !!winL.error) && (!!fleetL.data || !!fleetL.error);
  const planError = [policyL.error && `policy: ${policyL.error}`, epsL.error && `endpoints: ${epsL.error}`].filter(Boolean).join(" · ");
  const retryPlan = () => { void policyL.reload(); void epsL.reload(); void winL.reload(); void fleetL.reload(); };
  const canCreate = approved && canDeploy && !sodBlocks && !runningId && planLoaded && problems.length === 0;

  const visiblePresets = PRESETS.filter((p) => p.kind !== "endpoint" || endpoint);
  const ringsForPreview = draft.rings.map((r) => ({ name: r.name, groups: r.groups.join(", ") }));
  const handoffUrl = `${window.location.origin}${paths.catalog(pkg.package_id)}`;

  const footer: ReactNode = (
    <>
      <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
      {approved && canDeploy && !sodBlocks && runningId && (
        <Link className="btn btn-primary" to={`/deployments/${enc(runningId)}`} onClick={onClose}>Open the running deployment</Link>
      )}
      {approved && canDeploy && !sodBlocks && !runningId && !nothingToDo(summary) && (
        <span className="reason-hint" title={othersMustApprove(deployApprovals)}>{needsApprovalsText(deployApprovals)}</span>
      )}
      {approved && canDeploy && !sodBlocks && !runningId && !nothingToDo(summary) && (
        <button className={`btn ${preset === "emergency" ? "btn-danger" : "btn-primary"}`} disabled={!canCreate || busy}
                onClick={() => void create(draft)}>
          {busy ? "Creating…" : preset === "emergency" ? "Create emergency deployment" : "Create deployment"}
        </button>
      )}
    </>
  );

  return (
    <Modal title={title} onClose={onClose} xwide footer={footer}>
      <div className="patch-head">
        <div>
          <span className={`sev sev-${pkg.severity}`}>{pkg.severity}</span>{" "}
          <Pill state={pkg.state} />{" "}
          {pkg.kb ? <Mono>{pkg.kb}</Mono> : <span>{pkg.vendor} {pkg.version}</span>}
          <span className="muted"> · released {pkg.release_date || "—"} · <Link to={paths.catalog(pkg.package_id)} onClick={onClose}><Mono>{pkg.package_id}</Mono></Link></span>
        </div>
        <div className="patch-fleet"><FleetLine fleet={fleet} /></div>
        {runningId && <AlreadyRunning deploymentId={runningId} onOpen={onClose} />}
        {pkg.superseded_by && (
          <div className="banner banner-warn">Superseded by <Link to={paths.catalog(pkg.superseded_by)} onClick={onClose}><Mono>{pkg.superseded_by}</Mono></Link>; prefer the newer package.</div>
        )}
      </div>

      <ol className="steps patch-steps">
        {quarantined && (
          <li>
            <h3>Approve <span className="muted">· {approvals.length} of {required} approval{required === 1 ? "" : "s"}</span></h3>
            {approvals.length > 0 && (
              <ul className="plain small">
                {approvals.map((a, i) => <li key={i}><b>{a.by}</b> <span className="muted">{fmtTime(a.at)}</span>{a.reason && <> — {a.reason}</>}</li>)}
              </ul>
            )}
            {canApprove && !iApproved && (
              <>
                <label className="field">
                  <span>Reason <em className="req">required</em></span>
                  <textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded in the audit log" />
                </label>
                {policy?.separation_of_duties && (
                  <div className="hint">Separation of duties is on: after approving, another User must create the deployment.</div>
                )}
                <div className="form-actions">
                  <button className="btn btn-primary" disabled={busy || !reason.trim()} onClick={() => void approve()}>
                    {busy ? "Working…" : approvals.length + 1 < required ? `Record approval (${approvals.length + 1} of ${required})` : "Approve"}
                  </button>
                </div>
              </>
            )}
            {canApprove && iApproved && (
              <div className="banner banner-info">You approved this package. Waiting for another person ({approvals.length} of {required}).</div>
            )}
            {!canApprove && (
              <div className="banner banner-info">Awaiting approval ({approvals.length} of {required}). A User or Admin must approve it before it can be deployed.</div>
            )}
          </li>
        )}

        {!quarantined && !approved && (
          <li><h3>Not deployable</h3><div className="banner banner-error">This package is <b>{pkg.state}</b> and cannot be deployed.</div></li>
        )}

        {approved && (
          <li>
            <h3>Plan</h3>
            {notice && <div className="banner banner-ok">{notice}</div>}
            {sodBlocks ? (
              <div className="banner banner-warn">
                <b>You approved this; someone else must deploy it.</b> Separation of duties is on, so the server refuses a deployment
                created by a person who approved the package. Send this link to another User:
                <CopyBox value={handoffUrl} />
              </div>
            ) : !canDeploy ? (
              <div className="banner banner-info">Only Users and Admins can deploy.</div>
            ) : runningId ? (
              <div className="hint">No new deployment is offered while one is running: open it to follow it.</div>
            ) : (
              <>
                <div className="preset-row" role="radiogroup" aria-label="How to roll it out">
                  {visiblePresets.map((p) => {
                    const noPilot = p.kind === "standard" && pilotEmpty;
                    return (
                      <button key={p.kind} type="button" role="radio" aria-checked={preset === p.kind} disabled={noPilot}
                              title={noPilot ? "No machine is in group pilot yet (Endpoints → select → Edit groups)" : undefined}
                              className={`preset ${preset === p.kind ? "preset-on" : ""} ${p.kind === "emergency" ? "preset-danger" : ""}`}
                              onClick={() => setPreset(p.kind)}>
                        <b>{p.label}{preset === p.kind && summary && <span className="muted"> → {willInstallText(summary)}</span>}</b>
                        <span>{noPilot ? "no test machines yet: put 2–5 machines in group pilot"
                          : p.kind === "one_ring" && firstWave.length > 0 ? `${firstWave.length} machines first, then the rest by themselves; ${p.hint}`
                          : p.hint}</span>
                      </button>
                    );
                  })}
                  <button type="button" className="preset" onClick={() => navigate(customHref(draft))}>
                    <b>Custom…</b><span>full form, prefilled</span>
                  </button>
                </div>


                {!planLoaded && (planError ? (
                  <div className="banner banner-error">
                    <b>The plan cannot be completed:</b> {planError}. Nothing can be created until both load.{" "}
                    <button className="btn btn-sm" onClick={retryPlan}>Retry</button>
                  </div>
                ) : (
                  <div className="hint">Loading the policy and the endpoint list…</div>
                ))}
                {preset === "standard" && <div className="hint">{STAGES_HINT}</div>}
                {preset === "chosen" && <ChosenPicker value={chosen} onChange={setChosen} endpoints={eps} />}
                {isFirstWavePlan(draft) && <div className="banner banner-info">{firstWaveText(firstWave.length)}</div>}
                <PlanSummary draft={draft} counts={epsL.data ? counts : null} policyDeadline={policy?.deadlines?.[pkg.severity]}
                             policyMissing={!!policyL.error} dlFromPolicy={dl} endpoints={eps}
                             noRebootWindow={!!winL.data && !rebootInWindow && draft.reboot_policy === "never"}
                             policy={policy} atOnce={atOnce} setAtOnce={setAtOnce} />

                {preset === "emergency" && (
                  <label className="field">
                    <span>Justification <em className="req">required</em> <em className="muted">— incident or change ticket; recorded in the audit log</em></span>
                    <textarea rows={2} value={justification} onChange={(e) => setJustification(e.target.value)} />
                  </label>
                )}

                <details className="patch-preview">
                  <summary>Preview who receives it</summary>
                  <TargetPreview pkg={pkg} rings={ringsForPreview} endpoints={epsL.data} fleet={fleetL.data} onSummary={setSummary} />
                </details>

                <div className="banner banner-warn">
                  <b>{needsApprovalsText(deployApprovals)}.</b> {othersMustApprove(deployApprovals)} It waits on the deployment page until then.
                </div>
                {problems.length > 0 && <ul className="problems">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
              </>
            )}
          </li>
        )}
      </ol>

      {err && (
        <div className="banner banner-error">
          {err}
          {conflict && (
            <div className="small">The server refused it. With separation of duties on, someone who approved the package cannot also deploy it: hand it to another User.</div>
          )}
        </div>
      )}
    </Modal>
  );
}

const GROUP_TAGS_SHOWN = 5;

/** Group tags of a stage; "endpoint:<id>" groups read as host names. */
function StageGroups({ groups, endpoints }: { groups: string[]; endpoints: Endpoint[] }) {
  const host = (g: string) => {
    if (!g.toLowerCase().startsWith("endpoint:")) return g;
    const id = g.slice("endpoint:".length);
    return endpoints.find((e) => e.endpoint_id === id)?.hostname ?? id;
  };
  const names = groups.map(host);
  return (
    <>
      {names.slice(0, GROUP_TAGS_SHOWN).map((g, i) => <span key={`${g}-${i}`} className="tag">{g}</span>)}
      {names.length > GROUP_TAGS_SHOWN && <span className="muted" title={names.join(", ")}>+{names.length - GROUP_TAGS_SHOWN} more </span>}
    </>
  );
}

function PlanSummary({ draft, counts, policyDeadline: policyDur, policyMissing, dlFromPolicy, endpoints, noRebootWindow, policy, atOnce, setAtOnce }: {
  draft: NewDeployment; counts: number[] | null; policyDeadline: string | undefined; policyMissing: boolean; dlFromPolicy: Date | null;
  endpoints: Endpoint[]; noRebootWindow: boolean; policy: Policy | null; atOnce: string; setAtOnce: (v: string) => void;
}) {
  const deadline = draft.deadline ? new Date(draft.deadline) : null;
  const overdue = !!deadline && deadline.getTime() < Date.now();
  return (
    <table className="table table-compact plan-summary">
      <tbody>
        <tr>
          <th>Stages</th>
          <td>
            {draft.rings.map((r, i) => (
              <span key={i} className="plan-ring">
                {i > 0 && <span className="muted"> → </span>}
                <b>{stageLabel(r.name, i)}</b> <StageGroups groups={r.groups} endpoints={endpoints} />
                {counts && <span className={counts[i] === 0 ? "text-red" : "muted"}>({counts[i]} endpoint{counts[i] === 1 ? "" : "s"})</span>}
              </span>
            ))}
            {draft.auto_advance && draft.rings.length > 1 && <div className="small muted">The next stage starts automatically once the previous one succeeds.</div>}
          </td>
        </tr>
        <tr>
          <th>Deadline</th>
          <td>
            {deadline ? fmtTime(draft.deadline) : <span className="muted">none</span>}
            {!draft.emergency && dlFromPolicy && <span className="muted"> · release date + {humanDuration(policyDur)} (policy)</span>}
            {!draft.emergency && !dlFromPolicy && <span className="muted"> · {policyMissing ? "policy unavailable" : "no policy deadline for this severity or no release date"}</span>}
            {overdue && <div className="text-amber small">Already past: maintenance windows no longer hold installs back.</div>}
          </td>
        </tr>
        <tr>
          <th>Restart</th>
          <td>
            {REBOOT_LABELS[draft.reboot_policy]}
            {noRebootWindow && (
              <div className="small text-amber">
                No maintenance window allows automatic restarts. {NO_REBOOT_WINDOW_NOTE}{" "}
                <Link to={paths.windows}>Maintenance windows</Link>
              </div>
            )}
          </td>
        </tr>
        <tr><th>Windows</th><td>{draft.ignore_windows ? <span className="text-red">ignored: installs start as soon as assigned</span> : "group maintenance windows apply"}</td></tr>
        <tr><th>Safety</th><td>auto-pause above {draft.max_failure_pct} % failures · {draft.max_retries} retries</td></tr>
        <tr>
          <th>Network</th>
          <td>
            <label className="inline-field">
              Machines at once for this deployment{" "}
              <input type="number" min={0} step={1} value={atOnce} onChange={(e) => setAtOnce(e.target.value)} style={{ width: "6em" }}
                aria-label="Machines at once for this deployment" />
              <span className="muted"> {Number(atOnce) > 0 ? "" : "0 = only the limits below"}</span>
            </label>
            {policy && <div className="small muted">{networkLimitsText(policy)}</div>}
          </td>
        </tr>
      </tbody>
    </table>
  );
}

/** Pick the machines for "Chosen machines": a group, a site or one endpoint. */
function ChosenPicker({ value, onChange, endpoints }: { value: ChosenTarget; onChange: (c: ChosenTarget) => void; endpoints: Endpoint[] }) {
  const live = endpoints.filter((e) => !e.retired_at);
  const groups = [...new Set(live.flatMap((e) => e.groups ?? []))].sort();
  const sites = [...new Set(live.map((e) => e.site).filter(Boolean))].sort();
  const count = (by: ChosenTarget["by"], v: string) =>
    by === "group" ? live.filter((e) => (e.groups ?? []).includes(v)).length : live.filter((e) => e.site === v).length;
  return (
    <div className="chosen-picker form-row">
      <label className="field">
        <span>Deploy to</span>
        <select value={value.by} onChange={(e) => onChange({ by: e.target.value as ChosenTarget["by"], value: "" })}>
          <option value="group">a group</option>
          <option value="site">a site</option>
          <option value="endpoint">one endpoint</option>
        </select>
      </label>
      <label className="field">
        <span>{value.by === "group" ? "Group" : value.by === "site" ? "Site" : "Endpoint"}</span>
        <select value={value.value} onChange={(e) => onChange({ ...value, value: e.target.value })}>
          <option value="">Choose…</option>
          {value.by === "group" && groups.map((g) => <option key={g} value={g}>{g} ({count("group", g)})</option>)}
          {value.by === "site" && sites.map((s) => <option key={s} value={s}>{s} ({count("site", s)})</option>)}
          {value.by === "endpoint" && [...live].sort((a, b) => a.hostname.localeCompare(b.hostname)).map((e) => (
            <option key={e.endpoint_id} value={e.endpoint_id}>{e.hostname}{e.site ? ` · ${e.site}` : ""}</option>
          ))}
        </select>
      </label>
    </div>
  );
}
