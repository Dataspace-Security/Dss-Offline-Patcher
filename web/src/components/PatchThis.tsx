import { useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, ApiError, enc, errMsg } from "../api";
import { useCan, useMe } from "../auth";
import { paths } from "../paths";
import type { Deployment, NewDeployment, Package, PackageFleet } from "../types";
import { fmtTime, useLoad } from "../util";
import { REBOOT_LABELS, STAGES_HINT, stageLabel } from "./deployLabels";
import {
  approvalsRequired, approvedBy, buildPreset, customHref, fetchEndpoints, fetchFleet, fetchPolicy,
  groupSize, humanDuration, policyDeadline, ringCounts, type PresetKind,
} from "./patchPlan";
import { TargetPreview } from "./TargetPreview";
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
  { kind: "standard", label: "Standard", hint: "test machines first, then all machines; policy deadline, reboot in window" },
  { kind: "emergency", label: "Emergency", hint: "one stage, ignores windows, 24 h deadline" },
  { kind: "endpoint", label: "This endpoint only", hint: "one stage with just this endpoint" },
];

/** Guided drawer: approve (if needed) → choose a preset → preview → create. */
export function PatchThis({ packageId, endpoint, onClose, onChanged }: PatchThisProps) {
  const navigate = useNavigate();
  const me = useMe();
  const canApprove = useCan("approver");
  const canDeploy = useCan("operator");
  const pkgL = useLoad(() => api.get<Package>(`/api/packages/${enc(packageId)}`), [packageId]);
  const policyL = useLoad(fetchPolicy, []);
  const fleetL = useLoad(fetchFleet, [packageId]);
  const epsL = useLoad(fetchEndpoints, []);
  const [preset, setPreset] = useState<PresetKind>(endpoint ? "endpoint" : "standard");
  const [justification, setJustification] = useState("");
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
      setErr(errMsg(e));
      setConflict(e instanceof ApiError && e.status === 409);
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
  const draft = buildPreset(preset, pkg, { policy, endpointId: endpoint?.id, hostname: endpoint?.hostname, justification });
  const counts = ringCounts(draft.rings, eps);
  const dl = policyDeadline(pkg, policy);
  const pilotEmpty = (preset === "standard") && !!epsL.data && pilotN === 0;

  const problems: string[] = [];
  if (!approved) problems.push("The package must be approved first.");
  if (pilotEmpty) problems.push("No test machines: no endpoint is in group pilot. Deploy in one stage, or put 2–5 machines in group pilot first.");
  if (preset === "emergency" && !justification.trim()) problems.push("Emergency deployments require a justification.");
  if (epsL.data && counts.every((c) => c === 0)) problems.push("No endpoint is in these stages.");
  // The plan (deadline, stage sizes) depends on the policy and the endpoint
  // list: never create from a half-loaded plan (e.g. silently without the
  // policy deadline).
  const planLoaded = !!policyL.data && !!epsL.data;
  const planError = [policyL.error && `policy: ${policyL.error}`, epsL.error && `endpoints: ${epsL.error}`].filter(Boolean).join(" · ");
  const retryPlan = () => { void policyL.reload(); void epsL.reload(); };
  const canCreate = approved && canDeploy && !sodBlocks && planLoaded && problems.length === 0;

  const visiblePresets = PRESETS.filter((p) => p.kind !== "endpoint" || endpoint);
  const ringsForPreview = draft.rings.map((r) => ({ name: r.name, groups: r.groups.join(", ") }));
  const handoffUrl = `${window.location.origin}${paths.catalog(pkg.package_id)}`;

  const footer: ReactNode = (
    <>
      <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
      {approved && canDeploy && !sodBlocks && (
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
        {fleet?.active_deployment_id && (
          <div className="banner banner-info">
            Already deploying in <Link to={`/deployments/${enc(fleet.active_deployment_id)}`}><Mono>{fleet.active_deployment_id}</Mono></Link>.
            A second deployment of the same package is usually not needed.
          </div>
        )}
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
                  <div className="hint">Separation of duties is on: after approving, another operator must create the deployment.</div>
                )}
                <div className="form-actions">
                  <button className="btn btn-primary" disabled={busy || !reason.trim()} onClick={() => void approve()}>
                    {busy ? "Working…" : approvals.length + 1 < required ? `Record approval (${approvals.length + 1} of ${required})` : "Approve"}
                  </button>
                </div>
              </>
            )}
            {canApprove && iApproved && (
              <div className="banner banner-info">You approved this package. Waiting for a second approver ({approvals.length} of {required}).</div>
            )}
            {!canApprove && (
              <div className="banner banner-info">Awaiting approval ({approvals.length} of {required}). An approver must approve it before it can be deployed.</div>
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
                <b>You approved this; an operator must deploy it.</b> Separation of duties is on, so the server refuses a deployment
                created by an approver of the package. Send this link to an operator:
                <CopyBox value={handoffUrl} />
              </div>
            ) : !canDeploy ? (
              <div className="banner banner-info">Deploying requires the operator role.</div>
            ) : (
              <>
                <div className="preset-row" role="radiogroup" aria-label="Preset">
                  {visiblePresets.map((p) => (
                    <button key={p.kind} type="button" role="radio" aria-checked={preset === p.kind}
                            className={`preset ${preset === p.kind ? "preset-on" : ""} ${p.kind === "emergency" ? "preset-danger" : ""}`}
                            onClick={() => setPreset(p.kind)}>
                      <b>{p.label}</b><span>{p.hint}</span>
                    </button>
                  ))}
                  <button type="button" className="preset" onClick={() => navigate(customHref(draft))}>
                    <b>Custom…</b><span>full form, prefilled</span>
                  </button>
                </div>

                {pilotEmpty && (
                  <div className="banner banner-warn">
                    <b>No test machines:</b> no endpoint is in group <span className="tag">pilot</span>, so stage 1 would be empty.
                    Deploy in one stage, or <Link to="/endpoints" onClick={onClose}>put 2–5 machines in group pilot</Link> first
                    (Endpoints → select → Edit groups).{" "}
                    <button className="btn btn-sm" onClick={() => setPreset("one_ring")}>Deploy in one stage (all machines)</button>
                  </div>
                )}
                {preset === "one_ring" && (
                  <div className="hint">One stage with every endpoint (no test machines first). <button className="btn-link" onClick={() => setPreset("standard")}>Back to Standard</button></div>
                )}

                {!planLoaded && (planError ? (
                  <div className="banner banner-error">
                    <b>The plan cannot be completed:</b> {planError}. Nothing can be created until both load.{" "}
                    <button className="btn btn-sm" onClick={retryPlan}>Retry</button>
                  </div>
                ) : (
                  <div className="hint">Loading the policy and the endpoint list…</div>
                ))}
                <div className="hint">{STAGES_HINT}</div>
                <PlanSummary draft={draft} counts={epsL.data ? counts : null} policyDeadline={policy?.deadlines?.[pkg.severity]}
                             policyMissing={!!policyL.error} dlFromPolicy={dl} />

                {preset === "emergency" && (
                  <label className="field">
                    <span>Justification <em className="req">required</em> <em className="muted">— incident or change ticket; recorded in the audit log</em></span>
                    <textarea rows={2} value={justification} onChange={(e) => setJustification(e.target.value)} />
                  </label>
                )}

                <details className="patch-preview">
                  <summary>Preview who receives it</summary>
                  <TargetPreview pkg={pkg} rings={ringsForPreview} endpoints={epsL.data} fleet={fleetL.data} />
                </details>

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
            <div className="small">The server refused it. With separation of duties on, someone who approved the package cannot also deploy it: hand it to another operator.</div>
          )}
        </div>
      )}
    </Modal>
  );
}

function PlanSummary({ draft, counts, policyDeadline: policyDur, policyMissing, dlFromPolicy }: {
  draft: NewDeployment; counts: number[] | null; policyDeadline: string | undefined; policyMissing: boolean; dlFromPolicy: Date | null;
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
                <b>{stageLabel(r.name, i)}</b> {r.groups.map((g) => <span key={g} className="tag">{g}</span>)}
                {counts && <span className={counts[i] === 0 ? "text-red" : "muted"}>({counts[i]} endpoint{counts[i] === 1 ? "" : "s"})</span>}
              </span>
            ))}
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
        <tr><th>Reboot</th><td>{REBOOT_LABELS[draft.reboot_policy]}</td></tr>
        <tr><th>Windows</th><td>{draft.ignore_windows ? <span className="text-red">ignored: installs start as soon as assigned</span> : "group maintenance windows apply"}</td></tr>
        <tr><th>Safety</th><td>auto-pause above {draft.max_failure_pct} % failures · {draft.max_retries} retries</td></tr>
      </tbody>
    </table>
  );
}
