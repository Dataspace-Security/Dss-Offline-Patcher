import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, downloadFile, enc, errMsg, qs } from "../api";
import type { AcquisitionRequestRecord, LifecycleExport, Package, PackageFleet, Target, TargetState } from "../types";
import { parseTime, useLoad } from "../util";
import { useCan } from "../auth";
import { ErrorBanner, Mono, Time } from "./ui";
import "../patch.css";

type Status = "done" | "current" | "pending" | "bad";
type Step = { key: string; title: ReactNode; status: Status; at?: string; actor?: string; detail?: ReactNode };

/** Does a tracked request item refer to this package? */
function requestMatches(item: AcquisitionRequestRecord["items"][number], pkg: Package): boolean {
  if (item.package_id && item.package_id === pkg.package_id) return true;
  if (item.kind === "kb") return !!pkg.kb && item.key.toUpperCase() === pkg.kb.toUpperCase();
  // winget packages are named "<winget id>-<version>"
  return pkg.package_id.toLowerCase().startsWith(`${item.key.toLowerCase()}-`);
}

const latest = (xs: (string | undefined)[]): string | undefined =>
  xs.filter((x) => parseTime(x)).sort((a, b) => new Date(b!).getTime() - new Date(a!).getTime())[0];
const earliest = (xs: (string | undefined)[]): string | undefined =>
  xs.filter((x) => parseTime(x)).sort((a, b) => new Date(a!).getTime() - new Date(b!).getTime())[0];

// Best first: a verified install beats a failure elsewhere; "not applicable"
// only stands when no deployment found the patch applicable.
const STATE_RANK: TargetState[] = [
  "verified", "installed", "pending_reboot", "installing", "downloaded", "downloading", "pending", "deferred",
  "failed", "lost_after_install", "rolled_back", "exception", "not_applicable",
];
const rankOf = (s: TargetState) => { const i = STATE_RANK.indexOf(s); return i < 0 ? STATE_RANK.length : i; };

export function bestTargetPerEndpoint(targets: Target[]): Target[] {
  const best = new Map<string, Target>();
  for (const t of targets) {
    const cur = best.get(t.endpoint_id);
    if (!cur || rankOf(t.state) < rankOf(cur.state) || (rankOf(t.state) === rankOf(cur.state) && t.updated_at > cur.updated_at)) {
      best.set(t.endpoint_id, t);
    }
  }
  return Array.from(best.values());
}

export function buildSteps(pkg: Package, life: LifecycleExport | null, requests: AcquisitionRequestRecord[] | null, fleet: PackageFleet | undefined): Step[] {
  const steps: Step[] = [];
  const events = life?.events ?? [];
  const ev = (prefix: string) => events.filter((e) => e.action.startsWith(prefix));

  steps.push({
    key: "needed", title: <>Needed{fleet ? <> by <b>{fleet.needed}</b> endpoint{fleet.needed === 1 ? "" : "s"}</> : null}</>,
    status: fleet ? (fleet.needed > 0 ? "current" : "done") : "pending",
    detail: fleet && fleet.needed === 0 ? "no endpoint needs it now" : undefined,
  });

  const reqs = (requests ?? []).filter((r) => r.items.some((i) => requestMatches(i, pkg)));
  const firstReq = reqs.sort((a, b) => a.created_at.localeCompare(b.created_at))[0];
  const item = firstReq?.items.find((i) => requestMatches(i, pkg));
  steps.push({
    key: "requested", title: <>Requested{reqs.length > 1 ? <span className="muted"> · {reqs.length} requests</span> : null}</>,
    status: firstReq ? "done" : "pending", at: firstReq?.created_at, actor: firstReq?.created_by,
    detail: firstReq ? <><Mono>{firstReq.request_id}</Mono> · {item?.status ?? "requested"}{item?.reason ? <>: {item.reason}</> : null}{firstReq.seen_at && parseTime(firstReq.seen_at) ? <> · seen by the acquisition zone <Time value={firstReq.seen_at} hideRel /></> : null}</>
      : requests === null ? "request tracking unavailable" : "no tracked acquisition request (it may have arrived with a regular feed)",
  });

  const sigAt = pkg.vendor_signature?.checked_at;
  steps.push({
    key: "downloaded", title: "Downloaded", status: parseTime(sigAt) ? "done" : "pending", at: sigAt,
    actor: life?.bundle?.source ? `source ${life.bundle.source}` : undefined,
    detail: pkg.source_url ? <span className="break">{pkg.source_url}</span> : undefined,
  });

  const bundle = life?.bundle;
  const rejected = bundle?.state === "rejected";
  steps.push({
    key: "received", title: "Received & validated", status: rejected ? "bad" : bundle ? "done" : "pending",
    at: bundle?.received_at ?? ev("bundle.")[0]?.ts,
    actor: ev("bundle.validated")[0]?.actor,
    detail: bundle ? <>bundle <Mono>{bundle.bundle_id}</Mono> · {bundle.state}</> : undefined,
  });

  const approvals = pkg.approvals ?? [];
  const required = pkg.approvals_required || 1;
  const approvedEv = ev("package.approved")[0];
  const isApproved = pkg.state === "approved" || (pkg.state === "revoked" && !!approvedEv);
  steps.push({
    key: "approved",
    title: <>Approved <span className="muted">({approvals.length}/{required})</span></>,
    status: pkg.state === "rejected" ? "bad" : isApproved ? "done" : pkg.state === "quarantined" ? "current" : "pending",
    at: isApproved ? (approvedEv?.ts ?? latest(approvals.map((a) => a.at))) : latest(approvals.map((a) => a.at)),
    actor: approvals.map((a) => a.by).join(", ") || undefined,
    detail: pkg.state === "rejected" ? <>rejected: {pkg.state_reason}</> : pkg.state === "revoked" ? <span className="text-red">revoked: {pkg.state_reason}</span> : undefined,
  });

  const deps = (life?.deployments ?? []).filter((d) => (d.operation ?? "install") === "install");
  const active = deps.find((d) => d.state === "active" || d.state === "paused");
  const firstDep = [...deps].sort((a, b) => a.created_at.localeCompare(b.created_at))[0];
  const shown = active ?? firstDep;
  steps.push({
    key: "deploying",
    title: <>Deploying{shown ? <> · stage {Math.min(shown.current_ring, (shown.rings?.length ?? 1) - 1) + 1} of {shown.rings?.length ?? 1}</> : null}</>,
    status: active ? (active.state === "paused" ? "bad" : "current") : deps.length ? "done" : "pending",
    at: shown?.created_at, actor: shown?.created_by,
    detail: shown ? <><Link to={`/deployments/${enc(shown.deployment_id)}`}><Mono>{shown.deployment_id}</Mono></Link> · {shown.state}{deps.length > 1 ? ` · ${deps.length} deployments` : ""}</> : undefined,
  });

  // One entry per endpoint across the (non-cancelled) install deployments:
  // a machine retried in a second deployment counts once, with its best state.
  const targets = bestTargetPerEndpoint(deps.filter((d) => d.state !== "cancelled").flatMap((d) => d.targets ?? []));
  const applicable = targets.filter((t) => t.state !== "not_applicable" && t.state !== "exception");
  const verified = applicable.filter((t) => t.state === "verified");
  const failed = applicable.filter((t) => t.state === "failed" || t.state === "lost_after_install").length;
  steps.push({
    key: "verified",
    title: <>Verified <b>{verified.length}</b>/{applicable.length}{failed > 0 && <span className="text-red"> · {failed} failed</span>}</>,
    status: applicable.length && verified.length === applicable.length ? "done" : verified.length ? "current" : failed ? "bad" : "pending",
    at: latest(verified.map((t) => t.updated_at)),
    detail: verified.length ? <>first <Time value={earliest(verified.map((t) => t.updated_at))} hideRel /></> : undefined,
  });
  return steps;
}

/** P2.1: one package's path from "needed" to "verified", from the audit export and tracked requests. */
export function LifecycleTimeline({ pkg, fleet }: { pkg: Package; fleet: PackageFleet | undefined }) {
  const id = pkg.package_id;
  const life = useLoad(() => api.get<LifecycleExport>(`/api/audit/export${qs({ package_id: id })}`), [id, pkg.state, pkg.approvals?.length]);
  // Import tracking is User and up (viewers: the timeline without request steps' details).
  const canImport = useCan("user");
  const reqs = useLoad(() => (canImport ? api.get<AcquisitionRequestRecord[]>("/api/acquisition-requests") : Promise.resolve(null)), [id, canImport]);
  const [dlErr, setDlErr] = useState<string | null>(null);
  const steps = buildSteps(pkg, life.data, !canImport || reqs.error ? null : reqs.data ?? [], fleet);

  const download = async () => {
    setDlErr(null);
    try {
      await downloadFile(`/api/audit/export${qs({ package_id: id })}`, `lifecycle-${id.replace(/[^A-Za-z0-9._-]/g, "_")}.json`);
    } catch (e) {
      setDlErr(errMsg(e));
    }
  };

  return (
    <>
      <div className="section-head">
        <h3>Lifecycle</h3>
        <button className="btn btn-sm" onClick={() => void download()}>Download lifecycle JSON</button>
      </div>
      <ErrorBanner error={life.error ? `Lifecycle: ${life.error}` : dlErr} />
      <ol className="timeline">
        {steps.map((s) => (
          <li key={s.key} className={`tl-${s.status}`}>
            <div className="tl-title">{s.title}</div>
            {(s.at || s.actor) && (
              <div className="tl-meta">
                {s.at && parseTime(s.at) ? <Time value={s.at} /> : null}
                {s.actor && <> · {s.actor}</>}
              </div>
            )}
            {s.detail && <div className="tl-meta">{s.detail}</div>}
          </li>
        ))}
      </ol>
    </>
  );
}
