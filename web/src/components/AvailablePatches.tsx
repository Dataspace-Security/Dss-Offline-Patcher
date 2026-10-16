import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, enc, errMsg } from "../api";
import { useCan } from "../auth";
import type { Deployment } from "../types";
import { useLoad } from "../util";
import { ErrorBanner, Mono, Pill } from "./ui";

export type Available = {
  package_id: string; title: string; kind: string; severity: string; version: string; kb: string;
  installed_version: string; package_state: "approved" | "quarantined"; reason: string;
  deployment_id: string; target_state: string;
};

/** Creates a deployment that targets exactly the given endpoints. */
export async function deployToEndpoints(packageId: string, title: string, endpointIds: string[], label: string): Promise<Deployment> {
  return api.post<Deployment>("/api/deployments", {
    package_id: packageId,
    name: `${title} → ${label}`,
    rings: [{ name: "needed", groups: endpointIds.map((id) => `endpoint:${id}`) }],
    max_failure_pct: 20, max_retries: 2, window_start: "", window_end: "", emergency: false, justification: "",
    deadline: "", max_concurrent: 0, reboot_policy: "never", ignore_windows: false, health_checks: [],
  });
}

/** "What does this endpoint still need?" — inventory compared with the catalog. */
export function AvailablePatches({ endpointId, hostname }: { endpointId: string; hostname: string }) {
  const canDeploy = useCan("operator");
  const navigate = useNavigate();
  const { data, error, reload } = useLoad(() => api.get<Available[]>(`/api/endpoints/${enc(endpointId)}/available`), [endpointId], 15000);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const ready = (data ?? []).filter((a) => a.package_state === "approved" && !a.deployment_id);

  const deploy = async (items: Available[]) => {
    setErr(null);
    let last: Deployment | null = null;
    for (const a of items) {
      setBusy(a.package_id);
      try {
        last = await deployToEndpoints(a.package_id, a.title, [endpointId], hostname);
      } catch (e) {
        setErr(`${a.package_id}: ${errMsg(e)}`);
        break;
      }
    }
    setBusy(null);
    reload();
    if (last && items.length === 1) navigate(`/deployments/${enc(last.deployment_id)}`);
  };

  return (
    <section className="section">
      <div className="section-head">
        <h2>Available patches <span className="muted">· {data?.length ?? "…"} needed</span></h2>
        {canDeploy && ready.length > 1 && (
          <button className="btn btn-primary btn-sm" disabled={!!busy} onClick={() => deploy(ready)}>Deploy all ready ({ready.length})</button>
        )}
      </div>
      <ErrorBanner error={error || err} />
      {data && data.length === 0 && (
        <div className="empty">
          Up to date with the catalog. <span className="muted">Only patches already imported into the catalog are checked; apps that are not installed are never offered, and macOS system updates are not covered.</span>
        </div>
      )}
      {data && data.length > 0 && (
        <table className="table">
          <thead>
            <tr><th>Patch</th><th>Severity</th><th>Kind</th><th>Installed → Available</th><th>Why</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {data.map((a) => (
              <tr key={a.package_id}>
                <td><Link to={`/catalog/${enc(a.package_id)}`} className="cell-title">{a.title}</Link><div className="cell-sub"><Mono>{a.package_id}</Mono></div></td>
                <td><span className={`sev sev-${a.severity}`}>{a.severity}</span></td>
                <td><span className="tag">{a.kind}</span></td>
                <td className="nowrap">{a.kb ? <>missing <Mono>{a.kb}</Mono></> : <>{a.installed_version || "—"} → <b>{a.version}</b></>}</td>
                <td className="muted">{a.reason}</td>
                <td>
                  {a.deployment_id
                    ? <Link to={`/deployments/${enc(a.deployment_id)}`}><Pill state={a.target_state} label={`deploying: ${a.target_state.replace(/_/g, " ")}`} /></Link>
                    : a.package_state === "approved" ? <Pill state="approved" label="ready" /> : <Pill state="quarantined" label="awaiting approval" />}
                </td>
                <td className="right">
                  {canDeploy && a.package_state === "approved" && !a.deployment_id && (
                    <button className="btn btn-sm btn-primary" disabled={!!busy} onClick={() => deploy([a])}>
                      {busy === a.package_id ? "Deploying…" : "Deploy here"}
                    </button>
                  )}
                  {a.package_state === "quarantined" && <Link className="btn btn-sm" to={`/catalog/${enc(a.package_id)}`}>Review…</Link>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
