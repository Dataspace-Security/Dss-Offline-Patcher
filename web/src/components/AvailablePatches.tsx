import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, enc } from "../api";
import { paths } from "../paths";
import { useCan } from "../auth";
import type { AcquisitionRequestRecord, AcquisitionRequestRef, CatalogLink, EndpointUpdates, PackageKind } from "../types";
import { useLoad } from "../util";
import { acqStatusPill } from "./AcqRequestStatus";
import { PatchThis } from "./PatchThis";
import { isAgentPackage } from "./patchPlan";
import { PipelineAction, isRequestable } from "./PipelineAction";
import { RequestResultBanner } from "./RequestResultBanner";
import { latestRequests, useImportRequest, type ImportItems } from "./useImportRequest";
import { IntelSource } from "./UpdatesAvailable";
import { ErrorBanner, Mono, Pill } from "./ui";
import "../patch.css";

/** GET /api/endpoints/{id}/available: approved or quarantined catalog packages this endpoint needs. */
export type Available = {
  package_id: string; title: string; kind: string; severity: string; version: string; kb: string;
  installed_version: string; package_state: "approved" | "quarantined"; reason: string;
  deployment_id: string; target_state: string;
};

type Row = {
  key: string;
  kind: "Windows" | "app" | string;
  title: string;
  sub: ReactNode;
  installed: ReactNode;
  available: ReactNode;
  severity?: string;
  link: CatalogLink | null;
  deploymentId: string;
  targetState: string;
  /** What Import asks for (intelligence rows only; catalog-only rows are already imported). */
  importItems: ImportItems | null;
  /** Key into the tracked acquisition requests ("app:<winget id>" / "kb:<KB>"). */
  requestKey: string;
  /** An offpatch agent version (approved and deployed by the super admin only). */
  agent?: boolean;
};

/** Where an update stands: to import → importing → awaiting approval → ready → deploying (target state). */
function Pipeline({ r, requested }: { r: Row; requested: AcquisitionRequestRef | undefined }) {
  if (r.deploymentId) {
    return <Link to={paths.deployment(r.deploymentId)}><Pill state={r.targetState || "pending"} label={`deploying: ${(r.targetState || "pending").replace(/_/g, " ")}`} /></Link>;
  }
  if (!r.link) {
    if (!requested) return <span className="muted" title="Not in the catalog yet: Import downloads it in the acquisition zone">not in the catalog yet</span>;
    const s = acqStatusPill(requested.status);
    return <Pill state={s.pill} label={s.label} />;
  }
  const label = { approved: "ready", quarantined: "awaiting approval" }[r.link.state] ?? r.link.state;
  return <Link to={paths.catalog(r.link.package_id)}><Pill state={r.link.state} label={label} /></Link>;
}

function mergeRows(intel: EndpointUpdates | null, avail: Available[] | null): Row[] {
  const byPkg = new Map((avail ?? []).map((a) => [a.package_id, a]));
  const used = new Set<string>();
  const rows: Row[] = [];
  const fromCatalog = (link: CatalogLink | null) => {
    const a = link ? byPkg.get(link.package_id) : undefined;
    if (a) used.add(a.package_id);
    return a;
  };
  for (const u of intel?.os ?? []) {
    const a = fromCatalog(u.catalog);
    rows.push({
      key: `os:${u.kb}`, kind: "Windows", title: u.title,
      sub: <>{u.product} · released {u.release_date}{u.size_mb ? ` · ${u.size_mb.toLocaleString()} MB` : ""}{u.basis === "kb_inventory" && <span title="Decided from the installed-updates list because a build revision is unknown"> · by KB list</span>}</>,
      installed: <Mono>{u.build}.{u.installed_ubr || "?"}</Mono>,
      available: <><Mono>{u.kb}</Mono>{u.ubr ? <> → <Mono>{u.build}.{u.ubr}</Mono></> : null}</>,
      severity: a?.severity, link: u.catalog, deploymentId: a?.deployment_id ?? "", targetState: a?.target_state ?? "",
      importItems: { apps: [], kbs: [u.kb] }, requestKey: `kb:${u.kb.toLowerCase()}`,
    });
  }
  for (const u of intel?.apps ?? []) {
    const a = fromCatalog(u.catalog);
    rows.push({
      key: `app:${u.app_id}:${u.installed_name}`, kind: "app", title: u.installed_name,
      sub: <><Mono>{u.app_id}</Mono>{u.matched_by === "name" && <span title="Matched by display name, not by product code"> · matched by name</span>}</>,
      installed: <Mono>{u.installed_version}</Mono>, available: <b><Mono>{u.latest_version}</Mono></b>,
      severity: a?.severity, link: u.catalog, deploymentId: a?.deployment_id ?? "", targetState: a?.target_state ?? "",
      importItems: { apps: [u.app_id], kbs: [] }, requestKey: `app:${u.app_id.toLowerCase()}`,
    });
  }
  // Catalog packages the intelligence does not list (other OSes, agent, no intel yet).
  for (const a of avail ?? []) {
    if (used.has(a.package_id)) continue;
    rows.push({
      key: `pkg:${a.package_id}`, kind: a.kind === "msu" ? "Windows" : a.kind, title: a.title,
      sub: <><Mono>{a.package_id}</Mono>{a.reason && <> · {a.reason}</>}</>,
      installed: a.kb ? <span className="muted">missing</span> : <Mono>{a.installed_version || "—"}</Mono>,
      available: a.kb ? <Mono>{a.kb}</Mono> : <b><Mono>{a.version}</Mono></b>,
      severity: a.severity, link: { package_id: a.package_id, state: a.package_state },
      deploymentId: a.deployment_id, targetState: a.target_state, importItems: null, requestKey: "",
      agent: isAgentPackage({ kind: a.kind as PackageKind, package_id: a.package_id }),
    });
  }
  return rows;
}

/**
 * One "Updates" table for an endpoint (P2.6): update intelligence (newest
 * Windows CUs and app versions, imported or not) merged with the catalog
 * packages it needs, with the pipeline state and a single next action.
 */
export function EndpointUpdatesTable({ endpointId, hostname, os }: { endpointId: string; hostname: string; os: string }) {
  const windows = os === "windows";
  const intel = useLoad(() => (windows ? api.get<EndpointUpdates>(`/api/endpoints/${enc(endpointId)}/updates`) : Promise.resolve(null)), [endpointId, windows], 30000);
  const avail = useLoad(() => api.get<Available[]>(`/api/endpoints/${enc(endpointId)}/available`), [endpointId], 15000);
  const canImport = useCan("user");
  // Tracked acquisition requests: "Importing… requested 5m ago" on the rows already asked for.
  const reqs = useLoad(() => api.get<AcquisitionRequestRecord[]>("/api/acquisition-requests"), [endpointId], 30000);
  const [patching, setPatching] = useState<string | null>(null);
  const imp = useImportRequest(() => { void reqs.reload(); void intel.reload(); void avail.reload(); });
  const requestedBy = latestRequests(reqs.data);
  const rows = mergeRows(intel.data, avail.data);
  const importable = (r: Row) => !r.deploymentId && !!r.importItems && isRequestable(r.link, r.requestKey ? requestedBy.get(r.requestKey) : undefined);
  const loaded = avail.data !== null && (!windows || intel.data !== null || !!intel.error);
  const info = intel.data;

  return (
    <section className="section">
      <div className="section-head">
        <h2>Updates <span className="muted">· {loaded ? rows.length : "…"} needed</span></h2>
        <IntelSource intel={info?.intel} />
      </div>
      <ErrorBanner error={intel.error || avail.error} />
      {imp.error && <div className="banner banner-error">Import failed: {imp.error}</div>}
      {imp.result && <RequestResultBanner req={imp.result} onDismiss={imp.dismiss} />}
      {info?.intel?.error && (
        <div className="banner banner-error">The stored update intelligence cannot be used: {info.intel.error}. Ask the acquisition team to send a new one.</div>
      )}
      {windows && info && !info.intel && (
        <div className="hint">
          No update intelligence received yet, so only catalog packages are checked. Ask the acquisition team to send update
          intelligence; then every missing Windows and application update shows here.
        </div>
      )}
      {loaded && rows.length === 0 && (
        <div className="empty">
          {info?.intel && !info.intel.error
            ? <>Windows and all {info.current} recognised applications are up to date, and no catalog package is needed.</>
            : <>Up to date with the catalog.</>}
          {(info?.unmatched ?? 0) > 0 && <span className="muted"> {info!.unmatched} installed programs are not in the application index and are not checked.</span>}
          <span className="muted"> Apps that are not installed are never offered.</span>
        </div>
      )}
      {rows.length > 0 && (
        <table className="table">
          <thead>
            <tr><th>Update</th><th>Severity</th><th>Installed</th><th>Available</th><th>Pipeline</th><th className="right" /></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key}>
                <td>
                  {r.link ? <Link to={paths.catalog(r.link.package_id)} className="cell-title">{r.title}</Link> : <div className="cell-title">{r.title}</div>}
                  <div className="cell-sub"><span className="tag">{r.kind}</span> {r.sub}</div>
                </td>
                <td>{r.severity ? <span className={`sev sev-${r.severity}`}>{r.severity}</span> : <span className="muted">—</span>}</td>
                <td className="nowrap">{r.installed}</td>
                <td className="nowrap">{r.available}</td>
                <td><Pipeline r={r} requested={r.link ? undefined : requestedBy.get(r.requestKey)} /></td>
                <td className="right">
                  {r.deploymentId
                    ? <Link className="btn btn-sm" to={paths.deployment(r.deploymentId)}>Deployment →</Link>
                    : <PipelineAction link={r.link} agent={r.agent} requested={r.requestKey ? requestedBy.get(r.requestKey) : undefined} onPatch={setPatching}
                                      onRequest={importable(r) ? () => void imp.send(r.importItems!, r.key) : undefined}
                                      requesting={imp.busy === r.key} disabled={imp.busy !== null} />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {rows.some(importable) && (
        <div className="hint">
          {canImport
            ? <>Import downloads the update in the acquisition zone (it is verified, signed and comes back here for approval); then <b>Patch this</b> installs it.</>
            : <>Updates not in the catalog yet must be imported by a User (here or on <Link to={paths.needed()}>Patches → Needed</Link>); then they can be approved and installed.</>}
        </div>
      )}
      {patching && (
        <PatchThis packageId={patching} endpoint={{ id: endpointId, hostname }} onClose={() => setPatching(null)}
                   onChanged={() => { void avail.reload(); void intel.reload(); }} />
      )}
    </section>
  );
}
