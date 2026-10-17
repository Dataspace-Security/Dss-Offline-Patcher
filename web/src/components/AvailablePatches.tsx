import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, enc } from "../api";
import { paths } from "../paths";
import type { CatalogLink, EndpointUpdates } from "../types";
import { useLoad } from "../util";
import { PatchThis } from "./PatchThis";
import { PipelineAction } from "./PipelineAction";
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
};

/** Where an update stands: not imported → awaiting approval → ready → deploying (target state). */
function Pipeline({ r }: { r: Row }) {
  if (r.deploymentId) {
    return <Link to={paths.deployment(r.deploymentId)}><Pill state={r.targetState || "pending"} label={`deploying: ${(r.targetState || "pending").replace(/_/g, " ")}`} /></Link>;
  }
  if (!r.link) return <span className="muted" title="Must be acquired: select it on Patches → Updates and export an acquisition request">not imported</span>;
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
    });
  }
  for (const u of intel?.apps ?? []) {
    const a = fromCatalog(u.catalog);
    rows.push({
      key: `app:${u.app_id}:${u.installed_name}`, kind: "app", title: u.installed_name,
      sub: <><Mono>{u.app_id}</Mono>{u.matched_by === "name" && <span title="Matched by display name, not by product code"> · matched by name</span>}</>,
      installed: <Mono>{u.installed_version}</Mono>, available: <b><Mono>{u.latest_version}</Mono></b>,
      severity: a?.severity, link: u.catalog, deploymentId: a?.deployment_id ?? "", targetState: a?.target_state ?? "",
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
      deploymentId: a.deployment_id, targetState: a.target_state,
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
  const [patching, setPatching] = useState<string | null>(null);
  const rows = mergeRows(intel.data, avail.data);
  const loaded = avail.data !== null && (!windows || intel.data !== null || !!intel.error);
  const info = intel.data;

  return (
    <section className="section">
      <div className="section-head">
        <h2>Updates <span className="muted">· {loaded ? rows.length : "…"} needed</span></h2>
        <IntelSource intel={info?.intel} />
      </div>
      <ErrorBanner error={intel.error || avail.error} />
      {info?.intel?.error && (
        <div className="banner banner-error">The stored update intelligence cannot be used: {info.intel.error}. Send a new document from the acquisition zone.</div>
      )}
      {windows && info && !info.intel && (
        <div className="hint">
          No update intelligence received yet, so only catalog packages are checked. Enable <Mono>"intel": {"{}"}</Mono> in the acquisition
          config (or run <Mono>pmctl intel</Mono>) to see every missing Windows and application update.
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
                <td><Pipeline r={r} /></td>
                <td className="right">
                  {r.deploymentId
                    ? <Link className="btn btn-sm" to={paths.deployment(r.deploymentId)}>Deployment →</Link>
                    : <PipelineAction link={r.link} onPatch={setPatching} />}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {rows.some((r) => !r.link) && (
        <div className="hint">
          Updates marked <i>not imported</i> must be acquired first: select them on <Link to={paths.updates()}>Patches → Updates</Link> and export an acquisition request.
        </div>
      )}
      {patching && (
        <PatchThis packageId={patching} endpoint={{ id: endpointId, hostname }} onClose={() => setPatching(null)}
                   onChanged={() => { void avail.reload(); void intel.reload(); }} />
      )}
    </section>
  );
}
