import { Link } from "react-router-dom";
import { api, enc } from "../api";
import type { CatalogLink, EndpointUpdates, IntelSummary } from "../types";
import { useLoad } from "../util";
import { ErrorBanner, Mono, Pill, RelTime } from "./ui";

/** Where an available update stands in the offline pipeline. */
export function CatalogState({ link }: { link: CatalogLink | null }) {
  if (!link) return <span className="muted" title="Not imported yet: add it to the acquisition run (pmctl fetch / acquire.json)">not imported</span>;
  const label = { approved: "in catalog · approved", quarantined: "in catalog · awaiting approval" }[link.state] ?? `in catalog · ${link.state}`;
  return <Link to={`/catalog/${enc(link.package_id)}`}><Pill state={link.state} label={label} /></Link>;
}

export function IntelSource({ intel }: { intel: IntelSummary | null | undefined }) {
  if (!intel) return null;
  return (
    <span className="muted">
      update intelligence from <RelTime value={intel.generated_at} /> · {intel.windows} Windows builds · {intel.apps.toLocaleString()} apps
    </span>
  );
}

/**
 * "What is this endpoint missing?" — inventory compared with update
 * intelligence (newest Windows cumulative updates and app versions from the
 * acquisition zone), including updates not imported into the catalog yet.
 */
export function UpdatesAvailable({ endpointId, os }: { endpointId: string; os: string }) {
  const { data, error } = useLoad(() => api.get<EndpointUpdates>(`/api/endpoints/${enc(endpointId)}/updates`), [endpointId], 30000);
  if (os !== "windows") return null;
  const n = data ? data.os.length + data.apps.length : null;
  return (
    <section className="section">
      <div className="section-head">
        <h2>Updates available <span className="muted">· {n ?? "…"}</span></h2>
        <IntelSource intel={data?.intel} />
      </div>
      <ErrorBanner error={error} />
      {data?.intel?.error && (
        <div className="banner banner-error">The stored update intelligence cannot be used: {data.intel.error}. Send a new document from the acquisition zone.</div>
      )}
      {data && !data.intel && (
        <div className="empty">
          No update intelligence received yet. <span className="muted">Enable <Mono>"intel": {"{}"}</Mono> in the acquisition config (or run <Mono>pmctl intel</Mono>) so the newest Windows and application versions reach this server.</span>
        </div>
      )}
      {data?.intel && !data.intel.error && n === 0 && (
        <div className="empty">
          Windows and all {data.current} recognised applications are up to date.
          {data.unmatched > 0 && <span className="muted"> {data.unmatched} installed programs are not in the application index and are not checked.</span>}
        </div>
      )}
      {data?.intel && n! > 0 && (
        <table className="table">
          <thead>
            <tr><th>Update</th><th>Installed</th><th>Available</th><th>Catalog</th></tr>
          </thead>
          <tbody>
            {data.os.map((u) => (
              <tr key={u.kb}>
                <td>
                  <div className="cell-title">{u.title}</div>
                  <div className="cell-sub"><span className="tag">Windows</span> {u.product} · released {u.release_date}{u.size_mb ? ` · ${u.size_mb.toLocaleString()} MB` : ""}</div>
                </td>
                <td className="nowrap"><Mono>{u.build}.{u.installed_ubr || "?"}</Mono></td>
                <td className="nowrap">
                  <Mono>{u.kb}</Mono>{u.ubr ? <> → <Mono>{u.build}.{u.ubr}</Mono></> : null}
                  {u.basis === "kb_inventory" && <div className="cell-sub" title="Decided from the installed-updates list because a build revision is unknown">by KB list</div>}
                </td>
                <td><CatalogState link={u.catalog} /></td>
              </tr>
            ))}
            {data.apps.map((u) => (
              <tr key={u.app_id + u.installed_name}>
                <td>
                  <div className="cell-title">{u.installed_name}</div>
                  <div className="cell-sub"><span className="tag">app</span> <Mono>{u.app_id}</Mono>{u.matched_by === "name" && <span className="muted" title="Matched by display name, not by product code"> · matched by name</span>}</div>
                </td>
                <td className="nowrap"><Mono>{u.installed_version}</Mono></td>
                <td className="nowrap"><b><Mono>{u.latest_version}</Mono></b></td>
                <td><CatalogState link={u.catalog} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data?.intel && n! > 0 && (
        <div className="hint">
          {data.current} recognised applications are current{data.unmatched > 0 && <>; {data.unmatched} installed programs are not in the application index</>}.
          Updates marked <i>not imported</i> must be acquired (and approved) before they can be deployed.
        </div>
      )}
    </section>
  );
}
