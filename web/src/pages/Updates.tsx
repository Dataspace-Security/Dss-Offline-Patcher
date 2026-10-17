import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, enc } from "../api";
import { CatalogState, IntelSource } from "../components/UpdatesAvailable";
import { ErrorBanner, Mono, PageHeader } from "../components/ui";
import type { FleetUpdates } from "../types";
import { useLoad } from "../util";

/** Every update the fleet is missing, with the endpoints that need it. */
export default function Updates() {
  const { data, error } = useLoad(() => api.get<FleetUpdates>("/api/updates"), [], 60000);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<"" | "os" | "app">("");
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.updates ?? []).filter((u) =>
      (!kind || u.kind === kind) &&
      (!needle || u.name.toLowerCase().includes(needle) || u.key.toLowerCase().includes(needle) || u.endpoints.some((e) => e.hostname.toLowerCase().includes(needle))));
  }, [data, q, kind]);
  const osCount = (data?.updates ?? []).filter((u) => u.kind === "os").length;
  const appCount = (data?.updates ?? []).length - osCount;

  return (
    <>
      <PageHeader title="Updates" sub="Everything the fleet is missing: Windows cumulative updates and newer versions of installed applications, whether or not they are in the catalog yet">
        {data?.intel && <input className="search" placeholder="Filter by update, app or host…" value={q} onChange={(e) => setQ(e.target.value)} />}
      </PageHeader>
      <ErrorBanner error={error} />
      {data?.intel?.error && <div className="banner banner-error">The stored update intelligence cannot be used: {data.intel.error}</div>}
      {data && !data.intel && (
        <div className="empty">
          No update intelligence received yet. Enable <Mono>"intel": {"{}"}</Mono> in the acquisition config (<Mono>/etc/offpatch/acquire.json</Mono>)
          or run <Mono>pmctl intel -key bundle.key -to &lt;inbox&gt;</Mono> in the acquisition zone.
        </div>
      )}
      {data?.intel && (
        <>
          <div className="section-head">
            <div className="chips">
              <button className={`chip ${kind === "" ? "chip-on" : ""}`} onClick={() => setKind("")}>All <b>{osCount + appCount}</b></button>
              <button className={`chip ${kind === "os" ? "chip-on" : ""}`} onClick={() => setKind("os")}>Windows <b>{osCount}</b></button>
              <button className={`chip ${kind === "app" ? "chip-on" : ""}`} onClick={() => setKind("app")}>Applications <b>{appCount}</b></button>
            </div>
            <IntelSource intel={data.intel} />
          </div>
          {rows.length === 0 ? (
            <div className="empty">{(data.updates ?? []).length === 0 ? "The whole fleet is up to date." : "No updates match the filter."}</div>
          ) : (
            <table className="table">
              <thead>
                <tr><th>Update</th><th>Latest</th><th>Endpoints</th><th>Catalog</th></tr>
              </thead>
              <tbody>
                {rows.map((u) => (
                  <tr key={u.kind + u.key}>
                    <td>
                      <div className="cell-title">{u.name}</div>
                      <div className="cell-sub"><span className="tag">{u.kind === "os" ? "Windows" : "app"}</span> <Mono>{u.key}</Mono></div>
                    </td>
                    <td className="nowrap"><Mono>{u.latest}</Mono></td>
                    <td>
                      <b>{u.endpoints.length}</b>{" "}
                      <span className="muted">
                        {u.endpoints.slice(0, 5).map((e, i) => (
                          <span key={e.endpoint_id}>{i > 0 && ", "}<Link to={`/endpoints/${enc(e.endpoint_id)}`}>{e.hostname}</Link>{u.kind === "app" && <> ({e.installed})</>}</span>
                        ))}
                        {u.endpoints.length > 5 && <> and {u.endpoints.length - 5} more</>}
                      </span>
                    </td>
                    <td><CatalogState link={u.catalog} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </>
  );
}
