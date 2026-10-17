import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, enc, errMsg, saveBlob } from "../api";
import { useCan } from "../auth";
import { CatalogState, IntelSource } from "../components/UpdatesAvailable";
import { ErrorBanner, Mono, PageHeader } from "../components/ui";
import type { AcquisitionRequest, FleetUpdates } from "../types";
import { useLoad } from "../util";

type Row = FleetUpdates["updates"][number];
const rowKey = (u: Row) => `${u.kind}:${u.key}`;

/** Every update the fleet is missing, with the endpoints that need it. */
export default function Updates() {
  const { data, error } = useLoad(() => api.get<FleetUpdates>("/api/updates"), [], 60000);
  const canRequest = useCan("operator");
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<"" | "os" | "app">("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [exportErr, setExportErr] = useState<string | null>(null);
  const [exported, setExported] = useState<AcquisitionRequest | null>(null);
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.updates ?? []).filter((u) =>
      (!kind || u.kind === kind) &&
      (!needle || u.name.toLowerCase().includes(needle) || u.key.toLowerCase().includes(needle) || u.endpoints.some((e) => e.hostname.toLowerCase().includes(needle))));
  }, [data, q, kind]);
  const osCount = (data?.updates ?? []).filter((u) => u.kind === "os").length;
  const appCount = (data?.updates ?? []).length - osCount;

  // Only updates not in the catalog yet can be requested; the selection
  // follows the current data (an update that disappears drops out).
  const chosen = (data?.updates ?? []).filter((u) => !u.catalog && selected.has(rowKey(u)));
  const visibleRequestable = rows.filter((u) => !u.catalog);
  const allOn = visibleRequestable.length > 0 && visibleRequestable.every((u) => selected.has(rowKey(u)));
  const toggleOne = (u: Row) => {
    const n = new Set(selected);
    if (n.has(rowKey(u))) n.delete(rowKey(u)); else n.add(rowKey(u));
    setSelected(n);
  };
  const toggleAll = () => {
    const n = new Set(selected);
    for (const u of visibleRequestable) {
      if (allOn) n.delete(rowKey(u)); else n.add(rowKey(u));
    }
    setSelected(n);
  };

  const exportRequest = async () => {
    setBusy(true);
    setExportErr(null);
    try {
      const req = await api.post<AcquisitionRequest>("/api/acquisition-requests", {
        apps: chosen.filter((u) => u.kind === "app").map((u) => u.key),
        kbs: chosen.filter((u) => u.kind === "os").map((u) => u.key),
      });
      saveBlob(new Blob([JSON.stringify(req, null, 2) + "\n"], { type: "application/json" }), `${req.request_id}.json`);
      setExported(req);
      setSelected(new Set());
    } catch (e) {
      setExportErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

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
      {exportErr && <div className="banner banner-error">Acquisition request not exported: {exportErr}</div>}
      {exported && (
        <div className="banner banner-ok">
          Downloaded <Mono>{exported.request_id}.json</Mono> ({exported.apps.length} application{exported.apps.length === 1 ? "" : "s"},{" "}
          {exported.kbs.length} Windows update{exported.kbs.length === 1 ? "" : "s"}). Carry it to the acquisition zone on approved media and put it
          in the <Mono>requests</Mono> directory of <Mono>pmctl auto</Mono>. The packages come back in a signed bundle and wait in the catalog for approval.{" "}
          <button className="btn btn-sm" onClick={() => setExported(null)}>Dismiss</button>
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
          {canRequest && chosen.length > 0 && (
            <div className="bulkbar">
              <b>{chosen.length}</b> selected
              <button className="btn btn-sm btn-primary" disabled={busy} onClick={exportRequest}>
                {busy ? "Exporting…" : "Export acquisition request"}
              </button>
              <button className="btn btn-sm" onClick={() => setSelected(new Set())}>Clear selection</button>
              <span className="muted">downloads a file to carry to the acquisition zone; the server itself never sends anything out</span>
            </div>
          )}
          {rows.length === 0 ? (
            <div className="empty">{(data.updates ?? []).length === 0 ? "The whole fleet is up to date." : "No updates match the filter."}</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  {canRequest && (
                    <th style={{ width: 28 }}>
                      <input type="checkbox" className="rowcheck" checked={allOn} disabled={visibleRequestable.length === 0} onChange={toggleAll}
                             aria-label="Select all updates not imported" title="Select every update shown that is not in the catalog yet" />
                    </th>
                  )}
                  <th>Update</th><th>Latest</th><th>Endpoints</th><th>Catalog</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((u) => (
                  <tr key={rowKey(u)} className={!u.catalog && selected.has(rowKey(u)) ? "selected" : ""}>
                    {canRequest && (
                      <td>
                        {!u.catalog && (
                          <input type="checkbox" className="rowcheck" checked={selected.has(rowKey(u))} onChange={() => toggleOne(u)}
                                 aria-label={`Request ${u.name}`} />
                        )}
                      </td>
                    )}
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
