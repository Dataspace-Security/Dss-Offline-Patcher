import { Fragment, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, errMsg, saveBlob } from "../api";
import { useCan } from "../auth";
import { RequestedPill } from "../components/AcqRequestStatus";
import { FleetBar, StatusCounts, UpdateEndpoints, needsAction, type FleetEndpointStatus } from "../components/fleetStatusParts";
import { PatchThis } from "../components/PatchThis";
import { PipelineAction } from "../components/PipelineAction";
import { fetchFleet } from "../components/patchPlan";
import { CatalogState, IntelSource } from "../components/UpdatesAvailable";
import { Empty, ErrorBanner, Mono, PageHeader, RelTime, expandRowProps } from "../components/ui";
import { paths } from "../paths";
import type { AcquisitionRequest, FleetStatus, FleetStatusRow, FleetUpdates } from "../types";
import { useLoad } from "../util";
import "../ops.css";

type Kind = "" | "os" | "app";
type View = "action" | "all";
type NeededEndpoint = FleetUpdates["updates"][number]["endpoints"][number];

const POLL_MS = 60000;
const NAMES_SHOWN = 5;
const rowKey = (r: { kind: string; key: string }) => `${r.kind}:${r.key}`;

/**
 * Patches → Updates: every Windows update and application across the fleet
 * in one list (formerly "Needed" and "Status"). Default view: only what needs
 * action (outdated or failed somewhere); "Everything" adds what is up to date.
 * Rows from GET /api/fleet/status; the endpoints of a row are fetched when it
 * is opened. Names of the endpoints that still need an update come from
 * GET /api/updates.
 */
export default function PatchUpdates() {
  const [sp, setSp] = useSearchParams();
  const view: View = sp.get("view") === "all" ? "all" : "action";
  const kind = (["os", "app"].includes(sp.get("kind") ?? "") ? sp.get("kind") : "") as Kind;
  const setParam = (k: string, v: string) => {
    const n = new URLSearchParams(sp);
    if (v) n.set(k, v); else n.delete(k);
    setSp(n, { replace: true });
  };
  const canRequest = useCan("operator");
  const status = useLoad(() => api.get<FleetStatus>("/api/fleet/status"), [], POLL_MS);
  const needed = useLoad(() => api.get<FleetUpdates>("/api/updates"), [], POLL_MS);
  const fleet = useLoad(fetchFleet, [], POLL_MS);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<{ key: string; status: FleetEndpointStatus | "" } | null>(null);
  const [patching, setPatching] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [exportErr, setExportErr] = useState<string | null>(null);
  const [exported, setExported] = useState<AcquisitionRequest | null>(null);

  const allRows = status.data?.rows ?? [];
  const intel = status.data?.intel ?? null;
  // Endpoints that still need each update (names for the list).
  const neededBy = useMemo(() => {
    const m = new Map<string, NeededEndpoint[]>();
    for (const u of needed.data?.updates ?? []) m.set(rowKey(u), u.endpoints ?? []);
    return m;
  }, [needed.data]);
  const namesOf = (r: FleetStatusRow): NeededEndpoint[] => {
    const inline = (r.endpoints ?? []).filter((e) => e.status === "outdated" || e.status === "failed");
    return inline.length ? inline : neededBy.get(rowKey(r)) ?? [];
  };

  const inView = allRows.filter((r) => view === "all" || needsAction(r));
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return inView
      .filter((r) => !kind || r.kind === kind)
      .filter((r) => !needle || `${r.name} ${r.key} ${r.latest}`.toLowerCase().includes(needle)
        || namesOf(r).some((e) => e.hostname.toLowerCase().includes(needle)))
      .sort((a, b) => b.failed - a.failed || b.outdated - a.outdated || a.name.localeCompare(b.name));
  }, [inView, kind, q, neededBy]); // eslint-disable-line react-hooks/exhaustive-deps
  const kindCount = (k: Kind) => inView.filter((r) => !k || r.kind === k).length;
  const actionCount = allRows.filter(needsAction).length;

  // Only updates not in the catalog yet can be requested; the selection
  // follows the current data (an update that disappears drops out).
  const chosen = allRows.filter((r) => !r.catalog && selected.has(rowKey(r)));
  const visibleRequestable = rows.filter((r) => !r.catalog);
  const allOn = visibleRequestable.length > 0 && visibleRequestable.every((r) => selected.has(rowKey(r)));
  const toggleOne = (r: FleetStatusRow) => {
    const n = new Set(selected);
    if (n.has(rowKey(r))) n.delete(rowKey(r)); else n.add(rowKey(r));
    setSelected(n);
  };
  const toggleAll = () => {
    const n = new Set(selected);
    for (const r of visibleRequestable) {
      if (allOn) n.delete(rowKey(r)); else n.add(rowKey(r));
    }
    setSelected(n);
  };
  const toggleOpen = (key: string, s: FleetEndpointStatus | "") =>
    setOpen(open && open.key === key && (s === "" || open.status === s) ? null : { key, status: s });

  const reloadAll = () => { void status.reload(); void needed.reload(); void fleet.reload(); };

  const exportRequest = async () => {
    setBusy(true);
    setExportErr(null);
    try {
      const req = await api.post<AcquisitionRequest>("/api/acquisition-requests", {
        apps: chosen.filter((r) => r.kind === "app").map((r) => r.key),
        kbs: chosen.filter((r) => r.kind === "os").map((r) => r.key),
      });
      saveBlob(new Blob([JSON.stringify(req, null, 2) + "\n"], { type: "application/json" }), `${req.request_id}.json`);
      setExported(req);
      setSelected(new Set());
      reloadAll();
    } catch (e) {
      setExportErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const cols = canRequest ? 6 : 5;

  return (
    <>
      <PageHeader
        title="Updates"
        sub={<>Every Windows update and application across the fleet, imported or not. <b>Up to date</b> = inventory shows it; <b>verified</b> = installed by an offpatch deployment and confirmed.
          {status.loadedAt ? <> · updated <RelTime value={new Date(status.loadedAt).toISOString()} /></> : null}</>}
      >
        <input className="search" placeholder="Filter by update, app, version or host…" value={q} onChange={(e) => setQ(e.target.value)} />
      </PageHeader>
      <ErrorBanner error={status.error} />
      {intel?.error && <div className="banner banner-error">The stored update intelligence cannot be used: {intel.error}. Send a new document from the acquisition zone.</div>}
      {status.data && !intel && (
        <div className="banner banner-info">
          No update intelligence received yet, so only catalog-based status is known. Enable <Mono>"intel": {"{}"}</Mono> in the acquisition config
          (<Mono>/etc/offpatch/acquire.json</Mono>) or run <Mono>pmctl intel -key bundle.key -to &lt;inbox&gt;</Mono> in the acquisition zone.
        </div>
      )}
      {exportErr && <div className="banner banner-error">Acquisition request not exported: {exportErr}</div>}
      {exported && (
        <div className="banner banner-ok">
          Downloaded <Mono>{exported.request_id}.json</Mono> ({exported.apps.length} application{exported.apps.length === 1 ? "" : "s"},{" "}
          {exported.kbs.length} Windows update{exported.kbs.length === 1 ? "" : "s"}). Carry it to the acquisition zone on approved media and put it
          in the <Mono>requests</Mono> directory of <Mono>pmctl auto</Mono>. The packages come back in a signed bundle and wait in the catalog for approval.
          {" "}Track it on <Link to={paths.transfers}>Transfers</Link>.{" "}
          <button className="btn btn-sm" onClick={() => setExported(null)}>Dismiss</button>
        </div>
      )}

      <div className="section-head">
        <div className="chips">
          <button className={`chip ${view === "action" ? "chip-on" : ""}`} onClick={() => setParam("view", "")}
                  title="Outdated or failed on at least one endpoint">Needs action <b>{actionCount}</b></button>
          <button className={`chip ${view === "all" ? "chip-on" : ""}`} onClick={() => setParam("view", "all")}
                  title="Also updates every endpoint already has">Everything <b>{allRows.length}</b></button>
          <span className="muted">·</span>
          {([["", "All"], ["os", "Windows"], ["app", "Apps"]] as [Kind, string][]).map(([k, label]) => (
            <button key={k || "all"} className={`chip ${kind === k ? "chip-on" : ""}`} onClick={() => setParam("kind", k)}>
              {label} <b>{kindCount(k)}</b>
            </button>
          ))}
        </div>
        <IntelSource intel={intel} />
      </div>

      {canRequest && chosen.length > 0 && (
        <div className="bulkbar">
          <b>{chosen.length}</b> selected
          <button className="btn btn-sm btn-primary" disabled={busy} onClick={() => void exportRequest()}>
            {busy ? "Exporting…" : "Export acquisition request"}
          </button>
          <button className="btn btn-sm" onClick={() => setSelected(new Set())}>Clear selection</button>
          <span className="muted">downloads a file to carry to the acquisition zone; the server itself never sends anything out</span>
        </div>
      )}

      {status.data && rows.length === 0 && (
        <Empty>
          {allRows.length === 0
            ? <>Nothing to show yet: endpoints need to report inventory and an intelligence document must be imported. See <Link to={paths.endpoints}>Endpoints</Link>.</>
            : inView.length === 0 ? <>Nothing needs action: the whole fleet is up to date. <button className="btn-link" onClick={() => setParam("view", "all")}>Show everything</button></>
            : "No updates match the filter."}
        </Empty>
      )}
      {rows.length > 0 && (
        <table className="table fs-table">
          <thead>
            <tr>
              {canRequest && (
                <th style={{ width: 28 }}>
                  <input type="checkbox" className="rowcheck" checked={allOn} disabled={visibleRequestable.length === 0} onChange={toggleAll}
                         aria-label="Select all updates not imported" title="Select every update shown that is not in the catalog yet" />
                </th>
              )}
              <th>Update / application</th><th>Endpoints</th><th>Catalog</th><th style={{ width: 120 }}>Fleet</th><th className="right">Next step</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const key = rowKey(r);
              const isOpen = open?.key === key;
              const names = namesOf(r);
              return (
                <Fragment key={key}>
                  <tr {...expandRowProps(isOpen, () => toggleOpen(key, ""), !r.catalog && selected.has(key) ? "selected" : "")}>
                    {canRequest && (
                      <td onClick={(e) => e.stopPropagation()}>
                        {!r.catalog && (
                          <input type="checkbox" className="rowcheck" checked={selected.has(key)} onChange={() => toggleOne(r)} aria-label={`Request ${r.name || r.key}`} />
                        )}
                      </td>
                    )}
                    <td>
                      <span className="caret" aria-hidden="true">{isOpen ? "▾" : "▸"}</span>{" "}
                      <span className="tag">{r.kind === "os" ? "Windows" : "App"}</span> <span className="cell-title">{r.name || r.key}</span>
                      <div className="cell-sub"><Mono>{r.key}</Mono>{r.latest && <> · latest <Mono>{r.latest}</Mono></>}</div>
                    </td>
                    <td>
                      <StatusCounts r={r} active={isOpen ? open?.status ?? "" : null} onPick={(s) => toggleOpen(key, s)} />
                      {names.length > 0 && (
                        <div className="cell-sub fs-names" onClick={(e) => e.stopPropagation()}>
                          needs it:{" "}
                          {names.slice(0, NAMES_SHOWN).map((e, i) => (
                            <span key={e.endpoint_id}>{i > 0 && ", "}<Link to={paths.endpoint(e.endpoint_id)}>{e.hostname}</Link>{r.kind === "app" && e.installed && <> ({e.installed})</>}</span>
                          ))}
                          {names.length > NAMES_SHOWN && <> and {names.length - NAMES_SHOWN} more</>}
                        </div>
                      )}
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div className="fs-catalog">
                        <CatalogState link={r.catalog} />
                        {r.requested && r.catalog && <div><RequestedPill r={r.requested} /></div>}
                      </div>
                    </td>
                    <td><FleetBar r={r} /></td>
                    <td className="right" onClick={(e) => e.stopPropagation()}>
                      {needsAction(r) || r.catalog
                        ? <PipelineAction link={r.catalog} requested={r.requested} fleet={r.catalog ? fleet.data?.[r.catalog.package_id] : undefined}
                                          onPatch={setPatching} selected={selected.has(key)} onSelect={() => toggleOne(r)} />
                        : <span className="muted small">nothing to do</span>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="expand">
                      <td colSpan={cols}>
                        <UpdateEndpoints row={r} status={open?.status ?? ""} onStatus={(s) => setOpen({ key, status: s })} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
      {patching && <PatchThis packageId={patching} onClose={() => setPatching(null)} onChanged={reloadAll} />}
    </>
  );
}
