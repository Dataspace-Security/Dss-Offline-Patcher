import { Fragment, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useCan } from "../auth";
import { RequestedPill } from "../components/AcqRequestStatus";
import { FleetBar, StatusCounts, UpdateEndpoints, needsAction, type FleetEndpointStatus } from "../components/fleetStatusParts";
import { PatchThis } from "../components/PatchThis";
import { CantImport, PipelineAction, isRequestable } from "../components/PipelineAction";
import { cantImportReason, importInfoOf, useLibraryImportability, type ImportInfo } from "../components/importability";
import { RequestResultBanner } from "../components/RequestResultBanner";
import { useImportRequest } from "../components/useImportRequest";
import { fetchFleet } from "../components/patchPlan";
import { CatalogState, IntelSource } from "../components/UpdatesAvailable";
import { IntelStaleBanner } from "../components/IntelStaleBanner";
import { Empty, ErrorBanner, Mono, PageHeader, RelTime, expandRowProps } from "../components/ui";
import { paths } from "../paths";
import type { FleetStatus, FleetStatusRow, FleetUpdates } from "../types";
import { useLoad } from "../util";
import "../ops.css";

type Kind = "" | "os" | "app";
type View = "action" | "all";
type NeededEndpoint = FleetUpdates["updates"][number]["endpoints"][number];

const POLL_MS = 60000;
const NAMES_SHOWN = 5;
const rowKey = (r: { kind: string; key: string }) => `${r.kind}:${r.key.toLowerCase()}`;
const BULK = "__bulk__";

/** "build 26200" / "builds 22631, 26200" / "their build". */
function buildsText(builds: number[] | undefined): string {
  if (!builds?.length) return "their build";
  return `build${builds.length === 1 ? "" : "s"} ${builds.join(", ")}`;
}

/** The catalog package covers only some of the Windows builds that need this KB. */
function UncoveredNote({ r }: { r: FleetStatusRow }) {
  const n = r.uncovered ?? 0;
  return (
    <div className="small text-amber" title="Windows releases such as 24H2 and 25H2 share KB numbers but need different packages">
      {n} machine{n === 1 ? "" : "s"} on {buildsText(r.uncovered_builds)} can't use this package: import the update for {n === 1 ? "its" : "their"} build
    </div>
  );
}

/** One endpoint per endpoint_id (an app with two Apps & features entries reports the machine twice). */
function uniqueEndpoints<T extends { endpoint_id: string }>(list: T[]): T[] {
  const seen = new Set<string>();
  return list.filter((e) => (seen.has(e.endpoint_id) ? false : (seen.add(e.endpoint_id), true)));
}

/**
 * One row per update: rows for the same app id (or KB) and version are
 * merged, counts added and machines listed once.
 */
function groupRows(rows: FleetStatusRow[]): FleetStatusRow[] {
  const by = new Map<string, FleetStatusRow>();
  for (const r of rows) {
    const k = `${rowKey(r)}@${r.latest}`;
    const prev = by.get(k);
    if (!prev) { by.set(k, r); continue; }
    by.set(k, {
      ...prev,
      name: prev.name || r.name,
      catalog: prev.catalog ?? r.catalog,
      requested: !prev.requested ? r.requested : !r.requested ? prev.requested : prev.requested.at >= r.requested.at ? prev.requested : r.requested,
      importable: prev.importable ?? r.importable, importable_reason: prev.importable_reason ?? r.importable_reason,
      uncovered: (prev.uncovered ?? 0) + (r.uncovered ?? 0),
      uncovered_builds: Array.from(new Set([...(prev.uncovered_builds ?? []), ...(r.uncovered_builds ?? [])])).sort(),
      up_to_date: prev.up_to_date + r.up_to_date, outdated: prev.outdated + r.outdated, being_patched: prev.being_patched + r.being_patched,
      verified: prev.verified + r.verified, failed: prev.failed + r.failed, exception: prev.exception + r.exception,
      endpoints: uniqueEndpoints([...(prev.endpoints ?? []), ...(r.endpoints ?? [])]),
    });
  }
  return [...by.values()];
}

/**
 * Patches → Needed: every Windows update and application across the fleet
 * in one list. Default view: only what needs
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
  const canRequest = useCan("user");
  // The Library is the vendor's (super admin) tool.
  const isSuper = useCan("super_admin");
  const status = useLoad(() => api.get<FleetStatus>("/api/fleet/status"), [], POLL_MS);
  const needed = useLoad(() => api.get<FleetUpdates>("/api/updates"), [], POLL_MS);
  const fleet = useLoad(fetchFleet, [], POLL_MS);
  // ?q= pre-fills the search (links from the Overview charts).
  const [q, setQ] = useState(() => sp.get("q") ?? "");
  const [open, setOpen] = useState<{ key: string; status: FleetEndpointStatus | "" } | null>(null);
  const [patching, setPatching] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const allRows = useMemo(() => groupRows(status.data?.rows ?? []), [status.data]);
  // What the Library knows about importing each app (super admin; others rely on the row fields).
  const library = useLibraryImportability(isSuper);
  const infoOf = (r: FleetStatusRow): ImportInfo => importInfoOf(r, library);
  // A Windows row whose package covers only some builds stays importable for the others.
  const requestable = (r: FleetStatusRow) => isRequestable(r.catalog, r.requested, infoOf(r))
    || (r.kind === "os" && (r.uncovered ?? 0) > 0 && cantImportReason(infoOf(r), r.requested) === null);
  const intel = status.data?.intel ?? null;
  // Endpoints that still need each update (names for the list).
  const neededBy = useMemo(() => {
    const m = new Map<string, NeededEndpoint[]>();
    for (const u of needed.data?.updates ?? []) m.set(rowKey(u), uniqueEndpoints([...(m.get(rowKey(u)) ?? []), ...(u.endpoints ?? [])]));
    return m;
  }, [needed.data]);
  const namesOf = (r: FleetStatusRow): NeededEndpoint[] => {
    const inline = uniqueEndpoints((r.endpoints ?? []).filter((e) => e.status === "outdated" || e.status === "failed"));
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

  // Updates not in the catalog yet (or whose package was rejected) can
  // be imported, unless the Library says they cannot; the selection follows the current data.
  const chosen = allRows.filter((r) => requestable(r) && selected.has(rowKey(r)));
  const visibleRequestable = rows.filter(requestable);
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
  const imp = useImportRequest(reloadAll);
  const busy = imp.busy; // row key, BULK, or null

  // Import = one acquisition request for the given rows.
  const sendRequest = async (items: FleetStatusRow[], busyKey: string) => {
    const req = await imp.send({
      apps: items.filter((r) => r.kind === "app").map((r) => r.key),
      kbs: items.filter((r) => r.kind === "os").map((r) => r.key),
    }, busyKey);
    if (!req) return;
    const sent = new Set(items.map(rowKey));
    setSelected((cur) => new Set([...cur].filter((k) => !sent.has(k))));
  };

  const cols = canRequest ? 6 : 5;

  return (
    <>
      <PageHeader
        title="Needed"
        sub={<>Updates for the Windows versions and applications on your machines, imported or not.{" "}
          {isSuper ? <>To add software no machine has yet, use the <Link to={paths.library()}>Library</Link>.</> : "Software no machine has yet is added by the vendor."}{" "}
          <b>Up to date</b> = inventory shows it; <b>verified</b> = installed by a DSS Patcher deployment and confirmed.
          {status.loadedAt ? <> · updated <RelTime value={new Date(status.loadedAt).toISOString()} /></> : null}</>}
      >
        <input className="search" placeholder="Filter by update, app, version or host…" value={q} onChange={(e) => setQ(e.target.value)} />
      </PageHeader>
      <ErrorBanner error={status.error} />
      <IntelStaleBanner />
      {intel?.error && <div className="banner banner-error">The stored update intelligence cannot be used: {intel.error}. Ask the acquisition team to send a new one.</div>}
      {status.data && !intel && (
        <div className="banner banner-info">
          No update intelligence received yet, so only catalog-based status is known. Ask the acquisition team to send update intelligence;
          it arrives through the transfer like any bundle.
        </div>
      )}
      {imp.error && <div className="banner banner-error">Import failed: {imp.error}</div>}
      {imp.result && <RequestResultBanner req={imp.result} onDismiss={imp.dismiss} />}

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
          <button className="btn btn-sm btn-primary" disabled={busy !== null} onClick={() => void sendRequest(chosen, BULK)}>
            {busy === BULK ? "Sending…" : `Import selected (${chosen.length})`}
          </button>
          <button className="btn btn-sm" onClick={() => setSelected(new Set())}>Clear selection</button>
          <span className="muted">one acquisition request for all of them</span>
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
                         aria-label="Select all importable updates" title="Select every update shown that can be imported (not in the catalog yet, or rejected); updates that can't be imported are left out" />
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
                  <tr {...expandRowProps(isOpen, () => toggleOpen(key, ""), requestable(r) && selected.has(key) ? "selected" : "")}>
                    {canRequest && (
                      <td onClick={(e) => e.stopPropagation()}>
                        {requestable(r) && (
                          <input type="checkbox" className="rowcheck" checked={selected.has(key)} onChange={() => toggleOne(r)} aria-label={`Import ${r.name || r.key}`} />
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
                        {r.catalog && (r.uncovered ?? 0) > 0 && <UncoveredNote r={r} />}
                      </div>
                    </td>
                    <td><FleetBar r={r} /></td>
                    <td className="right" onClick={(e) => e.stopPropagation()}>
                      {r.catalog && r.kind === "os" && (r.uncovered ?? 0) > 0 && requestable(r) && (
                        <button type="button" className="btn btn-sm" disabled={busy !== null} onClick={() => void sendRequest([r], key)}
                                title="Import the update for the Windows builds the catalog package does not cover">
                          {busy === key ? "Sending…" : `Import for ${buildsText(r.uncovered_builds)}`}
                        </button>
                      )}{" "}
                      {needsAction(r) || r.catalog
                        ? <PipelineAction link={r.catalog} requested={r.requested} fleet={r.catalog ? fleet.data?.[r.catalog.package_id] : undefined}
                                          onPatch={setPatching} importInfo={infoOf(r)}
                                          onRequest={requestable(r) ? () => void sendRequest([r], key) : undefined}
                                          requesting={busy === key} disabled={busy !== null} />
                        : !r.catalog && cantImportReason(infoOf(r), r.requested) !== null
                        ? <CantImport reason={cantImportReason(infoOf(r), r.requested)!} />
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
