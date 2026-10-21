import { Link } from "react-router-dom";
import { api, qs } from "../api";
import { paths } from "../paths";
import type { FleetStatus, FleetStatusEndpoint, FleetStatusRow } from "../types";
import { useLoad } from "../util";
import { Empty, ErrorBanner, Mono, Pill } from "./ui";
import "../ops.css";

export type FleetEndpointStatus = FleetStatusEndpoint["status"];

/** The per-endpoint states of an update across the fleet (GET /api/fleet/status). */
export const STATUS_COLUMNS: { key: FleetEndpointStatus; label: string; tone: string; pill: string; help: string }[] = [
  { key: "outdated", label: "Outdated", tone: "amber", pill: "noncompliant", help: "Missing and not being patched yet" },
  { key: "failed", label: "Failed", tone: "red", pill: "failed", help: "Install failed or the endpoint was lost after installing" },
  { key: "being_patched", label: "Being patched", tone: "blue", pill: "active", help: "Target in an active or paused deployment" },
  { key: "restart_needed", label: "Restart needed", tone: "amber", pill: "pending_reboot", help: "Installed; the machine has to restart to finish" },
  { key: "verified", label: "Verified", tone: "green", pill: "verified", help: "Installed by a DSS Patcher deployment and confirmed by inventory" },
  { key: "up_to_date", label: "Up to date", tone: "green", pill: "verified", help: "Inventory shows it (or something newer), however it got there" },
  { key: "exception", label: "Exception", tone: "purple", pill: "exception", help: "Risk accepted by an active exception" },
];

const statusOf = (s: FleetEndpointStatus) => STATUS_COLUMNS.find((c) => c.key === s);

export const rowTotal = (r: FleetStatusRow) => STATUS_COLUMNS.reduce((a, c) => a + (r[c.key] ?? 0), 0);

/** Needs action: some endpoint is outdated or failed. */
export const needsAction = (r: FleetStatusRow) => r.outdated > 0 || r.failed > 0;

/** Share of endpoints that are up to date or verified, as an accessible bar. */
export function FleetBar({ r }: { r: FleetStatusRow }) {
  const total = rowTotal(r);
  if (!total) return <span className="muted">—</span>;
  const ok = r.up_to_date + r.verified;
  const pct = Math.floor((ok / total) * 100);
  return (
    <div title={`${ok} of ${total} up to date or verified`}>
      <div className="countbar" role="progressbar" aria-label={`${r.name || r.key}: current`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        {STATUS_COLUMNS.map((c) => r[c.key] > 0 && <span key={c.key} className={`seg seg-${c.tone}`} style={{ width: `${(r[c.key] / total) * 100}%` }} />)}
      </div>
      <div className="cell-sub">{pct}% current</div>
    </div>
  );
}

/** Non-zero state counts as buttons that open the row filtered to that state. */
export function StatusCounts({ r, active, onPick }: { r: FleetStatusRow; active: FleetEndpointStatus | "" | null; onPick: (s: FleetEndpointStatus) => void }) {
  const cols = STATUS_COLUMNS.filter((c) => r[c.key] > 0);
  if (cols.length === 0) return <span className="muted">no endpoint reports it</span>;
  return (
    <span className="fs-counts">
      {cols.map((c) => (
        <button key={c.key} type="button" className={`fs-cell fs-${c.tone} ${active === c.key ? "fs-cell-on" : ""}`}
                title={`${r[c.key]} endpoint(s) ${c.label.toLowerCase()}: ${c.help}`}
                onClick={(e) => { e.stopPropagation(); onPick(c.key); }}>
          {r[c.key]} <span className="fs-cell-label">{c.label.toLowerCase()}</span>
        </button>
      ))}
    </span>
  );
}

/**
 * The endpoints of one update with their status. The list rows usually come
 * without endpoints (on-demand contract): they are then fetched with
 * GET /api/fleet/status?kind=&key= when the row is opened.
 */
export function UpdateEndpoints({ row, status, onStatus }: { row: FleetStatusRow; status: FleetEndpointStatus | ""; onStatus: (s: FleetEndpointStatus | "") => void }) {
  const inline = row.endpoints ?? [];
  const fetchIt = inline.length === 0 && rowTotal(row) > 0;
  const detail = useLoad(
    () => (fetchIt ? api.get<FleetStatus>(`/api/fleet/status${qs({ kind: row.kind, key: row.key })}`) : Promise.resolve(null)),
    [row.kind, row.key, fetchIt]);
  const fetched = detail.data?.rows?.find((r) => r.kind === row.kind && r.key === row.key) ?? detail.data?.rows?.[0];
  const all = fetchIt ? fetched?.endpoints ?? null : inline;
  const eps = (all ?? [])
    .filter((e) => !status || e.status === status)
    .sort((a, b) => a.status.localeCompare(b.status) || a.hostname.localeCompare(b.hostname));

  return (
    <div className="fs-drill">
      <div className="chips">
        <button className={`chip ${status === "" ? "chip-on" : ""}`} onClick={() => onStatus("")}>All <b>{rowTotal(row)}</b></button>
        {STATUS_COLUMNS.filter((c) => row[c.key] > 0).map((c) => (
          <button key={c.key} className={`chip ${status === c.key ? "chip-on" : ""}`} onClick={() => onStatus(c.key)}>
            <Pill state={c.pill} label={c.label} /> <b>{row[c.key]}</b>
          </button>
        ))}
        <span className="spacer" />
        {row.catalog && <Link className="btn btn-sm" to={paths.catalog(row.catalog.package_id)}>Open in catalog →</Link>}
      </div>
      <ErrorBanner error={detail.error ? `Endpoints could not be loaded: ${detail.error}` : null} />
      {detail.error && <button className="btn btn-sm" onClick={() => void detail.reload()}>Retry</button>}
      {all === null && !detail.error && <div className="muted">Loading endpoints…</div>}
      {all !== null && (eps.length === 0 ? <Empty>No endpoints in this state.</Empty> : (
        <table className="table table-compact">
          <thead><tr><th>Hostname</th><th>Status</th><th>Installed</th></tr></thead>
          <tbody>
            {eps.map((e) => (
              <tr key={e.endpoint_id}>
                <td><Link to={paths.endpoint(e.endpoint_id)}>{e.hostname || e.endpoint_id}</Link></td>
                <td><Pill state={statusOf(e.status)?.pill ?? e.status} label={statusOf(e.status)?.label ?? e.status} /></td>
                <td><Mono>{e.installed || "—"}</Mono></td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </div>
  );
}
