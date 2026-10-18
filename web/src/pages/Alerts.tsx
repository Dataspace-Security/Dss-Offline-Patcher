import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { paths } from "../paths";
import { useRefreshAlerts } from "../alertsContext";
import { useCan } from "../auth";
import { Empty, ErrorBanner, Mono, PageHeader, ReasonModal, RelTime, Time } from "../components/ui";
import type { Alert, Endpoint } from "../types";
import { parseTime, useLoad } from "../util";

const HOSTS_SHOWN = 5;

/** Open = not closed by itself (resolved) and not acknowledged by a person. */
export function isOpenAlert(a: Alert): boolean {
  return !parseTime(a.resolved_at) && !a.acknowledged_at;
}

/** Endpoint ids an alert is about (details.endpoint_ids, else its object when that is an endpoint). */
function alertEndpointIds(a: Alert): string[] {
  const ids = Array.isArray(a.details?.endpoint_ids) ? a.details!.endpoint_ids!.filter((x) => typeof x === "string") : [];
  if (ids.length) return ids;
  return a.object_type === "endpoint" && a.object_id ? [a.object_id] : [];
}

/** The machines an alert names, as links to their pages ("+N more" after five). */
function AlertHosts({ a, names }: { a: Alert; names: Map<string, string> }) {
  const ids = alertEndpointIds(a);
  if (ids.length === 0) return null;
  const given = Array.isArray(a.details?.hostnames) ? a.details!.hostnames! : [];
  const name = (id: string, i: number) => names.get(id) || (typeof given[i] === "string" ? given[i] : "") || id;
  return (
    <div className="cell-sub">
      {ids.length === 1 ? "Machine: " : "Machines: "}
      {ids.slice(0, HOSTS_SHOWN).map((id, i) => (
        <span key={id}>{i > 0 && ", "}<Link to={paths.endpoint(id)}>{name(id, i)}</Link></span>
      ))}
      {ids.length > HOSTS_SHOWN && <> +{ids.length - HOSTS_SHOWN} more</>}
    </div>
  );
}

const SEV_ORDER: Record<string, number> = { critical: 0, warning: 1, info: 2 };

export function SeverityPill({ s }: { s: Alert["severity"] | string }) {
  const tone = s === "critical" ? "red" : s === "warning" ? "amber" : s === "info" ? "blue" : "grey";
  return <span className={`pill pill-${tone}`}>{s}</span>;
}

/** Link to the object an alert is about, when the console has a page for it. */
export function alertObjectLink(a: Pick<Alert, "object_type" | "object_id">): string | null {
  if (!a.object_id) return null;
  switch (a.object_type) {
    case "deployment": return paths.deployment(a.object_id);
    case "endpoint": return paths.endpoint(a.object_id);
    case "package": return paths.catalog(a.object_id);
    case "exception": return paths.exceptions;
    case "bundle": return paths.imports;
    default: return null;
  }
}

export default function Alerts() {
  const canAck = useCan("operator");
  const refreshBadge = useRefreshAlerts();
  const [openOnly, setOpenOnly] = useState(true);
  const { data, error, reload } = useLoad(
    () => api.get<Alert[]>(openOnly ? "/api/alerts?open=1" : "/api/alerts"), [openOnly], 15000);
  const [acking, setAcking] = useState<Alert | null>(null);
  const needHosts = (data ?? []).some((a) => alertEndpointIds(a).length > 0);
  const eps = useLoad(() => (needHosts ? api.get<Endpoint[]>("/api/endpoints") : Promise.resolve(null)), [needHosts], 60000);
  const names = new Map((eps.data ?? []).map((e) => [e.endpoint_id, e.hostname] as [string, string]));

  // Alerts that closed by themselves never stay in the open list.
  const rows = [...(data ?? [])].filter((a) => !openOnly || isOpenAlert(a)).sort((a, b) => {
    const ao = isOpenAlert(a) ? 0 : 1;
    const bo = isOpenAlert(b) ? 0 : 1;
    return ao - bo || (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || b.created_at.localeCompare(a.created_at);
  });

  return (
    <>
      <PageHeader title="Alerts" sub="Failures, auto-pauses, silent machines, expiring exceptions. Alerts about a problem that has gone away close by themselves · refresh every 15s">
        <div className="tabs tabs-inline">
          <button className={`tab ${openOnly ? "tab-on" : ""}`} onClick={() => setOpenOnly(true)}>Open</button>
          <button className={`tab ${!openOnly ? "tab-on" : ""}`} onClick={() => setOpenOnly(false)}>All</button>
        </div>
      </PageHeader>
      <ErrorBanner error={error} />
      {data && rows.length === 0 && <Empty>{openOnly ? "No open alerts." : "No alerts recorded."}</Empty>}
      {rows.length > 0 && (
        <table className="table">
          <thead>
            <tr><th>Severity</th><th>Message</th><th>Object</th><th>Created</th><th>Status</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const link = alertObjectLink(a);
              const resolved = parseTime(a.resolved_at);
              return (
                <tr key={a.id} className={isOpenAlert(a) ? "" : "row-disabled"}>
                  <td><SeverityPill s={a.severity} /></td>
                  <td className="detail-cell">
                    {a.message}
                    <AlertHosts a={a} names={names} />
                    {a.kind && <div className="cell-sub"><Mono>{a.kind}</Mono></div>}
                  </td>
                  <td>
                    {a.object_type && <span className="tag">{a.object_type}</span>}
                    {a.object_id && (link ? <Link to={link}><Mono>{a.object_id}</Mono></Link> : <Mono>{a.object_id}</Mono>)}
                    {!a.object_type && !a.object_id && <span className="muted">—</span>}
                  </td>
                  <td className="nowrap"><Time value={a.created_at} hideRel /><div className="cell-sub"><RelTime value={a.created_at} /></div></td>
                  <td className="nowrap">
                    {resolved
                      ? <><span title="The problem went away, so the alert closed itself">closed by itself</span> <RelTime value={a.resolved_at} /></>
                      : a.acknowledged_at
                      ? <>acknowledged <RelTime value={a.acknowledged_at} /><div className="cell-sub">{a.acknowledged_by}</div></>
                      : <span className="muted">open</span>}
                  </td>
                  <td className="right">
                    {canAck && isOpenAlert(a) && (
                      <button className="btn btn-sm" onClick={() => setAcking(a)}>Acknowledge…</button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {acking && (
        <ReasonModal
          title="Acknowledge alert"
          description={<><SeverityPill s={acking.severity} /> {acking.message}</>}
          confirmLabel="Acknowledge"
          onClose={() => setAcking(null)}
          onSubmit={async (reason) => {
            await api.post(`/api/alerts/${acking.id}/ack`, { reason });
            await reload();
            refreshBadge();
          }}
        />
      )}
    </>
  );
}
