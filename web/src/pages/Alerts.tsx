import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { paths } from "../paths";
import { useRefreshAlerts } from "../alertsContext";
import { useCan } from "../auth";
import { Empty, ErrorBanner, Mono, PageHeader, ReasonModal, RelTime, Time } from "../components/ui";
import type { Alert } from "../types";
import { useLoad } from "../util";

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
    case "bundle": return paths.transfers;
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

  const rows = [...(data ?? [])].sort((a, b) => {
    const ao = a.acknowledged_at ? 1 : 0;
    const bo = b.acknowledged_at ? 1 : 0;
    return ao - bo || (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || b.created_at.localeCompare(a.created_at);
  });

  return (
    <>
      <PageHeader title="Alerts" sub="Raised inside the isolated zone: failures, auto-pauses, silent endpoints, expiring exceptions · refresh every 15s">
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
            <tr><th>Severity</th><th>Message</th><th>Object</th><th>Created</th><th>Acknowledged</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const link = alertObjectLink(a);
              return (
                <tr key={a.id} className={a.acknowledged_at ? "row-disabled" : ""}>
                  <td><SeverityPill s={a.severity} /></td>
                  <td className="detail-cell">
                    {a.message}
                    {a.kind && <div className="cell-sub"><Mono>{a.kind}</Mono></div>}
                  </td>
                  <td>
                    {a.object_type && <span className="tag">{a.object_type}</span>}
                    {a.object_id && (link ? <Link to={link}><Mono>{a.object_id}</Mono></Link> : <Mono>{a.object_id}</Mono>)}
                    {!a.object_type && !a.object_id && <span className="muted">—</span>}
                  </td>
                  <td className="nowrap"><Time value={a.created_at} hideRel /><div className="cell-sub"><RelTime value={a.created_at} /></div></td>
                  <td className="nowrap">
                    {a.acknowledged_at
                      ? <><RelTime value={a.acknowledged_at} /><div className="cell-sub">{a.acknowledged_by}</div></>
                      : <span className="muted">open</span>}
                  </td>
                  <td className="right">
                    {canAck && !a.acknowledged_at && (
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
