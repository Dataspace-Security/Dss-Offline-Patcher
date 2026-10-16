import { Link } from "react-router-dom";
import { api } from "../api";
import { ErrorBanner, PageHeader, Pill, RelTime, pillTone, scoreTone } from "../components/ui";
import type { Alert, Summary } from "../types";
import { useLoad } from "../util";

const ENDPOINT_STATUSES = ["offline", "stale", "failed", "pending_reboot", "exception", "noncompliant", "compliant"] as const;
const PACKAGE_STATES = ["quarantined", "approved", "rejected", "revoked"] as const;
const BUNDLE_STATES = ["received", "validated", "rejected"] as const;
const DEPLOYMENT_STATES = ["active", "paused", "completed", "cancelled"] as const;

function n(r: Record<string, number> | undefined, k: string): number {
  return r?.[k] ?? 0;
}

export default function Overview() {
  const { data: s, error, loadedAt } = useLoad(() => api.get<Summary>("/api/summary"), [], 10000);
  const alerts = useLoad(() => api.get<Alert[]>("/api/alerts?open=1"), [], 15000);
  const openCritical = (alerts.data ?? []).filter((a) => a.severity === "critical").length;
  const openWarning = (alerts.data ?? []).filter((a) => a.severity === "warning").length;

  const by = s?.endpoints.by_status as Record<string, number> | undefined;
  const silent = n(by, "offline") + n(by, "stale");

  return (
    <>
      <PageHeader title="Overview" sub={loadedAt ? <>Auto-refresh every 10s · updated <RelTime value={new Date(loadedAt).toISOString()} /></> : "Loading…"} />
      <ErrorBanner error={error} />
      {s && (
        <>
          {alerts.data && (
            <Link to="/alerts" className={`alert-strip ${openCritical ? "alert-strip-critical" : openWarning ? "alert-strip-warning" : "alert-strip-ok"}`}>
              <span className="alert-strip-label">Open alerts</span>
              <span className="alert-strip-count"><span className="pill pill-red">critical</span> <b>{openCritical}</b></span>
              <span className="alert-strip-count"><span className="pill pill-amber">warning</span> <b>{openWarning}</b></span>
              {alerts.data.length - openCritical - openWarning > 0 && (
                <span className="alert-strip-count"><span className="pill pill-blue">info</span> <b>{alerts.data.length - openCritical - openWarning}</b></span>
              )}
              <span className="spacer" />
              <span className="alert-strip-go">{alerts.data.length ? "Review alerts →" : "No open alerts"}</span>
            </Link>
          )}
          {silent > 0 && (
            <div className="banner banner-warn">
              <b>{silent}</b> endpoint{silent === 1 ? " is" : "s are"} silent ({n(by, "offline")} offline, {n(by, "stale")} stale).
              Silence is never compliance — these endpoints are not counted as compliant.{" "}
              <Link to="/endpoints?status=offline,stale">Review</Link>
            </div>
          )}

          <section className="section">
            <h2>Endpoints <span className="muted">· {s.endpoints.total} total{s.endpoints.retired ? <> · <Link to="/endpoints?status=retired">{s.endpoints.retired} retired</Link> (excluded)</> : null}</span></h2>
            <div className="tiles">
              {(() => {
                // Fleet score: endpoints fully patched (compliant) out of all
                // non-retired endpoints. Offline/stale count against it.
                const total = s.endpoints.total;
                const pct = total ? Math.floor((n(by, "compliant") / total) * 100) : 0;
                const tone = scoreTone(pct);
                return (
                  <Link to="/reports" className={`tile tile-wide tile-score tile-${tone}`} title="Compliant endpoints ÷ all endpoints (offline and stale count as not compliant)">
                    <div className={`tile-value text-${tone}`}>{total ? `${pct}%` : "—"}</div>
                    <div className="tile-label">fleet patch score · {n(by, "compliant")} of {total} compliant</div>
                    <div className="score-meter"><span className={`bg-${tone}`} style={{ width: `${pct}%` }} /></div>
                  </Link>
                );
              })()}
              {ENDPOINT_STATUSES.map((k) => {
                const v = n(by, k);
                const prominent = (k === "offline" || k === "stale") && v > 0;
                return (
                  <Link key={k} to={`/endpoints?status=${k}`} className={`tile tile-${pillTone(k)} ${prominent ? "tile-alert" : ""}`}>
                    <div className="tile-value">{v}</div>
                    <div className="tile-label">{k.replace(/_/g, " ")}</div>
                  </Link>
                );
              })}
            </div>
          </section>

          <div className="grid-3">
            <section className="section">
              <h2>Packages</h2>
              <StateList record={s.packages} keys={PACKAGE_STATES} link={(k) => `/catalog?state=${k}`} />
            </section>
            <section className="section">
              <h2>Bundles</h2>
              <StateList record={s.bundles} keys={BUNDLE_STATES} link={() => "/intake"} />
            </section>
            <section className="section">
              <h2>Deployments</h2>
              <StateList record={s.deployments} keys={DEPLOYMENT_STATES} link={() => "/deployments"} />
            </section>
          </div>

          <div className="grid-2">
            <Link to="/exceptions" className="tile tile-purple tile-wide">
              <div className="tile-value">{s.active_exceptions}</div>
              <div className="tile-label">active exceptions</div>
            </Link>
            <Link to="/audit" className={`tile tile-wide ${s.audit.ok ? "tile-green" : "tile-red tile-alert"}`}>
              <div className="tile-value">{s.audit.ok ? "OK" : "BROKEN"}</div>
              <div className="tile-label">audit chain · {s.audit.count} events</div>
            </Link>
          </div>
        </>
      )}
    </>
  );
}

function StateList({ record, keys, link }: {
  record: Record<string, number> | undefined; keys: readonly string[]; link: (k: string) => string;
}) {
  const extra = Object.keys(record ?? {}).filter((k) => !keys.includes(k));
  return (
    <table className="table table-compact">
      <tbody>
        {[...keys, ...extra].map((k) => (
          <tr key={k}>
            <td><Link to={link(k)}><Pill state={k} /></Link></td>
            <td className="num"><b>{n(record, k)}</b></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
