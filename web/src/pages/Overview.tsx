import { Link } from "react-router-dom";
import { api } from "../api";
import { paths } from "../paths";
import { ErrorBanner, Meter, PageHeader, Pill, RelTime, STATUS_HELP, pillTone, scoreTone, stateLabel } from "../components/ui";
import { YourWork } from "../components/YourWork";
import { fetchFleet } from "../components/patchPlan";
import type { Alert, Endpoint, PackageFleet, Summary } from "../types";
import { isOpenAlert } from "./Alerts";
import { useLoad } from "../util";

const ENDPOINT_STATUSES = [
  "lost_after_install", "offline", "stale", "failed", "out_of_support", "pending_reboot", "exception", "noncompliant",
  "updates_available", "awaiting_checkin", "compliant",
] as const;
const PACKAGE_STATES = ["quarantined", "approved", "rejected", "revoked"] as const;
const BUNDLE_STATES = ["received", "validated", "rejected"] as const;
const DEPLOYMENT_STATES = ["active", "paused", "completed", "cancelled"] as const;

function n(r: Record<string, number> | undefined, k: string): number {
  return r?.[k] ?? 0;
}

export default function Overview() {
  const { data: s, error, loadedAt } = useLoad(() => api.get<Summary>("/api/summary"), [], 10000);
  const alerts = useLoad(() => api.get<Alert[]>("/api/alerts?open=1").then((l) => (l ?? []).filter(isOpenAlert)), [], 15000);
  const eps = useLoad(() => api.get<Endpoint[]>("/api/endpoints"), [], 30000);
  const needs = useLoad(fetchFleet, [], 60000);
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
            <Link to={paths.alerts} className={`alert-strip ${openCritical ? "alert-strip-critical" : openWarning ? "alert-strip-warning" : "alert-strip-ok"}`}>
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

          <YourWork summary={s} endpoints={eps.data} />

          <section className="section">
            <h2>Endpoints <span className="muted">· {s.endpoints.total} total{s.endpoints.retired ? <> · <Link to="/endpoints?status=retired">{s.endpoints.retired} retired</Link> (excluded)</> : null}</span></h2>
            <div className="tiles">
              {(() => {
                // Fleet score: endpoints with no open deployment problem
                // (compliant) out of all non-retired endpoints. Offline/stale
                // count against it. It does NOT mean "has every update".
                const total = s.endpoints.total;
                const pct = total ? Math.floor((n(by, "compliant") / total) * 100) : 0;
                const tone = scoreTone(pct);
                return (
                  <Link to={paths.reports} className={`tile tile-wide tile-score tile-${tone}`} title="Compliant = checking in, no failed, pending or overdue deployment target and no known missing update. Machines with updates available, on Windows that is no longer updated, or waiting for their first check-in are not compliant. Compliant ÷ all endpoints; offline and stale count against it.">
                    <div className={`tile-value text-${tone}`}>{total ? `${pct}%` : "—"}</div>
                    <div className="tile-label">no open deployment problem · {n(by, "compliant")} of {total} compliant</div>
                    <Meter pct={pct} tone={tone} label="Endpoints with no open deployment problem" />
                  </Link>
                );
              })()}
              <UpToDateTile endpoints={eps.data} needs={needs.data} />
              {ENDPOINT_STATUSES.map((k) => {
                const v = n(by, k);
                const prominent = (k === "offline" || k === "stale") && v > 0;
                return (
                  <Link key={k} to={`/endpoints?status=${k}`} className={`tile tile-${pillTone(k)} ${prominent ? "tile-alert" : ""}`} title={STATUS_HELP[k]}>
                    <div className="tile-value">{v}</div>
                    <div className="tile-label">{stateLabel(k).toLowerCase()}</div>
                  </Link>
                );
              })}
            </div>
          </section>

          <div className="grid-3">
            <section className="section">
              <h2>Packages</h2>
              <StateList record={s.packages} keys={PACKAGE_STATES} link={(k) => `${paths.catalog()}?state=${k}`} />
            </section>
            <section className="section">
              <h2>Bundles</h2>
              <StateList record={s.bundles} keys={BUNDLE_STATES} link={() => paths.imports} />
            </section>
            <section className="section">
              <h2>Deployments</h2>
              <StateList record={s.deployments} keys={DEPLOYMENT_STATES} link={() => "/deployments"} />
            </section>
          </div>

          <div className="grid-2">
            <Link to={paths.exceptions} className="tile tile-purple tile-wide">
              <div className="tile-value">{s.active_exceptions}</div>
              <div className="tile-label">active exceptions</div>
            </Link>
            <Link to={paths.audit()} className={`tile tile-wide ${s.audit.ok ? "tile-green" : "tile-red tile-alert"}`}>
              <div className="tile-value">{s.audit.ok ? "OK" : "BROKEN"}</div>
              <div className="tile-label">audit chain · {s.audit.count} events</div>
            </Link>
          </div>
        </>
      )}
    </>
  );
}

/**
 * P1.1 honest status: endpoints whose inventory shows nothing missing
 * (Windows updates + applications), from Endpoint.missing. Endpoints without
 * update intelligence are not counted as up to date, nor are machines that
 * still need a catalog package (approved or awaiting approval).
 */
function UpToDateTile({ endpoints, needs }: { endpoints: Endpoint[] | null; needs: Record<string, PackageFleet> | null }) {
  if (!endpoints) {
    return <div className="tile tile-wide tile-grey"><div className="tile-value">…</div><div className="tile-label">fully up to date</div></div>;
  }
  const active = endpoints.filter((e) => e.status !== "retired");
  const known = active.filter((e) => e.missing);
  const needsPackage = new Set(Object.values(needs ?? {}).flatMap((f) => (f.needed > 0 ? f.endpoint_ids ?? [] : [])));
  const upToDate = known.filter((e) => e.missing && e.missing.os + e.missing.apps === 0 && !(e.missing.ready > 0)
    && !needsPackage.has(e.endpoint_id)).length;
  const unknown = active.length - known.length;
  const pct = active.length ? Math.floor((upToDate / active.length) * 100) : 0;
  const tone = scoreTone(pct);
  return (
    <Link to="/endpoints?outdated=1" className={`tile tile-wide tile-score tile-${tone}`}
          title="Up to date = no missing Windows update, no outdated application and no catalog package still needed. Machines without update information count against it.">
      <div className={`tile-value text-${tone}`}>{active.length ? `${pct}%` : "—"}</div>
      <div className="tile-label">fully up to date · {upToDate} of {active.length}{unknown ? ` · ${unknown} unknown` : ""}</div>
      <Meter pct={pct} tone={tone} label="Endpoints fully up to date" />
    </Link>
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
