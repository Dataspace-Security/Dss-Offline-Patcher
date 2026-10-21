import { Link } from "react-router-dom";
import { paths } from "../../paths";
import type { Alert, Endpoint, PackageFleet, Summary } from "../../types";
import { RadialGauge, Skeleton } from "./charts";
import { complianceScore, plural, scoreTone, upToDate } from "./model";

type Props = {
  summary: Summary | null;
  endpoints: Endpoint[] | null;
  needs: Record<string, PackageFleet> | null;
  alerts: Alert[] | null;
};

const SILENT = ["offline", "stale"];

/** Hero row: compliance gauge, fully-up-to-date share, machines needing attention, open critical alerts. */
export function HeroRow({ summary, endpoints, needs, alerts }: Props) {
  return (
    <div className="dash-hero">
      <ComplianceTile summary={summary} endpoints={endpoints} needs={needs} />
      <UpToDateTile endpoints={endpoints} needs={needs} />
      <AttentionTile summary={summary} />
      <CriticalAlertsTile alerts={alerts} />
    </div>
  );
}

function ComplianceTile({ summary, endpoints, needs }: {
  summary: Summary | null; endpoints: Endpoint[] | null; needs: Record<string, PackageFleet> | null;
}) {
  if (!summary) return <div className="dash-tile dash-tile-gauge"><Skeleton chart="gauge" lines={2} /></div>;
  const s = complianceScore(summary);
  const noInfo = endpoints ? upToDate(endpoints, needs).unknown : 0;
  const by = summary.endpoints.by_status as Record<string, number>;
  const silent = SILENT.reduce((a, k) => a + (by?.[k] ?? 0), 0);
  const waiting = by?.awaiting_checkin ?? 0;
  const tone = s.total ? scoreTone(s.pct) : "grey";
  return (
    <Link to={paths.reports} className="dash-tile dash-tile-gauge dash-tile-link"
          title="Compliant = checking in, no known missing update and no deployment problem. Offline, stale and machines waiting for their first check-in are not counted as compliant.">
      <div className="dash-tile-label">Patch compliance</div>
      <div className="dash-tile-caption">Machines with no known missing patch and no failed install</div>
      <RadialGauge pct={s.total ? s.pct : null} tone={tone} label="Patch compliance"
                   caption={<span className="num">{s.compliant.toLocaleString()} of {s.total.toLocaleString()}</span>} />
      <div className="dash-tile-foot">
        {s.total === 0
          ? "No endpoints enrolled yet."
          : silent + waiting > 0
            ? <>{plural(silent + waiting, "machine")} not reporting {silent + waiting === 1 ? "counts" : "count"} against the score.</>
            : "Every machine is reporting."}
        {s.total > 0 && noInfo > 0 && (
          <div className="dash-tile-note">{plural(noInfo, "machine")} without update information yet: judged on deployments only.</div>
        )}
      </div>
    </Link>
  );
}

function UpToDateTile({ endpoints, needs }: { endpoints: Endpoint[] | null; needs: Record<string, PackageFleet> | null }) {
  if (!endpoints) return <div className="dash-tile"><Skeleton lines={3} /></div>;
  const u = upToDate(endpoints, needs);
  const tone = u.pct === null ? "grey" : scoreTone(u.pct);
  return (
    <Link to="/endpoints?outdated=1" className={`dash-tile dash-tile-link dash-tone-${tone}`}
          title="Fully up to date = Windows and every application at the latest version the update information knows, and no catalog package still needed. Machines without update information are left out, not counted as behind.">
      <div className="dash-tile-label">Fully up to date</div>
      <div className="dash-tile-caption">Windows and all applications at the latest known version</div>
      <div className="dash-stat-value">{u.pct === null ? "—" : `${u.pct}%`}</div>
      {u.pct !== null && (
        <div className="dash-meter" role="img" aria-label={`${u.ok} of ${u.known} machines with update information fully up to date`}>
          <span className="dash-meter-fill" style={{ width: `${u.pct}%` }} />
        </div>
      )}
      <div className="dash-tile-foot">
        {u.total === 0 ? "No endpoints enrolled yet."
          : u.known === 0 ? <>No update information yet for any machine. It arrives with the transfer from the acquisition zone.</>
            : <>
              <span className="num">{u.ok.toLocaleString()}</span> of <span className="num">{u.known.toLocaleString()}</span> machines with update information
              {u.unknown > 0 && <> · <span className="num">{u.unknown}</span> not checked yet</>}
            </>}
      </div>
    </Link>
  );
}

function AttentionTile({ summary }: { summary: Summary | null }) {
  if (!summary) return <div className="dash-tile"><Skeleton lines={3} /></div>;
  const by = summary.endpoints.by_status as Record<string, number>;
  const v = (k: string) => by?.[k] ?? 0;
  const failed = v("failed") + v("lost_after_install");
  const silent = v("offline") + v("stale");
  const restart = v("pending_reboot");
  const unsupported = v("out_of_support");
  const total = summary.endpoints.total - v("compliant") - v("exception");
  const tone = total === 0 ? "green" : failed + silent > 0 ? "red" : "amber";
  const parts = [
    failed && `${failed} failed`, silent && `${silent} silent`, restart && `${restart} need a restart`,
    unsupported && `${unsupported} on old Windows`,
  ].filter(Boolean) as string[];
  const notCompliant = ["failed", "lost_after_install", "offline", "stale", "pending_reboot", "out_of_support",
    "updates_available", "noncompliant", "awaiting_checkin"];
  return (
    <Link to={`/endpoints?status=${notCompliant.join(",")}`} className={`dash-tile dash-tile-link dash-tone-${tone}`}
          title="Every enrolled machine that is not compliant and not covered by an exception.">
      <div className="dash-tile-label">Machines needing attention</div>
      <div className="dash-stat-value">{total.toLocaleString()}</div>
      <div className="dash-tile-foot">{total === 0 ? "Nothing needs attention." : parts.length ? parts.join(" · ") : "Updates are missing."}</div>
    </Link>
  );
}

function CriticalAlertsTile({ alerts }: { alerts: Alert[] | null }) {
  if (!alerts) return <div className="dash-tile"><Skeleton lines={3} /></div>;
  const critical = alerts.filter((a) => a.severity === "critical");
  const warning = alerts.filter((a) => a.severity === "warning").length;
  const unacked = critical.filter((a) => !a.acknowledged_at).length;
  const tone = critical.length ? "red" : warning ? "amber" : "green";
  return (
    <Link to={paths.alerts} className={`dash-tile dash-tile-link dash-tone-${tone}`}>
      <div className="dash-tile-label">Open critical alerts</div>
      <div className="dash-stat-value">{critical.length.toLocaleString()}</div>
      <div className="dash-tile-foot">
        {critical.length === 0 && warning === 0 && "No open alerts."}
        {critical.length > 0 && <>{unacked} not acknowledged</>}
        {critical.length > 0 && warning > 0 && " · "}
        {warning > 0 && <>{plural(warning, "warning")}</>}
        {critical[0] && <div className="dash-tile-quote" title={critical[0].message}>{critical[0].message}</div>}
      </div>
    </Link>
  );
}
