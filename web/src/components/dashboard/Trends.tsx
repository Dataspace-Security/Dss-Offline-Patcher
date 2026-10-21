import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { paths } from "../../paths";
import type { Deployment } from "../../types";
import { Columns, DashCard, EmptyState, LineArea, Skeleton, SrOnly, Swatch, type LinePoint } from "./charts";
import { trendSeries, weeklyDeployments, type FleetTrend } from "./model";

/** "2026-10-21" → "Oct 21" (local calendar day). */
function dayLabel(day: string): string {
  const [y, m, d] = day.split("-").map((x) => parseInt(x, 10));
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function points(days: string[], values: (number | null)[]): LinePoint[] {
  return days.map((d, i) => ({ x: d, label: dayLabel(d), value: values[i] }));
}

/** Change from the first to the last snapshot of the range, as words. */
function delta(values: (number | null)[], unit: string, upIsGood: boolean) {
  const known = values.filter((v): v is number => v !== null);
  if (known.length < 2) return null;
  const d = known[known.length - 1] - known[0];
  if (d === 0) return <span className="muted">no change</span>;
  const good = upIsGood ? d > 0 : d < 0;
  return <span className={good ? "text-green" : "text-red"}>{d > 0 ? "▲" : "▼"} {Math.abs(d).toLocaleString()}{unit}</span>;
}

/** Compliance trend: compliant share and machines with updates available, one chart each, over the last 30 days. */
export function ComplianceTrend({ trend, error, className = "" }: { trend: FleetTrend | null; error: string | null; className?: string }) {
  const card = (body: ReactNode, sub?: ReactNode) => (
    <DashCard title="Compliance trend" className={className} sub={sub ?? "Daily snapshot, last 30 days"}
              action={<Link to={paths.reports} className="dash-link">Reports →</Link>}>{body}</DashCard>
  );
  if (error) return card(<EmptyState title="History is not available">{error}</EmptyState>);
  if (!trend) return card(<Skeleton chart="bar" lines={4} />);
  const s = trendSeries(trend);
  const last = trend.rows[trend.rows.length - 1];
  if (s.points < 2) {
    return card(
      <>
        <EmptyState title="History starts today">
          The server records the fleet once a day; the trend appears from the second day on.
          {last && <> Today: <b className="num">{last.compliant}</b> of <b className="num">{last.endpoints}</b> machines compliant,{" "}
            <b className="num">{last.updates_available}</b> with updates available.</>}
        </EmptyState>
        <div className="dash-trend-grid">
          <TrendPanel title="Compliant machines" fill="--green-solid" unit="%" points={points(s.days, s.compliantPct)} max={100} />
          <TrendPanel title="Machines with updates available" fill="--amber-solid" unit=" machines" points={points(s.days, s.updates)} />
        </div>
      </>,
      `${trend.rows.length} snapshot${trend.rows.length === 1 ? "" : "s"} so far`,
    );
  }
  return card(
    <>
      <div className="dash-trend-grid">
        <TrendPanel title="Compliant machines" fill="--green-solid" unit="%" points={points(s.days, s.compliantPct)} max={100}
                    change={delta(s.compliantPct, " pts", true)} />
        <TrendPanel title="Machines with updates available" fill="--amber-solid" unit=" machines" points={points(s.days, s.updates)}
                    change={delta(s.updates, "", false)} />
      </div>
      <SrOnly>
        <table>
          <caption>Daily fleet snapshots</caption>
          <thead><tr><th>Day</th><th>Machines</th><th>Compliant</th><th>Updates available</th><th>Failed</th><th>Offline or stale</th></tr></thead>
          <tbody>{trend.rows.map((r) => (
            <tr key={r.day}><td>{r.day}</td><td>{r.endpoints}</td><td>{r.compliant}</td><td>{r.updates_available}</td><td>{r.failed}</td><td>{r.offline}</td></tr>
          ))}</tbody>
        </table>
      </SrOnly>
    </>,
  );
}

function TrendPanel({ title, fill, unit, points: pts, max, change }: {
  title: string; fill: string; unit: string; points: LinePoint[]; max?: number; change?: ReactNode;
}) {
  const latest = [...pts].reverse().find((p) => p.value !== null)?.value ?? null;
  const fmt = (v: number) => (unit === "%" ? `${v}%` : v.toLocaleString());
  return (
    <div className="dash-trend">
      <div className="dash-trend-head">
        <span className="dash-trend-title"><Swatch fill={fill} /> {title}</span>
        <span className="dash-trend-now num">{latest === null ? "—" : fmt(latest)} {change && <small>{change}</small>}</span>
      </div>
      <LineArea points={pts} fill={fill} max={max} unit={unit === "%" ? "compliant" : "machines"}
                format={unit === "%" ? (v) => `${v}%` : undefined} label={`${title}, daily over the last ${pts.length} days`} />
    </div>
  );
}

const DEP_PARTS = [
  { key: "completed", label: "Completed", fill: "--green-solid" },
  { key: "failed", label: "Failed or cancelled", fill: "--red-solid" },
] as const;

/** Deployments finished in the last 30 days, per week: completed cleanly vs. with failures or cancelled. */
export function DeploymentHistory({ deployments, className = "" }: { deployments: Deployment[] | null; className?: string }) {
  const weeks = weeklyDeployments(deployments, new Date());
  const done = weeks.reduce((a, w) => a + w.completed, 0);
  const failed = weeks.reduce((a, w) => a + w.failed, 0);
  return (
    <DashCard title="Deployments" className={className} sub="Finished in the last 30 days, by week"
              action={<Link to={paths.deployments} className="dash-link">Deployments →</Link>}>
      {!deployments ? <Skeleton chart="bar" lines={3} /> : (
        <>
          <Columns label={`Deployments per week: ${done} completed, ${failed} failed or cancelled`}
                   buckets={weeks.map((w) => ({
                     key: w.start.toISOString(), label: w.label,
                     parts: DEP_PARTS.map((p) => ({ key: p.key, label: p.label, fill: p.fill, value: p.key === "completed" ? w.completed : w.failed })),
                   }))} />
          <ul className="dash-inline-legend">
            {DEP_PARTS.map((p) => (
              <li key={p.key}><Swatch fill={p.fill} /> {p.label} <b className="num">{(p.key === "completed" ? done : failed).toLocaleString()}</b></li>
            ))}
          </ul>
          {done + failed === 0 && <div className="dash-note">No deployment finished in the last 30 days.</div>}
          <SrOnly>
            <table>
              <caption>Deployments per week</caption>
              <thead><tr><th>Week of</th><th>Completed</th><th>Failed or cancelled</th></tr></thead>
              <tbody>{weeks.map((w) => <tr key={w.label}><td>{w.label}</td><td>{w.completed}</td><td>{w.failed}</td></tr>)}</tbody>
            </table>
          </SrOnly>
        </>
      )}
    </DashCard>
  );
}
