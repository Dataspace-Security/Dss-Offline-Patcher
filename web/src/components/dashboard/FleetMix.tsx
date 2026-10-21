import { Link } from "react-router-dom";
import { paths } from "../../paths";
import type { Endpoint, FleetStatusRow } from "../../types";
import { DashCard, Donut, EmptyState, HBars, Skeleton, SrOnly, Swatch } from "./charts";
import { osSlices, pctFloor, plural, topOutdatedApps } from "./model";

/**
 * Categorical order for Windows releases (biggest first), checked with the
 * dataviz palette validator; "Other" is always grey. Every slice also has a
 * legend row with its count, so colour is never the only cue.
 */
const OS_FILLS = ["--blue-solid", "--amber-solid", "--purple-solid", "--brand-teal"];
const OTHER_FILL = "--grey-solid";

/** Endpoints by Windows release (from the agents' OS version and build). */
export function WindowsVersions({ endpoints, className = "" }: { endpoints: Endpoint[] | null; className?: string }) {
  const slices = osSlices(endpoints, OS_FILLS.length).map((s, i) => ({
    ...s, fill: s.key === "other" ? OTHER_FILL : OS_FILLS[i] ?? OTHER_FILL,
  }));
  const total = slices.reduce((a, s) => a + s.value, 0);
  return (
    <DashCard title="Windows versions" className={className} sub="Enrolled machines by Windows release"
              action={<Link to={paths.endpoints} className="dash-link">Endpoints →</Link>}>
      {!endpoints ? <Skeleton chart="gauge" lines={2} /> : total === 0 ? <EmptyState title="No machines enrolled yet" /> : (
        <div className="dash-donut-wrap">
          <Donut label={`${total} machines by Windows release`} slices={slices}
                 center={<><b className="num">{total.toLocaleString()}</b><span>{total === 1 ? "machine" : "machines"}</span></>} />
          <ul className="dash-donut-legend">
            {slices.map((s) => (
              <li key={s.key} title={s.builds.filter((b) => b > 0).length ? `Builds ${s.builds.filter((b) => b > 0).join(", ")}` : undefined}>
                <Swatch fill={s.fill} />
                <span className="dash-donut-label">{s.label}</span>
                <b className="num">{s.value.toLocaleString()}</b>
                <span className="muted num">{pctFloor(s.value, total)}%</span>
              </li>
            ))}
          </ul>
          <SrOnly>
            <table>
              <caption>Machines by Windows release</caption>
              <tbody>{slices.map((s) => <tr key={s.key}><td>{s.label}</td><td>{s.value}</td></tr>)}</tbody>
            </table>
          </SrOnly>
        </div>
      )}
    </DashCard>
  );
}

/** Address of Patches → Needed filtered to one application. */
function neededFor(name: string): string {
  return `${paths.needed()}?kind=app&q=${encodeURIComponent(name)}`;
}

/** The ten applications most machines run an outdated version of; each bar opens Patches → Needed for that app. */
export function OutdatedApps({ rows, error, className = "" }: { rows: FleetStatusRow[] | null; error: string | null; className?: string }) {
  const top = topOutdatedApps(rows, 10);
  return (
    <DashCard title="Most outdated applications" className={className} sub="Machines running an older version than the latest known"
              action={<Link to={`${paths.needed()}?kind=app`} className="dash-link">Applications →</Link>}>
      {error ? <EmptyState title="Application status is not available">{error}</EmptyState>
        : !rows ? <Skeleton lines={6} />
          : top.length === 0 ? (
            <EmptyState title="No outdated application known">
              Applications show here once the update information from the acquisition zone says a newer version exists.
            </EmptyState>
          ) : (
            <HBars wide label="Machines with an outdated version, per application" unit="machines"
                   bars={top.map((a) => ({
                     key: a.key, value: a.outdated, fill: "--purple-solid",
                     label: <Link to={neededFor(a.name)} title={`${a.name}: ${plural(a.outdated, "machine")} of ${a.seen} behind${a.latest ? `, latest ${a.latest}` : ""}${a.failed ? `, ${a.failed} failed` : ""}`}>{a.name}</Link>,
                   }))} />
          )}
    </DashCard>
  );
}
