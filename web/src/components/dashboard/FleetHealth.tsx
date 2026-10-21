import { Link } from "react-router-dom";
import { paths } from "../../paths";
import type { Summary } from "../../types";
import { DashCard, EmptyState, Skeleton, SrOnly, StackedBar, Swatch } from "./charts";
import { endpointsLink, fleetGroups, pctFloor } from "./model";

/** Fleet health: one part-to-whole bar of endpoint statuses; every slice and legend row opens the filtered list. */
export function FleetHealth({ summary, isOperator }: { summary: Summary | null; isOperator: boolean }) {
  if (!summary) {
    return <DashCard title="Fleet health" className="dash-a-fleet"><Skeleton chart="bar" lines={4} /></DashCard>;
  }
  const groups = fleetGroups(summary);
  const total = summary.endpoints.total;
  const segments = groups.map((g) => ({ key: g.key, label: g.label, value: g.count, fill: g.fill, hatch: g.hatch, to: endpointsLink(g.statuses), help: g.help }));
  return (
    <DashCard
      title="Fleet health"
      className="dash-a-fleet"
      sub={<>{total.toLocaleString()} machines{summary.endpoints.retired ? <> · <Link to="/endpoints?status=retired">{summary.endpoints.retired} retired</Link> (not counted)</> : null}</>}
      action={<Link to={paths.endpoints} className="dash-link">All endpoints →</Link>}
    >
      {total === 0 ? (
        <EmptyState title="No machines enrolled yet">
          {isOperator
            ? <><Link to={`${paths.endpoints}?enroll=1`}>Create an enrollment token</Link> and install the agent on the Windows PCs.</>
            : "A User or Admin enrolls the machines."}
        </EmptyState>
      ) : (
        <>
          <StackedBar segments={segments} label={`Endpoint status of ${total} machines. Select a part to open those machines.`} />
          <ul className="dash-legend">
            {groups.map((g) => (
              <li key={g.key} className={g.count === 0 ? "dash-legend-zero" : ""}>
                <Link to={endpointsLink(g.statuses)} title={g.help}>
                  <Swatch fill={g.fill} hatch={g.hatch} />
                  <span className="dash-legend-label">{g.label}</span>
                  <span className="dash-legend-value num">{g.count.toLocaleString()}</span>
                  <span className="dash-legend-pct num">{pctFloor(g.count, total)}%</span>
                </Link>
              </li>
            ))}
          </ul>
          <SrOnly>
            <table>
              <caption>Endpoint status</caption>
              <thead><tr><th>Status</th><th>Machines</th><th>Share</th></tr></thead>
              <tbody>{groups.map((g) => <tr key={g.key}><td>{g.label}</td><td>{g.count}</td><td>{pctFloor(g.count, total)}%</td></tr>)}</tbody>
            </table>
          </SrOnly>
        </>
      )}
    </DashCard>
  );
}
