import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, enc } from "../api";
import { hasRole, useMe } from "../auth";
import { paths } from "../paths";
import type { ComplianceReport, Deployment, DeploymentDetail, Endpoint, Package, PackageFleet, Summary } from "../types";
import { useLoad } from "../util";
import { exhaustedInCurrentRing, isLiveDeployment, readyToAdvance } from "./rollout";
import { approvedBy } from "./patchPlan";
import { usePageVisible } from "./usePageVisible";
import "../ops.css";

const POLL_MS = 30000;
const MAX_DETAILS = 20; // live deployments inspected for stage / failure state

type Item = { key: string; count: number; label: ReactNode; to: string; tone: "red" | "amber" | "blue" | "green" | "grey"; detail?: ReactNode };

/** P2.5: what is waiting on the signed-in user, by role, from existing APIs. */
export function YourWork({ summary, endpoints }: { summary: Summary; endpoints: Endpoint[] | null }) {
  const me = useMe();
  const isApprover = hasRole(me, "approver");
  const isOperator = hasRole(me, "operator");
  // No polling while the tab is hidden; becoming visible again reloads at once.
  const visible = usePageVisible();
  const poll = visible ? POLL_MS : undefined;

  const quarantined = useLoad(() => (isApprover ? api.get<Package[]>("/api/packages?state=quarantined") : Promise.resolve(null)), [isApprover, visible], poll);
  const approved = useLoad(() => (isOperator ? api.get<Package[]>("/api/packages?state=approved") : Promise.resolve(null)), [isOperator, visible], poll);
  const needs = useLoad(() => (isOperator ? api.get<Record<string, PackageFleet>>("/api/packages-needs") : Promise.resolve(null)), [isOperator, visible], poll);
  const live = useLoad(async () => {
    if (!isOperator) return null;
    const list = await api.get<Deployment[]>("/api/deployments");
    const liveList = list.filter(isLiveDeployment);
    const ids = liveList.slice(0, MAX_DETAILS).map((d) => d.deployment_id);
    const details = await Promise.all(ids.map((id) => api.get<DeploymentDetail>(`/api/deployments/${enc(id)}`)));
    return { details, unchecked: liveList.length - ids.length };
  }, [isOperator, visible], poll);
  const report = useLoad(() => api.get<ComplianceReport>("/api/reports/compliance"), [visible], visible ? 60000 : undefined);
  const loadErrors = ([
    ["packages awaiting approval", quarantined.error], ["approved packages", approved.error], ["fleet needs", needs.error],
    ["live deployments", live.error], ["compliance report", report.error],
  ] as const).filter(([, e]) => !!e);

  const items: Item[] = [];
  const firstRun: ReactNode[] = [];

  if (summary.endpoints.total === 0) {
    firstRun.push(<>No endpoints enrolled yet — <Link to={`${paths.endpoints}?enroll=1`}>create an enrollment token</Link> and install the agent on the Windows PCs.</>);
  }
  const pkgTotal = Object.values(summary.packages ?? {}).reduce((a, v) => a + (v ?? 0), 0);
  if (pkgTotal === 0) {
    firstRun.push(<>The catalog is empty — see <Link to={paths.updates()}>Updates</Link> to request updates, then <Link to={paths.transfers}>Transfers</Link> to track them in.</>);
  }

  if (isApprover && me) {
    const mine = (quarantined.data ?? []).filter((p) => !approvedBy(p, me));
    items.push({
      key: "approve", count: mine.length, tone: "amber", to: `${paths.catalog()}?state=quarantined`,
      label: "packages awaiting your approval",
      detail: mine.slice(0, 3).map((p) => <Link key={p.package_id} className="tag" to={paths.catalog(p.package_id)}>{p.title || p.package_id}</Link>),
    });
  }
  if (isOperator) {
    const n = needs.data ?? {};
    const ready = (approved.data ?? []).filter((p) => (n[p.package_id]?.needed ?? 0) > 0 && !n[p.package_id]?.active_deployment_id);
    const endpointsNeeding = ready.reduce((a, p) => a + (n[p.package_id]?.needed ?? 0), 0);
    items.push({
      key: "deploy", count: ready.length, tone: "blue", to: `${paths.catalog()}?state=approved`,
      label: <>approved &amp; needed, not deployed{ready.length > 0 && <span className="muted"> · {endpointsNeeding} endpoint-patches</span>}</>,
      detail: ready.slice(0, 3).map((p) => <Link key={p.package_id} className="tag" to={paths.catalog(p.package_id)}>{p.title || p.package_id} · {n[p.package_id]?.needed}</Link>),
    });
    const ds = live.data?.details ?? [];
    const advance = ds.filter((d) => readyToAdvance(d));
    const paused = ds.filter((d) => d.state === "paused");
    const exhausted = ds.flatMap((d) => exhaustedInCurrentRing(d).map((t) => ({ d, t })));
    const depLinks = (list: DeploymentDetail[]) =>
      list.slice(0, 3).map((d) => <Link key={d.deployment_id} className="tag" to={`/deployments/${enc(d.deployment_id)}`}>{d.name || d.deployment_id}</Link>);
    items.push({ key: "advance", count: advance.length, tone: "green", to: advance[0] ? `/deployments/${enc(advance[0].deployment_id)}` : "/deployments", label: "stages finished, next stage ready to start", detail: depLinks(advance) });
    items.push({ key: "paused", count: paused.length, tone: "red", to: paused[0] ? `/deployments/${enc(paused[0].deployment_id)}` : "/deployments", label: "paused deployments", detail: depLinks(paused) });
    items.push({
      key: "exhausted", count: exhausted.length, tone: "red", to: exhausted[0] ? `/deployments/${enc(exhausted[0].d.deployment_id)}` : "/deployments",
      label: "failed targets with no retries left",
      detail: depLinks(Array.from(new Set(exhausted.map((x) => x.d)))),
    });
  }
  const overdue = Object.values(report.data?.by_severity ?? {}).reduce((a, s) => a + (s.overdue ?? 0), 0);
  items.push({ key: "overdue", count: overdue, tone: "red", to: paths.reports, label: "overdue endpoint-patches (past deadline)" });
  const active = (endpoints ?? []).filter((e) => e.status !== "retired");
  const outdated = active.filter((e) => e.missing && e.missing.os + e.missing.apps > 0).length;
  if (endpoints) items.push({ key: "outdated", count: outdated, tone: "amber", to: `${paths.endpoints}?outdated=1`, label: "endpoints not fully up to date" });

  const open = items.filter((i) => i.count > 0);
  const role = me?.role ?? "viewer";

  return (
    <section className="card your-work">
      <div className="section-head">
        <h2>Your work <span className="muted">· {role}</span></h2>
        {open.length > 0 && <span className="muted small">{open.length} thing{open.length === 1 ? "" : "s"} need attention</span>}
      </div>
      {loadErrors.length > 0 && (
        <div className="banner banner-warn">
          Some of your work could not be checked, so this list may be incomplete:{" "}
          {loadErrors.map(([what, e], i) => <span key={what}>{i > 0 && " · "}<b>{what}</b>: {e}</span>)}
        </div>
      )}
      {(live.data?.unchecked ?? 0) > 0 && (
        <div className="hint">
          Only the first {MAX_DETAILS} live deployments are checked for finished stages, pauses and exhausted retries:{" "}
          <Link to="/deployments">+{live.data!.unchecked} not checked</Link>.
        </div>
      )}
      {firstRun.length > 0 && (
        <div className="banner banner-info">{firstRun.map((f, i) => <div key={i}>{f}</div>)}</div>
      )}
      {open.length === 0
        ? <div className="muted">Nothing is waiting on you. {isOperator ? "New needs show up on Patches → Updates." : ""}</div>
        : (
          <ul className="work-list">
            {open.map((i) => (
              <li key={i.key}>
                <Link to={i.to} className={`work-count work-${i.tone}`}>{i.count}</Link>
                <div>
                  <Link to={i.to}>{i.label}</Link>
                  {i.detail && <div className="work-detail">{i.detail}</div>}
                </div>
              </li>
            ))}
          </ul>
        )}
    </section>
  );
}
