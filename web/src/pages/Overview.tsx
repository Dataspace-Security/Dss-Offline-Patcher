import { Link } from "react-router-dom";
import { api } from "../api";
import { hasRole, useMe } from "../auth";
import { ErrorBanner, PageHeader, RelTime } from "../components/ui";
import { YourWork } from "../components/YourWork";
import { fetchFleet, fetchPolicy } from "../components/patchPlan";
import { usePageVisible } from "../components/usePageVisible";
import { DashCard, Skeleton } from "../components/dashboard/charts";
import { HeroRow } from "../components/dashboard/HeroRow";
import { FleetHealth } from "../components/dashboard/FleetHealth";
import { PatchExposure } from "../components/dashboard/PatchExposure";
import { Rollouts } from "../components/dashboard/Rollouts";
import { SupplyChain, type AcquisitionOverview } from "../components/dashboard/SupplyChain";
import { RecentActivity } from "../components/dashboard/RecentActivity";
import type { AcquisitionRequestRecord, Alert, AuditEvent, Deployment, Endpoint, Package, Summary } from "../types";
import { isOpenAlert } from "./Alerts";
import { useLoad } from "../util";
import "../dashboard.css";

const SUMMARY_MS = 10000;
const AUDIT_LIMIT = 8;

/** Overview dashboard: one screen that says how patched the bank is and what to do next. */
export default function Overview() {
  const me = useMe();
  const canPatch = hasRole(me, "user");
  // No polling while the browser tab is hidden; becoming visible again reloads at once.
  const visible = usePageVisible();
  const every = (ms: number) => (visible ? ms : undefined);

  const summary = useLoad(() => api.get<Summary>("/api/summary"), [visible], every(SUMMARY_MS));
  const alerts = useLoad(() => api.get<Alert[]>("/api/alerts?open=1").then((l) => (l ?? []).filter(isOpenAlert)), [visible], every(15000));
  const eps = useLoad(() => api.get<Endpoint[]>("/api/endpoints"), [visible], every(30000));
  const needs = useLoad(fetchFleet, [visible], every(60000));
  const packages = useLoad(() => api.get<Package[]>("/api/packages"), [visible], every(60000));
  const deployments = useLoad(() => api.get<Deployment[]>("/api/deployments"), [visible], every(SUMMARY_MS));
  const policy = useLoad(fetchPolicy, []);
  // Imports (download runs, requests) are User and up.
  const acquisition = useLoad(() => (canPatch ? api.get<AcquisitionOverview>("/api/acquisition?limit=1") : Promise.resolve(null)),
    [visible, canPatch], canPatch ? every(5 * 60000) : undefined);
  const requests = useLoad(() => (canPatch ? api.get<AcquisitionRequestRecord[]>("/api/acquisition-requests") : Promise.resolve(null)),
    [visible, canPatch], canPatch ? every(5 * 60000) : undefined);
  const audit = useLoad(() => api.get<AuditEvent[]>(`/api/audit?limit=${AUDIT_LIMIT}`).then((l) => (l ?? []).slice(0, AUDIT_LIMIT)), [visible], every(30000));

  const s = summary.data;
  const by = s?.endpoints.by_status as Record<string, number> | undefined;
  const silent = (by?.offline ?? 0) + (by?.stale ?? 0);
  const reloadPatches = () => { void needs.reload(); void packages.reload(); void deployments.reload(); };
  const otherErrors = ([
    ["alerts", alerts.error], ["endpoints", eps.error], ["patch needs", needs.error], ["packages", packages.error],
    ["deployments", deployments.error],
  ] as const).filter(([, e]) => !!e);

  return (
    <div className="dash">
      <PageHeader title="Overview"
                  sub={summary.loadedAt
                    ? <>Updated <RelTime value={new Date(summary.loadedAt).toISOString()} /> · refreshes every {SUMMARY_MS / 1000} s{visible ? "" : " (paused while this tab is hidden)"}</>
                    : "Loading…"} />
      <ErrorBanner error={summary.error} />
      {otherErrors.length > 0 && (
        <div className="banner banner-warn">
          Some numbers could not be loaded and may be missing:{" "}
          {otherErrors.map(([what, e], i) => <span key={what}>{i > 0 && " · "}<b>{what}</b>: {e}</span>)}
        </div>
      )}
      {silent > 0 && (
        <div className="banner banner-warn">
          <b>{silent}</b> machine{silent === 1 ? " is" : "s are"} not reporting ({by?.offline ?? 0} offline, {by?.stale ?? 0} stale).
          They are never counted as compliant. <Link to="/endpoints?status=offline,stale">Review them</Link>
        </div>
      )}

      <HeroRow summary={s} endpoints={eps.data} needs={needs.data} alerts={alerts.data} />

      <div className="dash-grid">
        <FleetHealth summary={s} isOperator={canPatch} />
        <PatchExposure packages={packages.data} needs={needs.data} endpoints={eps.data} canPatch={canPatch} onChanged={reloadPatches} />
        <SupplyChain summary={s} acquisition={acquisition.data} acquisitionError={acquisition.error} requests={requests.data} showImports={canPatch} />
        {s
          ? <YourWork summary={s} endpoints={eps.data} className="dash-span-2 dash-wide-3" />
          : <DashCard title="Your work" className="dash-span-2 dash-wide-3"><Skeleton lines={4} /></DashCard>}
        <Rollouts deployments={deployments.data} policy={policy.data} canPlan={canPatch} />
        <RecentActivity events={audit.data} error={audit.error} summary={s} />
      </div>
    </div>
  );
}
