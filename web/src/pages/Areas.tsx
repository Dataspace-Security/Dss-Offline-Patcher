import { api } from "../api";
import { TabbedArea } from "../components/TabbedArea";
import { paths } from "../paths";
import type { Package, Reconciliation } from "../types";
import { useLoad } from "../util";

// The six areas of the console. Each is a layout route (see App.tsx) whose
// tabs are its child routes.

export function OverviewArea({ openAlerts, critical }: { openAlerts: number; critical: boolean }) {
  return (
    <TabbedArea title="Overview" tabs={[
      { to: paths.overview, label: "Summary", end: true },
      { to: paths.alerts, label: "Alerts", badge: openAlerts, warn: !critical, badgeTitle: `${openAlerts} open alert(s)` },
    ]} />
  );
}

export function PatchesArea() {
  // Badges: packages awaiting approval, and transfers sent (signed receipt
  // seen) whose bundle never arrived.
  const waiting = useLoad(() => api.get<Package[]>("/api/packages?state=quarantined"), [], 30000);
  const recon = useLoad(() => api.get<Reconciliation>("/api/transfer/reconcile"), [], 30000);
  const awaiting = waiting.data?.length ?? 0;
  const missing = recon.data?.receipt_without_bundle?.length ?? 0;
  return (
    <TabbedArea
      title="Patches"
      sub="What the fleet needs and how each update stands, what is in the catalog, and what crossed the one-way transfer"
      tabs={[
        { to: paths.updates(), label: "Updates" },
        { to: paths.catalog(), label: "Catalog", badge: awaiting, warn: true, badgeTitle: `${awaiting} package(s) awaiting approval` },
        { to: paths.transfers, label: "Transfers", badge: missing, badgeTitle: `${missing} transfer(s) sent but never arrived` },
      ]}
    />
  );
}

export function DeploymentsArea() {
  return (
    <TabbedArea title="Deployments" tabs={[
      { to: paths.deployments, label: "Deployments", end: true },
      { to: paths.windows, label: "Maintenance windows" },
      { to: paths.exceptions, label: "Exceptions" },
    ]} />
  );
}

export function EndpointsArea() {
  return (
    <TabbedArea title="Endpoints" tabs={[
      { to: paths.endpoints, label: "Endpoints", end: true },
      { to: paths.addEndpoints, label: "Add endpoints" },
    ]} />
  );
}

export function ReportsArea() {
  return (
    <TabbedArea title="Reports" tabs={[
      { to: paths.reports, label: "Compliance", end: true },
      { to: paths.audit(), label: "Audit" },
    ]} />
  );
}

export function SettingsArea({ isAdmin }: { isAdmin: boolean }) {
  return (
    <TabbedArea title="Settings" tabs={[
      { to: paths.server, label: "Server" },
      { to: paths.users, label: "Users", hidden: !isAdmin },
    ]} />
  );
}
