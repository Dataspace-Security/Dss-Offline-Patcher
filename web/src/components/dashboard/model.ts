// Pure calculations behind the Overview dashboard. No React, no fetching:
// every function takes data the console already loads and returns new values.
import type { Deployment, Endpoint, Package, PackageFleet, Summary } from "../../types";
import { isAgentPackage } from "../patchPlan";

export type Tone = "green" | "amber" | "red" | "blue" | "purple" | "grey";

/** One slice of the fleet bar: which endpoint statuses it holds and where it links. */
export type FleetGroup = {
  key: string;
  label: string;
  help: string;
  statuses: readonly string[];
  /** CSS custom property used as the fill (status tokens only). */
  fill: string;
  /** Hatched fill: "no information" classes, so identity never rests on colour alone. */
  hatch?: boolean;
  count: number;
};

/**
 * Order matters: neighbours were checked with the dataviz palette validator
 * (colour-blind separation passes in light and dark); every slice also has a
 * legend row with its count, so the colour is never the only cue.
 */
const FLEET_GROUP_DEFS: Omit<FleetGroup, "count">[] = [
  { key: "compliant", label: "Compliant", statuses: ["compliant"], fill: "--green-solid",
    help: "Checking in, nothing missing and no deployment problem." },
  { key: "restart", label: "Restart needed", statuses: ["pending_reboot"], fill: "--blue-solid",
    help: "Installed; the machine must restart to finish." },
  { key: "updates", label: "Updates available", statuses: ["updates_available", "noncompliant"], fill: "--amber-solid",
    help: "Checking in, but Windows or application updates are missing." },
  { key: "unsupported", label: "Windows no longer updated", statuses: ["out_of_support"], fill: "--purple-solid",
    help: "This Windows version gets no more security updates. Upgrade it." },
  { key: "failed", label: "Failed", statuses: ["failed", "lost_after_install"], fill: "--red-solid",
    help: "An install failed, or an installed update went missing again." },
  { key: "silent", label: "Offline or stale", statuses: ["offline", "stale"], fill: "--grey-solid",
    help: "Not reporting. Silence is never counted as compliant." },
  { key: "waiting", label: "Waiting for first check-in", statuses: ["awaiting_checkin"], fill: "--grey-solid", hatch: true,
    help: "Enrolled, but the agent has not sent its first inventory yet." },
  { key: "exception", label: "Exception (accepted risk)", statuses: ["exception"], fill: "--purple-solid", hatch: true,
    help: "An active exception covers this machine." },
];

function count(by: Record<string, number> | undefined, k: string): number {
  return by?.[k] ?? 0;
}

export function fleetGroups(summary: Summary): FleetGroup[] {
  const by = summary.endpoints.by_status as Record<string, number> | undefined;
  return FLEET_GROUP_DEFS.map((g) => ({ ...g, count: g.statuses.reduce((a, s) => a + count(by, s), 0) }));
}

export function endpointsLink(statuses: readonly string[]): string {
  return `/endpoints?status=${statuses.join(",")}`;
}

/** Share as a whole percent, rounded down so 99.6 % never reads as 100 %. */
export function pctFloor(part: number, whole: number): number {
  return whole > 0 ? Math.floor((part / whole) * 100) : 0;
}

/**
 * Compliance score: compliant ÷ every non-retired endpoint. Offline, stale,
 * waiting and unknown machines stay in the denominator, so they count
 * against the score.
 */
export function complianceScore(summary: Summary) {
  const total = summary.endpoints.total;
  const compliant = count(summary.endpoints.by_status as Record<string, number>, "compliant");
  return { total, compliant, pct: pctFloor(compliant, total) };
}

export function activeEndpoints(endpoints: Endpoint[] | null | undefined): Endpoint[] {
  return (endpoints ?? []).filter((e) => e.status !== "retired");
}

/**
 * Fully up to date: inventory shows no missing Windows update, no outdated
 * application and no catalog package still needed. Machines without update
 * information are not counted as up to date.
 */
export function upToDate(endpoints: Endpoint[] | null, needs: Record<string, PackageFleet> | null) {
  const active = activeEndpoints(endpoints);
  const known = active.filter((e) => !!e.missing);
  const needsPackage = new Set(Object.values(needs ?? {}).flatMap((f) => (f.needed > 0 ? f.endpoint_ids ?? [] : [])));
  const ok = known.filter((e) => e.missing && e.missing.os + e.missing.apps === 0 && !(e.missing.ready > 0)
    && !needsPackage.has(e.endpoint_id)).length;
  return { total: active.length, ok, unknown: active.length - known.length, pct: pctFloor(ok, active.length) };
}

/** Windows updates vs. application updates still missing, summed over the fleet's inventory. */
export function missingSplit(endpoints: Endpoint[] | null) {
  const active = activeEndpoints(endpoints);
  return active.reduce(
    (acc, e) => ({
      os: acc.os + (e.missing?.os ?? 0),
      apps: acc.apps + (e.missing?.apps ?? 0),
      osMachines: acc.osMachines + ((e.missing?.os ?? 0) > 0 ? 1 : 0),
      appMachines: acc.appMachines + ((e.missing?.apps ?? 0) > 0 ? 1 : 0),
    }),
    { os: 0, apps: 0, osMachines: 0, appMachines: 0 },
  );
}

export const SEVERITIES = ["critical", "important", "moderate", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const SEVERITY_FILL: Record<Severity, string> = {
  critical: "--red-solid", important: "--orange", moderate: "--amber-solid", low: "--grey-solid",
};

/** Catalog packages that can still be rolled out (agent versions are not security patches). */
function patchable(p: Package): boolean {
  return (p.state === "approved" || p.state === "quarantined") && !isAgentPackage(p);
}

export type NeededPackage = { pkg: Package; fleet: PackageFleet };

export function neededPackages(packages: Package[] | null, needs: Record<string, PackageFleet> | null): NeededPackage[] {
  if (!packages || !needs) return [];
  return packages
    .filter(patchable)
    .map((pkg) => ({ pkg, fleet: needs[pkg.package_id] }))
    .filter((x): x is NeededPackage => !!x.fleet && x.fleet.needed > 0)
    .sort((a, b) => b.fleet.needed - a.fleet.needed || severityRank(a.pkg.severity) - severityRank(b.pkg.severity));
}

function severityRank(s: string): number {
  const i = SEVERITIES.indexOf(s as Severity);
  return i < 0 ? SEVERITIES.length : i;
}

/** Endpoint-patches still missing per severity (catalog packages only). */
export function bySeverity(list: NeededPackage[]): Record<Severity, { missing: number; packages: number }> {
  const empty = Object.fromEntries(SEVERITIES.map((s) => [s, { missing: 0, packages: 0 }])) as Record<Severity, { missing: number; packages: number }>;
  return list.reduce((acc, { pkg, fleet }) => {
    const s = (SEVERITIES as readonly string[]).includes(pkg.severity) ? (pkg.severity as Severity) : "low";
    return { ...acc, [s]: { missing: acc[s].missing + fleet.needed, packages: acc[s].packages + 1 } };
  }, empty);
}

/** Progress of a running deployment from its target counts. */
export function rolloutProgress(d: Pick<Deployment, "counts">) {
  const c = d.counts ?? {};
  const v = (k: string) => (c as Record<string, number | undefined>)[k] ?? 0;
  const total = Object.values(c).reduce<number>((a, x) => a + (x ?? 0), 0);
  const applicable = total - v("not_applicable") - v("exception");
  const done = v("verified");
  const working = v("downloading") + v("downloaded") + v("installing") + v("installed") + v("pending_reboot");
  const failed = v("failed") + v("lost_after_install");
  const waiting = Math.max(0, applicable - done - working - failed);
  return { total, applicable, done, working, failed, waiting, pct: pctFloor(done, applicable) };
}

export function scoreTone(pct: number): "green" | "amber" | "red" {
  return pct >= 95 ? "green" : pct >= 70 ? "amber" : "red";
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}
