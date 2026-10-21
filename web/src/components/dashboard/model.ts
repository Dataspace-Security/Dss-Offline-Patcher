// Pure calculations behind the Overview dashboard. No React, no fetching:
// every function takes data the console already loads and returns new values.
import type { Deployment, Endpoint, FleetStatusRow, Package, PackageFleet, Summary } from "../../types";
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
 * information are left out of the share (neither up to date nor behind).
 */
export function upToDate(endpoints: Endpoint[] | null, needs: Record<string, PackageFleet> | null) {
  const active = activeEndpoints(endpoints);
  const known = active.filter((e) => !!e.missing);
  const needsPackage = new Set(Object.values(needs ?? {}).flatMap((f) => (f.needed > 0 ? f.endpoint_ids ?? [] : [])));
  const ok = known.filter((e) => e.missing && e.missing.os + e.missing.apps === 0 && !(e.missing.ready > 0)
    && !needsPackage.has(e.endpoint_id)).length;
  // Machines without update information are neutral: the share is of machines that have it (null: none has).
  return { total: active.length, known: known.length, ok, unknown: active.length - known.length,
    pct: known.length ? pctFloor(ok, known.length) : null };
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

// ---------------------------------------------------------------------------
// History, platforms, deployments and applications (Overview charts).

/** One day of fleet history (GET /api/dashboard/trend). */
export type FleetDay = {
  day: string; endpoints: number; compliant: number; updates_available: number; failed: number; offline: number;
  critical_missing: number; important_missing: number; deployments_done: number; deployments_failed: number; taken_at: string;
};
export type FleetTrend = { days: number; today: string; rows: FleetDay[] };

/** Days from today back (inclusive), oldest first, as YYYY-MM-DD in local time. */
export function dayRange(today: string, days: number): string[] {
  const [y, m, d] = today.split("-").map((x) => parseInt(x, 10));
  return Array.from({ length: days }, (_, i) => {
    const t = new Date(y, m - 1, d - (days - 1 - i));
    return `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, "0")}-${String(t.getDate()).padStart(2, "0")}`;
  });
}

/** Trend series aligned to every day of the range (null = no snapshot that day). */
export function trendSeries(trend: FleetTrend) {
  const byDay = new Map(trend.rows.map((r) => [r.day, r]));
  const days = dayRange(trend.today, trend.days);
  const rows = days.map((d) => byDay.get(d) ?? null);
  return {
    days,
    // A day with no enrolled machine has no compliance share (not 0 %).
    compliantPct: rows.map((r) => (r && r.endpoints > 0 ? pctFloor(r.compliant, r.endpoints) : null)),
    updates: rows.map((r) => (r ? r.updates_available : null)),
    points: trend.rows.length,
  };
}

/** Windows 10/11 and Server builds by release name (KB numbers are shared across some of them). */
export const BUILD_NAMES: Record<number, string> = {
  19044: "10 21H2", 19045: "10 22H2", 20348: "Server 2022", 22621: "11 22H2", 22631: "11 23H2", 26100: "11 24H2 / Server 2025", 26200: "11 25H2",
};

/** Windows release of an endpoint, e.g. "Windows 11 23H2"; falls back to the reported version or build. */
export function windowsRelease(e: Pick<Endpoint, "build" | "os" | "os_version">): string {
  if (BUILD_NAMES[e.build]) return `Windows ${BUILD_NAMES[e.build]}`;
  if (e.build > 0) return `${e.os || "Windows"} build ${e.build}`;
  return e.os_version || e.os || "Unknown";
}

export type Slice = { key: string; label: string; value: number; builds: number[] };

/** Endpoints per Windows release, biggest first; slices after `named` fold into "Other". */
export function osSlices(endpoints: Endpoint[] | null, named = 4): Slice[] {
  const groups = new Map<string, Slice>();
  for (const e of activeEndpoints(endpoints)) {
    const label = windowsRelease(e);
    const g = groups.get(label) ?? { key: label, label, value: 0, builds: [] };
    groups.set(label, { ...g, value: g.value + 1, builds: g.builds.includes(e.build) ? g.builds : [...g.builds, e.build] });
  }
  const sorted = [...groups.values()].sort((a, b) => b.value - a.value || a.label.localeCompare(b.label));
  if (sorted.length <= named + 1) return sorted;
  const rest = sorted.slice(named);
  return [...sorted.slice(0, named), {
    key: "other", label: `Other (${rest.length} releases)`, value: rest.reduce((a, s) => a + s.value, 0),
    builds: rest.flatMap((s) => s.builds),
  }];
}

export type WeekBucket = { start: Date; label: string; completed: number; failed: number };

function mondayOf(t: Date): Date {
  const d = new Date(t.getFullYear(), t.getMonth(), t.getDate());
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() - ((d.getDay() + 6) % 7));
}

/** Deployment had a failed or lost target. */
function hadFailures(d: Pick<Deployment, "counts">): boolean {
  const c = (d.counts ?? {}) as Record<string, number | undefined>;
  return (c.failed ?? 0) + (c.lost_after_install ?? 0) > 0;
}

/**
 * Deployments finished in the last `days` days, per calendar week (Monday
 * first): completed without failures vs. with failed targets or cancelled.
 * The finish time is the deployment's last update.
 */
export function weeklyDeployments(deployments: Deployment[] | null, now: Date, days = 30): WeekBucket[] {
  const from = new Date(now.getFullYear(), now.getMonth(), now.getDate() - (days - 1));
  const weeks: WeekBucket[] = [];
  for (let w = mondayOf(from); w <= now; w = new Date(w.getFullYear(), w.getMonth(), w.getDate() + 7)) {
    weeks.push({ start: w, label: w.toLocaleDateString(undefined, { month: "short", day: "numeric" }), completed: 0, failed: 0 });
  }
  return (deployments ?? []).reduce((acc, d) => {
    if (d.state !== "completed" && d.state !== "cancelled") return acc;
    const t = new Date(d.updated_at);
    if (Number.isNaN(t.getTime()) || t < from || t > now) return acc;
    const i = acc.findIndex((b, j) => t >= b.start && (j === acc.length - 1 || t < acc[j + 1].start));
    if (i < 0) return acc;
    const bad = d.state === "cancelled" || hadFailures(d);
    return acc.map((b, j) => (j === i ? { ...b, completed: b.completed + (bad ? 0 : 1), failed: b.failed + (bad ? 1 : 0) } : b));
  }, weeks);
}

export type OutdatedApp = { key: string; name: string; latest: string; outdated: number; failed: number; seen: number };

/** Applications most machines run an old version of (fleet status rows kind=app). */
export function topOutdatedApps(rows: FleetStatusRow[] | null | undefined, n = 10): OutdatedApp[] {
  return (rows ?? [])
    .filter((r) => r.kind === "app" && r.outdated + r.failed > 0)
    .map((r) => ({
      key: r.key, name: r.name || r.key, latest: r.latest, outdated: r.outdated + r.failed, failed: r.failed,
      seen: r.up_to_date + r.outdated + r.being_patched + r.verified + r.failed + r.exception,
    }))
    .sort((a, b) => b.outdated - a.outdated || a.name.localeCompare(b.name))
    .slice(0, n);
}
