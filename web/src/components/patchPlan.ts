// Shared planning helpers for the "Patch this" drawer and the New deployment
// form: policy deadlines, presets, ring matching and the query-string format
// that carries a prefilled plan to /deployments/new.

import { api } from "../api";
import type { Endpoint, Me, NewDeployment, Package, PackageFleet, Policy, RebootPolicy, Ring } from "../types";

export type PresetKind = "standard" | "one_ring" | "emergency" | "endpoint";

export const STANDARD_MAX_FAILURE_PCT = 10;
export const STANDARD_MAX_RETRIES = 2;
export const EMERGENCY_DEADLINE_HOURS = 24;
const HOUR_MS = 3_600_000;

export const fetchPolicy = (): Promise<Policy> => api.get<Policy>("/api/policy");
export const fetchFleet = (): Promise<Record<string, PackageFleet>> => api.get<Record<string, PackageFleet>>("/api/packages-needs");
export const fetchEndpoints = (): Promise<Endpoint[]> => api.get<Endpoint[]>("/api/endpoints");

/** Go duration string ("168h0m0s", "72h", "90m") → milliseconds; null if unparseable. */
export function parseGoDuration(s: string | undefined | null): number | null {
  if (!s) return null;
  const re = /(\d+(?:\.\d+)?)(h|ms|m|s)/g;
  let total = 0;
  let consumed = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    const v = Number(m[1]);
    total += m[2] === "h" ? v * HOUR_MS : m[2] === "m" ? v * 60_000 : m[2] === "s" ? v * 1000 : v;
    consumed += m[0].length;
  }
  return consumed === s.length && consumed > 0 ? total : null;
}

/** "168h0m0s" → "7 days". */
export function humanDuration(s: string | undefined | null): string {
  const ms = parseGoDuration(s);
  if (ms === null) return s || "—";
  const h = ms / HOUR_MS;
  if (h >= 24 && h % 24 === 0) return `${h / 24} day${h === 24 ? "" : "s"}`;
  return `${Math.round(h * 10) / 10} h`;
}

/** Release date + the policy deadline for the package's severity. */
export function policyDeadline(pkg: Package | undefined, policy: Policy | null | undefined): Date | null {
  if (!pkg || !policy) return null;
  const dur = parseGoDuration(policy.deadlines?.[pkg.severity]);
  if (dur === null) return null;
  const rel = pkg.release_date ? new Date(pkg.release_date) : null;
  if (!rel || isNaN(rel.getTime())) return null;
  return new Date(rel.getTime() + dur);
}

export function approvalsRequired(pkg: Package, policy: Policy | null | undefined): number {
  return policy?.approvals_required?.[pkg.severity] ?? (pkg.approvals_required || 1);
}

/** The server records approvers as "user:<name>". */
export function approvedBy(pkg: Package | undefined, me: Me | null): boolean {
  if (!pkg || !me) return false;
  return (pkg.approvals ?? []).some((a) => a.by === me.user || a.by === `user:${me.user}`);
}

/** RFC 3339 (UTC, no millis). */
export function toRFC(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Date → value for <input type="datetime-local"> (local time). */
export function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** "HH:MM" local ↔ "HH:MM" UTC, using today's offset (the server stores UTC). */
export function localToUtcHHMM(local: string): string {
  if (!/^\d{2}:\d{2}$/.test(local)) return "";
  const [h, m] = local.split(":").map(Number);
  const d = new Date();
  d.setHours(h, m, 0, 0);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}
export function utcToLocalHHMM(utc: string): string {
  if (!/^\d{2}:\d{2}$/.test(utc)) return "";
  const [h, m] = utc.split(":").map(Number);
  const d = new Date();
  d.setUTCHours(h, m, 0, 0);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

export function autoName(pkg: Package | undefined, suffix: string): string {
  if (!pkg) return "";
  const what = pkg.kb || pkg.title || pkg.package_id;
  const month = new Date().toLocaleString("en", { month: "short", year: "numeric" });
  return `${what} · ${suffix} · ${month}`;
}

const norm = (gs: string[]) => gs.map((g) => g.trim().toLowerCase()).filter(Boolean);

/**
 * The stage an endpoint falls in, with the server's first-match rule
 * (deployments.go ringFor): the first ring whose groups contain "all", one of
 * the endpoint's groups or "endpoint:<id>". -1 = in no stage. Group names
 * and ids compare case-insensitively.
 */
export function stageIndexFor(rings: { groups: string[] }[], e: Pick<Endpoint, "endpoint_id" | "groups">): number {
  const eg = norm(e.groups ?? []);
  const self = `endpoint:${e.endpoint_id.toLowerCase()}`;
  for (let i = 0; i < rings.length; i++) {
    const rg = norm(rings[i].groups);
    if (rg.includes("all") || rg.some((g) => g === self || eg.includes(g))) return i;
  }
  return -1;
}

/** Endpoints (not retired) per ring, first matching ring wins. */
export function ringCounts(rings: { groups: string[] }[], endpoints: Endpoint[]): number[] {
  return ringMembers(rings, endpoints).map((m) => m.length);
}

export function groupSize(group: string, endpoints: Endpoint[]): number {
  const g = group.toLowerCase();
  return endpoints.filter((e) => e.status !== "retired" && norm(e.groups ?? []).includes(g)).length;
}

type PresetOpts = { policy: Policy | null | undefined; endpointId?: string; hostname?: string; justification?: string; now?: number };

/** Builds the deployment body for a preset (Custom is the form, see customHref). */
export function buildPreset(kind: PresetKind, pkg: Package, o: PresetOpts): NewDeployment {
  const now = o.now ?? Date.now();
  const base: NewDeployment = {
    package_id: pkg.package_id, name: "", rings: [], max_failure_pct: STANDARD_MAX_FAILURE_PCT,
    max_retries: STANDARD_MAX_RETRIES, window_start: "", window_end: "", emergency: false, justification: "",
    deadline: "", max_concurrent: 0, reboot_policy: "in_window", ignore_windows: false, health_checks: [], operation: "install",
  };
  const dl = policyDeadline(pkg, o.policy);
  switch (kind) {
    case "standard":
      return { ...base, name: autoName(pkg, "standard"), deadline: dl ? toRFC(dl) : "",
        rings: [{ name: "Test machines", groups: ["pilot"] }, { name: "All machines", groups: ["all"] }] };
    case "one_ring":
      return { ...base, name: autoName(pkg, "all endpoints"), deadline: dl ? toRFC(dl) : "",
        rings: [{ name: "all", groups: ["all"] }] };
    case "emergency":
      return { ...base, name: autoName(pkg, "emergency"), rings: [{ name: "all", groups: ["all"] }],
        emergency: true, justification: (o.justification ?? "").trim(), ignore_windows: true,
        deadline: toRFC(new Date(now + EMERGENCY_DEADLINE_HOURS * HOUR_MS)), reboot_policy: "at_deadline" };
    case "endpoint":
      return { ...base, name: `${pkg.kb || pkg.title || pkg.package_id} → ${o.hostname || o.endpointId}`,
        deadline: dl ? toRFC(dl) : "", rings: [{ name: "endpoint", groups: [`endpoint:${o.endpointId ?? ""}`] }] };
  }
}

// ---- query-string format for /deployments/new ----
// rings=pilot:pilot|broad:all,branch-a   (ring name, first ":", comma-separated groups)

export function encodeRings(rings: Ring[]): string {
  return rings.map((r) => `${r.name}:${r.groups.join(",")}`).join("|");
}
export function decodeRings(s: string | null): { name: string; groups: string }[] | null {
  if (!s) return null;
  const out = s.split("|").map((part) => {
    const i = part.indexOf(":");
    return i < 0 ? { name: part.trim(), groups: "" } : { name: part.slice(0, i).trim(), groups: part.slice(i + 1).split(",").map((g) => g.trim()).filter(Boolean).join(", ") };
  }).filter((r) => r.name || r.groups);
  return out.length ? out : null;
}

export function customHref(d: NewDeployment): string {
  const p = new URLSearchParams();
  p.set("package_id", d.package_id);
  if (d.operation && d.operation !== "install") p.set("operation", d.operation);
  if (d.name) p.set("name", d.name);
  if (d.rings.length) p.set("rings", encodeRings(d.rings));
  if (d.deadline) p.set("deadline", d.deadline);
  if (d.emergency) p.set("emergency", "1");
  if (d.justification) p.set("justification", d.justification);
  if (d.ignore_windows) p.set("ignore_windows", "1");
  p.set("reboot_policy", d.reboot_policy);
  p.set("max_failure_pct", String(d.max_failure_pct));
  p.set("max_retries", String(d.max_retries));
  if (d.max_concurrent) p.set("max_concurrent", String(d.max_concurrent));
  if (d.window_start) p.set("window_start", d.window_start);
  if (d.window_end) p.set("window_end", d.window_end);
  return `/deployments/new?${p.toString()}`;
}

export const REBOOT_VALUES: RebootPolicy[] = ["never", "in_window", "at_deadline"];

/** The machines in each stage (first matching stage wins, retired excluded). */
export function ringMembers(rings: { groups: string[] }[], endpoints: Endpoint[]): Endpoint[][] {
  const out: Endpoint[][] = rings.map(() => []);
  for (const e of endpoints) {
    if (e.status === "retired") continue;
    const i = stageIndexFor(rings, e);
    if (i >= 0) out[i].push(e);
  }
  return out;
}
