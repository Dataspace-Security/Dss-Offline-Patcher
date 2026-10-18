import type { ReactNode } from "react";
import { CONTROL_STATUSES, type ControlStatus, type CountPct } from "./types";
import { fmtTime, parseTime } from "../util";

/** Server may send "Partially compliant", "partially-compliant", "partial" … → canonical key. */
export function normStatus(s: string | null | undefined): ControlStatus {
  const k = (s ?? "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if ((CONTROL_STATUSES as readonly string[]).includes(k)) return k as ControlStatus;
  if (k.startsWith("partial")) return "partially_compliant";
  if (k === "noncompliant" || k === "non_compliant" || k === "failed") return "non_compliant";
  if (k === "na" || k === "n/a" || k === "not_applicable") return "not_applicable";
  if (k === "compliant" || k === "pass" || k === "met") return "compliant";
  return "not_assessed";
}

export const STATUS_LABEL: Record<ControlStatus, string> = {
  compliant: "Compliant",
  partially_compliant: "Partially compliant",
  non_compliant: "Non-compliant",
  not_applicable: "Not applicable",
  not_assessed: "Not assessed",
};

export function StatusBadge({ status, large }: { status: string | null | undefined; large?: boolean }) {
  const s = normStatus(status);
  return <span className={`crep-badge crep-badge-${s} ${large ? "crep-badge-lg" : ""}`}>{STATUS_LABEL[s]}</span>;
}

const OUTCOME_TONE: Record<string, string> = {
  compliant: "compliant", verified_late: "high", overdue: "non_compliant", failed: "non_compliant", pending: "partially_compliant",
  offline: "not_assessed", not_applicable: "not_applicable", exception: "exception",
};

export function OutcomeBadge({ outcome }: { outcome: string }) {
  const k = (outcome || "").toLowerCase();
  const tone = OUTCOME_TONE[k] ?? "not_assessed";
  const label = k === "exception" ? "approved exception" : k.replace(/_/g, " ") || "unknown";
  return <span className={`crep-badge crep-badge-sm crep-badge-${tone}`}>{label}</span>;
}

const SEV_TONE: Record<string, string> = { critical: "non_compliant", high: "high", medium: "partially_compliant", low: "not_applicable" };

export function SeverityBadge({ severity }: { severity: string }) {
  const k = (severity || "").toLowerCase();
  return <span className={`crep-badge crep-badge-sm crep-badge-${SEV_TONE[k] ?? "not_assessed"}`}>{severity || "—"}</span>;
}

/** "—" for empty values; dates in the report are shown as YYYY-MM-DD. */
export function Txt({ v, placeholder }: { v: string | number | null | undefined; placeholder?: string }): ReactNode {
  if (v === null || v === undefined || v === "") return <span className="crep-empty">{placeholder ?? "—"}</span>;
  return <>{v}</>;
}

export function fmtDate(s: string | null | undefined): string {
  if (!s) return "";
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const d = parseTime(s);
  if (!d) return "";
  return isoDay(d);
}

export function fmtStamp(s: string | null | undefined): string {
  if (!s) return "";
  const d = parseTime(s);
  if (!d) return s;
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, "0");
  const mm = String(Math.abs(off) % 60).padStart(2, "0");
  return `${fmtTime(s)} (UTC${sign}${hh}:${mm})`;
}

export function fmtCountPct(c: CountPct | number | null | undefined): string {
  if (c === null || c === undefined) return "—";
  if (typeof c === "number") return String(c);
  if (c.pct === null || c.pct === undefined || Number.isNaN(c.pct)) return String(c.count ?? 0);
  return `${c.count ?? 0} / ${c.pct.toFixed(1)}%`;
}

export function fmtPct(p: number | null | undefined): string {
  if (p === null || p === undefined || Number.isNaN(p)) return "Not assessed";
  return `${p.toFixed(1)}%`;
}

function pad(n: number): string {
  return String(n).padStart(2, "0");
}

export function isoDay(d: Date): string {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

export type PeriodKind = "this_month" | "last_month" | "this_quarter" | "custom";

export const PERIOD_LABELS: Record<PeriodKind, string> = {
  this_month: "This month",
  last_month: "Last month",
  this_quarter: "This quarter",
  custom: "Custom",
};

/** Local calendar range for a preset; "this …" ends today. */
export function periodRange(kind: Exclude<PeriodKind, "custom">, now = new Date()): { from: string; to: string } {
  const y = now.getFullYear();
  const m = now.getMonth();
  if (kind === "this_month") return { from: isoDay(new Date(y, m, 1)), to: isoDay(now) };
  if (kind === "last_month") return { from: isoDay(new Date(y, m - 1, 1)), to: isoDay(new Date(y, m, 0)) };
  const q = Math.floor(m / 3) * 3;
  return { from: isoDay(new Date(y, q, 1)), to: isoDay(now) };
}

/** Safe for file names and CSS strings: letters, digits, dot, dash, underscore. */
export function safeToken(s: string): string {
  return (s || "").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
}

/** Normalise a free-text field that may come as string or string[]. */
export function asLines(v: string | string[] | null | undefined): string[] {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter((x) => typeof x === "string" && x.trim() !== "");
  return v.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
}

/** Only http(s) links are rendered as anchors. */
export function safeHttpUrl(u: string | null | undefined): string | null {
  if (!u) return null;
  try {
    const url = new URL(u);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}
