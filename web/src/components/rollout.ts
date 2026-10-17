// Rollout logic shared by the deployment page and the Overview "Your work"
// card. It mirrors the server's ring bookkeeping (store/deployments.go):
// a ring is finished when every target is verified, skipped (not applicable /
// exception) or failed with its retries exhausted.
import type { Deployment, DeploymentDetail, Target, TargetLive, TargetState } from "../types";

export const IN_FLIGHT: TargetState[] = ["downloading", "downloaded", "installing", "installed", "pending_reboot"];
export const WAITING: TargetState[] = ["pending", "deferred"];

/** Failed and no retries left: only "Retry failed" or an exception moves it. */
export function isExhausted(t: Target, d: Pick<Deployment, "max_retries">): boolean {
  return t.state === "failed" && t.attempts > d.max_retries;
}

export function isTerminal(t: Target, d: Pick<Deployment, "max_retries">): boolean {
  return t.state === "verified" || t.state === "not_applicable" || t.state === "exception" || isExhausted(t, d);
}

/** Targets that count against the auto-pause threshold (or are about to). */
export function isFailing(t: Target): boolean {
  return t.state === "failed" || t.state === "lost_after_install" || (t.health === "failed" && t.state !== "verified");
}

export type RingSummary = {
  index: number; name: string; groups: string[];
  total: number; verified: number; failed: number; exhausted: number; inProgress: number; waiting: number; skipped: number;
  finished: boolean; // every target terminal (false when empty)
  empty: boolean;
};

export function ringSummaries(d: DeploymentDetail): RingSummary[] {
  const targets = d.targets ?? [];
  return (d.rings ?? []).map((r, index) => {
    const ts = targets.filter((t) => t.ring === index);
    const count = (f: (t: Target) => boolean) => ts.filter(f).length;
    const total = ts.length;
    return {
      index, name: r.name || "", groups: r.groups ?? [], total,
      verified: count((t) => t.state === "verified"),
      failed: count((t) => t.state === "failed" || t.state === "lost_after_install"),
      exhausted: count((t) => isExhausted(t, d)),
      inProgress: count((t) => IN_FLIGHT.includes(t.state)),
      waiting: count((t) => WAITING.includes(t.state)),
      skipped: count((t) => t.state === "not_applicable" || t.state === "exception"),
      finished: total > 0 && count((t) => isTerminal(t, d)) === total,
      empty: total === 0,
    };
  });
}

/** The current ring is done (or empty) and a later ring exists. */
export function readyToAdvance(d: DeploymentDetail): RingSummary | null {
  if (d.state !== "active") return null;
  const rings = ringSummaries(d);
  const cur = rings[d.current_ring];
  if (!cur || d.current_ring >= rings.length - 1) return null;
  return cur.finished || cur.empty ? cur : null;
}

export function exhaustedInCurrentRing(d: DeploymentDetail): Target[] {
  return (d.targets ?? []).filter((t) => t.ring === d.current_ring && isExhausted(t, d));
}

export function isLiveDeployment(d: Pick<Deployment, "state"> | null | undefined): boolean {
  return !!d && (d.state === "active" || d.state === "paused");
}

/** "2m 13s", "1h 04m", "45s". */
export function fmtDuration(sec: number): string {
  const s = Math.max(0, Math.round(sec));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
}

/** Live progress counts as fresh for a minute after the last heartbeat. */
export function liveFresh(live: TargetLive | null | undefined, now: number): boolean {
  if (!live?.at) return false;
  const t = new Date(live.at).getTime();
  return !isNaN(t) && now - t < 60_000;
}
