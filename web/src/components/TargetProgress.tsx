import type { Target } from "../types";
import { fmtBytes, parseTime } from "../util";
import { fmtDuration, liveFresh } from "./rollout";
import { TargetPill } from "./ui";

type Stage = { label: string; sub?: string; pct: number | null; tone: "blue" | "green" | "amber" | "red" | "grey"; live: boolean };

/**
 * What a target is doing right now, from its live heartbeat (Target.live)
 * when there is one, else from its recorded state. `pct` drives the bar;
 * null = indeterminate (animated) while work is in progress.
 */
export function targetStage(t: Target, currentRing: number, deploymentLive: boolean, now: number): Stage {
  const live = t.live && liveFresh(t.live, now) ? t.live : null;
  const since = parseTime(t.updated_at);
  const elapsed = since ? fmtDuration((now - since.getTime()) / 1000) : "";
  if (live) {
    switch (live.stage) {
      case "downloading": {
        const pct = live.pct >= 0 ? Math.min(100, live.pct) : null;
        const sizes = live.bytes_total > 0 ? `${fmtBytes(live.bytes_done)} of ${fmtBytes(live.bytes_total)}` : undefined;
        return { label: pct === null ? "Downloading" : `Downloading ${Math.round(pct)} %`, sub: sizes, pct, tone: "blue", live: true };
      }
      case "verifying":
        return { label: "Verifying hash & signature", pct: null, tone: "blue", live: true };
      case "installing":
        return { label: `Installing${elapsed ? ` · ${elapsed}` : ""}`, sub: "running the installer on the endpoint", pct: null, tone: "blue", live: true };
      case "waiting_reboot":
        return { label: "Restart needed", sub: t.detail || (elapsed ? `installed ${elapsed} ago` : undefined), pct: 90, tone: "amber", live: true };
    }
  }
  switch (t.state) {
    case "pending":
      if (t.ring > currentRing) return { label: "Waiting for its stage", pct: 0, tone: "grey", live: false };
      return { label: deploymentLive ? "Waiting for the agent to pick it up" : "Not started", sub: deploymentLive ? "next check-in" : undefined, pct: 0, tone: "grey", live: false };
    case "downloading":
      return { label: "Downloading", sub: elapsed ? `for ${elapsed}` : undefined, pct: null, tone: "blue", live: false };
    case "downloaded":
      return { label: "Downloaded · verifying", pct: 45, tone: "blue", live: false };
    case "installing":
      return { label: `Installing${elapsed ? ` · ${elapsed}` : ""}`, pct: null, tone: "blue", live: false };
    case "installed":
      // P2: the server flags installs that inventory has not confirmed after 6 h.
      if (/not confirmed/i.test(t.detail ?? "")) {
        return { label: "Installed · not confirmed", sub: t.detail, pct: 85, tone: "amber", live: false };
      }
      return { label: "Installed · confirming by inventory", sub: "verified at the next inventory report", pct: 85, tone: "green", live: false };
    case "pending_reboot":
      return { label: "Restart needed", sub: t.detail || (elapsed ? `for ${elapsed}` : undefined), pct: 90, tone: "amber", live: false };
    case "verified":
      return { label: "Verified", sub: t.detail === "already present" ? "already up to date" : "inventory confirms it", pct: 100, tone: "green", live: false };
    case "failed":
    case "lost_after_install":
      return { label: t.state === "failed" ? "Failed" : "Lost after install", pct: 100, tone: "red", live: false };
    case "deferred":
      return { label: "Deferred by pre-install check", sub: "retried at each check-in", pct: 0, tone: "amber", live: false };
    default:
      return { label: t.state.replace(/_/g, " "), pct: null, tone: "grey", live: false };
  }
}

export function TargetProgress({ t, currentRing, deploymentLive, now }: { t: Target; currentRing: number; deploymentLive: boolean; now: number }) {
  const s = targetStage(t, currentRing, deploymentLive, now);
  const running = s.pct === null && (s.tone === "blue" || s.tone === "amber");
  return (
    <div className="tprog">
      <div className="tprog-head">
        <TargetPill state={t.state} operation={t.operation} />
        <span className="tprog-label">{s.live && <span className="live-dot" title="Live progress from the agent" />}{s.label}</span>
      </div>
      <div className={`tprog-bar tprog-${s.tone} ${running ? "tprog-indet" : ""}`} role="progressbar" aria-label={`${t.hostname || t.endpoint_id} progress`}
           aria-valuemin={0} aria-valuemax={100} aria-valuenow={s.pct === null ? undefined : Math.round(s.pct)} aria-valuetext={s.label}>
        <span style={{ width: s.pct === null ? undefined : `${s.pct}%` }} />
      </div>
      {s.sub && <div className="cell-sub">{s.sub}</div>}
    </div>
  );
}
