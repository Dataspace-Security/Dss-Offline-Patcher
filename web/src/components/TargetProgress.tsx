import type { Target } from "../types";
import { fmtBytes, parseTime } from "../util";
import { fmtDuration, liveFresh } from "./rollout";
import { TargetPill } from "./ui";

type Stage = { label: string; sub?: string; pct: number | null; tone: "blue" | "green" | "amber" | "red" | "grey"; live: boolean };

// Fallback for how long "installed" can go without a check-in before the UI
// stops assuming verification is just about to land, used only when the
// caller doesn't know the server's actual configured check-in interval. The
// agent forces a fresh inventory report ~20s after an install, well inside
// the default 60s check-in interval; a few minutes of silence usually means
// the agent isn't checking in at all (down, offline, network issue), not
// that inventory is slow. Callers should instead derive this from the
// server's checkin_interval_seconds (GET /api/system): a site configured
// with a longer interval (e.g. to save bandwidth) would otherwise see this
// warning as a matter of course after every single install.
const DEFAULT_STALE_CONTACT_SEC = 180;

/**
 * What a target is doing right now, from its live heartbeat (Target.live)
 * when there is one, else from its recorded state. `pct` drives the bar;
 * null = indeterminate (animated) while work is in progress. `lastContact`
 * (ISO timestamp of the endpoint's last check-in, when known) flags a stuck
 * "confirming by inventory" wait that is really just a silent agent, once it
 * has been silent longer than `staleAfterSec` (default DEFAULT_STALE_CONTACT_SEC).
 */
export function targetStage(t: Target, currentRing: number, deploymentLive: boolean, now: number, lastContact?: string, staleAfterSec = DEFAULT_STALE_CONTACT_SEC): Stage {
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
    case "installed": {
      // P2: the server flags installs that inventory has not confirmed after 6 h.
      if (/not confirmed/i.test(t.detail ?? "")) {
        return { label: "Installed · not confirmed", sub: t.detail, pct: 85, tone: "amber", live: false };
      }
      const contactAt = parseTime(lastContact);
      const silentFor = contactAt ? (now - contactAt.getTime()) / 1000 : null;
      if (silentFor !== null && silentFor > staleAfterSec) {
        return {
          label: "Installed · waiting on the agent",
          sub: `hasn't checked in for ${fmtDuration(silentFor)} — verification will follow its next check-in`,
          pct: 85, tone: "amber", live: false,
        };
      }
      return { label: "Installed · confirming by inventory", sub: "verified at the next inventory report", pct: 85, tone: "green", live: false };
    }
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

export function TargetProgress({ t, currentRing, deploymentLive, now, lastContact, staleAfterSec }: { t: Target; currentRing: number; deploymentLive: boolean; now: number; lastContact?: string; staleAfterSec?: number }) {
  const s = targetStage(t, currentRing, deploymentLive, now, lastContact, staleAfterSec);
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
