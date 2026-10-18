import type { RebootPolicy } from "../types";

export const REBOOT_LABELS: Record<RebootPolicy, string> = {
  never: "never (machines show 'Restart needed' until someone restarts them)",
  in_window: "in a maintenance window that allows reboots",
  at_deadline: "at the deadline, even outside windows",
};

/** Friendly names for the default stage (ring) names; stored values are unchanged. */
const STAGE_FRIENDLY: Record<string, string> = {
  pilot: "Test machines",
  broad: "Compatible machines that need it",
  all: "Compatible machines that need it",
  "all machines": "Compatible machines that need it",
  endpoint: "This endpoint",
};

/** Display name of a stage: "Stage N · <friendly name>" (index is 0-based). */
export function stageLabel(name: string | undefined | null, index: number): string {
  const n = (name ?? "").trim();
  const friendly = STAGE_FRIENDLY[n.toLowerCase()] ?? n;
  return friendly ? `Stage ${index + 1} · ${friendly}` : `Stage ${index + 1}`;
}

/** Shown on deployments whose next stage starts by itself (auto_advance). */
export const AUTO_NEXT_HINT =
  "The next stage starts automatically once the current one succeeds; the deployment pauses instead if too many machines fail.";

/** Groups of a stage in plain words: "endpoint:<id>" groups become "N chosen machines". */
export function stageGroupsText(groups: string[]): string {
  const machines = groups.filter((g) => g.toLowerCase().startsWith("endpoint:")).length;
  const rest = groups.filter((g) => !g.toLowerCase().startsWith("endpoint:"))
    .map((g) => (g.toLowerCase() === "all" ? "all other machines" : g));
  const parts = [...(machines > 0 ? [`${machines} chosen machine${machines === 1 ? "" : "s"}`] : []), ...rest];
  return parts.join(", ");
}

/** One-line explanation of staged rollouts, shown on deployment forms. */
export const STAGES_HINT =
  "A deployment runs in stages: test machines first; you check them, then start the next stage (it pauses by itself if too many fail).";
