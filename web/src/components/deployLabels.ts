import type { RebootPolicy } from "../types";

export const REBOOT_LABELS: Record<RebootPolicy, string> = {
  never: "never (endpoints report pending reboot)",
  in_window: "in a maintenance window that allows reboots",
  at_deadline: "at the deadline, even outside windows",
};

/** Friendly names for the default stage (ring) names; stored values are unchanged. */
const STAGE_FRIENDLY: Record<string, string> = {
  pilot: "Test machines",
  broad: "All machines",
  all: "All machines",
  endpoint: "This endpoint",
};

/** Display name of a stage: "Stage N · <friendly name>" (index is 0-based). */
export function stageLabel(name: string | undefined | null, index: number): string {
  const n = (name ?? "").trim();
  const friendly = STAGE_FRIENDLY[n.toLowerCase()] ?? n;
  return friendly ? `Stage ${index + 1} · ${friendly}` : `Stage ${index + 1}`;
}

/** One-line explanation of staged rollouts, shown on deployment forms. */
export const STAGES_HINT =
  "A deployment runs in stages: test machines first; you check them, then start the next stage (it pauses by itself if too many fail).";
