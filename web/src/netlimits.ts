import type { Policy } from "./types";

function speed(kbps: number | undefined): string {
  if (!kbps) return "full speed per machine";
  return kbps >= 1024 ? `${Math.round((kbps / 1024) * 10) / 10} Mbit/s per machine` : `${kbps} kbit/s per machine`;
}

/** "All deployments together: at most 100 machines download at once, 5 per site · full speed per machine". */
export function networkLimitsText(policy: Policy | null | undefined): string {
  if (!policy) return "";
  const total = policy.max_downloads_total ?? 0;
  const site = policy.max_downloads_per_site ?? 0;
  const parts = [
    total > 0 ? `at most ${total} machine${total === 1 ? "" : "s"} download at once` : "no fleet-wide download limit",
    site > 0 ? `${site} per site` : "no per-site limit",
  ];
  const overrides = Object.keys(policy.site_max_downloads ?? {}).length + Object.keys(policy.site_download_kbps ?? {}).length;
  return `All deployments together: ${parts.join(", ")} · ${speed(policy.download_rate_kbps)}${overrides ? " (some sites have their own limits)" : ""}. Set by the server's network limits.`;
}
