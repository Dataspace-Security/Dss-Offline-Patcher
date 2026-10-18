import { api } from "../api";
import type { Summary } from "../types";
import { useLoad } from "../util";
import { Time } from "./ui";

const POLL_MS = 5 * 60 * 1000;

/**
 * Warns when the update intelligence (what exists upstream) is older than
 * the server's limit (summary.intel.stale, 8 days): new updates may be
 * missing from Needed and the Library until a fresh document arrives.
 */
export function IntelStaleBanner() {
  const { data } = useLoad(() => api.get<Summary>("/api/summary"), [], POLL_MS);
  const intel = data?.intel;
  if (!intel?.stale) return null;
  const days = Math.floor((intel.age_hours ?? 0) / 24);
  return (
    <div className="banner banner-warn">
      <b>Update information is {days} days old</b> (made <Time value={intel.generated_at} hideRel />). Newer updates may be missing from
      this list. Ask the acquisition team to send fresh update information; it arrives through the transfer.
    </div>
  );
}
