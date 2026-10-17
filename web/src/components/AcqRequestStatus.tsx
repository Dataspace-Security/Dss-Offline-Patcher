import type { AcquisitionRequestRef } from "../types";
import { Pill, RelTime } from "./ui";

const STATUS: Record<AcquisitionRequestRef["status"], { pill: string; label: string; help: string }> = {
  requested: { pill: "pending", label: "requested", help: "Exported for the acquisition zone; not seen by the downloader yet" },
  seen: { pill: "active", label: "seen by downloader", help: "The downloader reported working on this request" },
  fulfilled: { pill: "verified", label: "arrived", help: "A validated bundle brought it in" },
};

export function acqStatusPill(status: AcquisitionRequestRef["status"]): { pill: string; label: string; help: string } {
  return STATUS[status] ?? { pill: "grey", label: status, help: "" };
}

/** "requested · 2d ago" for an update listed in a tracked acquisition request. */
export function RequestedPill({ r }: { r: AcquisitionRequestRef }) {
  const s = acqStatusPill(r.status);
  return (
    <span className="small" title={`${s.help} · request ${r.request_id}`}>
      <Pill state={s.pill} label={s.label} /> <span className="muted"><RelTime value={r.at} /></span>
    </span>
  );
}
