import { Link } from "react-router-dom";
import { paths } from "../paths";
import type { CatalogLink, IntelSummary } from "../types";
import { Pill, RelTime } from "./ui";

// The per-endpoint "Updates available" list was merged with the catalog
// "Available patches" list into one table: EndpointUpdatesTable in
// AvailablePatches.tsx (P2.6). The shared pieces stay here.

/** Where an available update stands in the offline pipeline. */
export function CatalogState({ link }: { link: CatalogLink | null }) {
  if (!link) return <span className="muted" title="Not imported yet: select it on Patches → Updates and export an acquisition request for pmctl auto">not imported</span>;
  const label = { approved: "in catalog · approved", quarantined: "in catalog · awaiting approval" }[link.state] ?? `in catalog · ${link.state}`;
  return <Link to={paths.catalog(link.package_id)}><Pill state={link.state} label={label} /></Link>;
}

export function IntelSource({ intel }: { intel: IntelSummary | null | undefined }) {
  if (!intel) return null;
  return (
    <span className="muted">
      update intelligence from <RelTime value={intel.generated_at} /> · {intel.windows} Windows builds · {intel.apps.toLocaleString()} apps
    </span>
  );
}
