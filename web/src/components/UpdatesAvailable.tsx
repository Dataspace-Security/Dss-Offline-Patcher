import { Link } from "react-router-dom";
import { paths } from "../paths";
import type { CatalogLink, IntelSummary } from "../types";
import { Pill, RelTime } from "./ui";

// The per-endpoint "Updates available" list was merged with the catalog
// "Available patches" list into one table: EndpointUpdatesTable in
// AvailablePatches.tsx (P2.6). The shared pieces stay here.

/**
 * Where an available update stands in the offline pipeline. With `latest`
 * (the version the row shows), a link to a package of another version says
 * so, because the package page it opens shows that version.
 */
export function CatalogState({ link, latest }: { link: CatalogLink | null; latest?: string }) {
  if (!link) return <span className="muted" title="Not imported yet: use Import on Patches → Needed">not imported</span>;
  const label = { approved: "in catalog · approved", quarantined: "in catalog · awaiting approval" }[link.state] ?? `in catalog · ${link.state}`;
  const other = !!link.version && !!latest && link.version !== latest;
  return (
    <>
      <Link to={paths.catalog(link.package_id)} title={link.version ? `Opens package ${link.package_id}, version ${link.version}` : undefined}>
        <Pill state={link.state} label={label} />
      </Link>
      {other && <div className="small text-amber">package is version {link.version}, not {latest}</div>}
    </>
  );
}

export function IntelSource({ intel }: { intel: IntelSummary | null | undefined }) {
  if (!intel) return null;
  return (
    <span className="muted">
      update intelligence from <RelTime value={intel.generated_at} /> · {intel.windows} Windows builds · {intel.apps.toLocaleString()} apps
    </span>
  );
}
