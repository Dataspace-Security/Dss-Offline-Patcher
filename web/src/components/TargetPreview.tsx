import { api } from "../api";
import type { Endpoint, Package } from "../types";
import { useLoad } from "../util";
import { Pill } from "./ui";

type RingDraft = { name: string; groups: string };

const split = (s: string) => s.split(",").map((g) => g.trim().toLowerCase()).filter(Boolean);

// Mirrors the server's targeting (internal/store/deployments.go ringFor +
// applicable): an endpoint belongs to the FIRST ring whose groups match one
// of its groups (or "all"), and is then checked against the package's
// applicability. Inventory ("already installed") is only known server-side.
function ringFor(rings: RingDraft[], groups: string[], endpointId: string): number {
  for (let i = 0; i < rings.length; i++) {
    const rg = split(rings[i].groups);
    if (rg.includes("all") || rg.some((g) => groups.includes(g) || g === `endpoint:${endpointId}`)) return i;
  }
  return -1;
}

function notApplicable(p: Package, e: Endpoint): string | null {
  const a = p.applicability;
  if (a.os && e.os && a.os.toLowerCase() !== e.os.toLowerCase()) return `${e.os} endpoint, ${a.os} package`;
  if (a.arch && a.arch !== "any" && a.arch !== e.arch) return `arch ${e.arch} ≠ ${a.arch}`;
  if (a.min_build > 0 && e.build < a.min_build) return `build ${e.build} < ${a.min_build}`;
  if (a.max_build > 0 && e.build > a.max_build) return `build ${e.build} > ${a.max_build}`;
  const eds = a.editions ?? [];
  if (eds.length && e.edition && !eds.some((x) => x.toLowerCase() === e.edition.toLowerCase())) return `edition ${e.edition} not in ${eds.join(", ")}`;
  return null;
}

/** Live "who will this deployment reach?" preview for the New deployment form. */
export function TargetPreview({ pkg, rings }: { pkg: Package | undefined; rings: RingDraft[] }) {
  const { data: eps } = useLoad(() => api.get<Endpoint[]>("/api/endpoints"), []);
  if (!eps) return null;
  const active = eps.filter((e) => e.status !== "retired");
  const rows = active.map((e) => {
    const ring = ringFor(rings, e.groups ?? [], e.endpoint_id);
    const na = pkg && ring >= 0 ? notApplicable(pkg, e) : null;
    return { e, ring, na };
  });
  const targeted = rows.filter((r) => r.ring >= 0);
  const willInstall = targeted.filter((r) => !r.na);
  const missed = rows.filter((r) => r.ring < 0);
  const allGroups = Array.from(new Set(active.flatMap((e) => e.groups ?? []))).sort();

  return (
    <fieldset className="fieldset target-preview">
      <legend>Who will receive this patch? <span className="muted">— live preview</span></legend>
      {!pkg && <div className="hint">Choose a package to check applicability.</div>}
      {pkg && willInstall.length === 0 && (
        <div className="banner banner-error">
          <b>No endpoint will install this patch.</b>{" "}
          {targeted.length === 0
            ? <>No endpoint is in the groups of these rings.</>
            : <>The targeted endpoints are not applicable ({pkg.applicability.os} package).</>}{" "}
          Groups in use: {allGroups.length ? allGroups.map((g) => <span key={g} className="tag">{g}</span>) : "none"} — or use <span className="tag">all</span>.
        </div>
      )}
      {pkg && willInstall.length > 0 && (
        <div className="banner banner-ok">
          <b>{willInstall.length}</b> endpoint{willInstall.length === 1 ? "" : "s"} will install it
          {targeted.length > willInstall.length && <> · {targeted.length - willInstall.length} targeted but not applicable</>}
          {missed.length > 0 && <> · {missed.length} not in any ring</>}.
        </div>
      )}
      {targeted.length > 0 && (
        <table className="table table-compact">
          <thead><tr><th>Ring</th><th>Endpoint</th><th>OS</th><th>Groups</th><th>Result</th></tr></thead>
          <tbody>
            {targeted.sort((a, b) => a.ring - b.ring || a.e.hostname.localeCompare(b.e.hostname)).map(({ e, ring, na }) => (
              <tr key={e.endpoint_id}>
                <td>{ring + 1}. {rings[ring]?.name || "—"}</td>
                <td>{e.hostname}</td>
                <td>{e.os}</td>
                <td>{(e.groups ?? []).map((g) => <span key={g} className="tag">{g}</span>)}</td>
                <td>{na ? <Pill state="not_applicable" label={`not applicable: ${na}`} /> : <Pill state="pending" label="will install" />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {missed.length > 0 && (
        <details>
          <summary className="muted">{missed.length} endpoint{missed.length === 1 ? " is" : "s are"} not in any ring</summary>
          <ul className="plain">
            {missed.map(({ e }) => (
              <li key={e.endpoint_id}>{e.hostname} <span className="muted">({e.os})</span> — groups {(e.groups ?? []).map((g) => <span key={g} className="tag">{g}</span>)}</li>
            ))}
          </ul>
        </details>
      )}
      <div className="hint">Endpoints that already have this version show as <b>verified</b> right after the deployment is created.</div>
    </fieldset>
  );
}
