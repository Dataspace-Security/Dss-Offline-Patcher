import { useEffect } from "react";
import { Link } from "react-router-dom";
import { api, enc } from "../api";
import type { Endpoint, Package, PackageFleet } from "../types";
import { useLoad } from "../util";
import { stageIndexFor } from "./patchPlan";
import { Pill } from "./ui";
import { stageLabel } from "./deployLabels";
import { isExePackage } from "./exeParts";

type RingDraft = { name: string; groups: string };

const split = (s: string) => s.split(",").map((g) => g.trim()).filter(Boolean);

// Mirrors the server's targeting (internal/store/deployments.go ringFor +
// applicable): an endpoint belongs to the FIRST stage whose groups match one
// of its groups (or "all"), and is then checked against the package's
// applicability. What the endpoint already has comes from the server
// (GET /api/packages-needs: needed / up to date / not installed per endpoint).
// Not modelled here: active exceptions and app-store-managed apps, which the
// server also skips when it assigns targets — hence "unless an exception
// covers it" in the wording.

/** First agent release that runs EXE packages (manifest.MinAgentVersionExe). */
const MIN_AGENT_EXE = "0.9.0";

/** a < b for dotted versions ("0.6.5" < "0.9.0"); unknown versions are not "older". */
function olderVersion(a: string, b: string): boolean {
  const pa = a.replace(/^v/i, "").split(/[.+-]/).map((x) => parseInt(x, 10));
  const pb = b.split(".").map((x) => parseInt(x, 10));
  if (!a || Number.isNaN(pa[0])) return false;
  for (let i = 0; i < pb.length; i++) {
    const x = Number.isNaN(pa[i] ?? NaN) ? 0 : pa[i];
    if (x !== pb[i]) return x < pb[i];
  }
  return false;
}

/** Windows 10/11 and Server builds by release name (KB numbers are shared across some of them). */
const BUILD_NAMES: Record<number, string> = {
  19044: "10 21H2", 19045: "10 22H2", 20348: "Server 2022", 22621: "11 22H2", 22631: "11 23H2", 26100: "11 24H2 / Server 2025", 26200: "11 25H2",
};
function buildName(b: number): string {
  return BUILD_NAMES[b] ? `${BUILD_NAMES[b]} (build ${b})` : `build ${b}`;
}
function buildRange(min: number, max: number): string {
  if (min > 0 && min === max) return buildName(min);
  if (min > 0 && max > 0) return `builds ${min}–${max}`;
  return min > 0 ? `build ${min} or later` : `build ${max} or earlier`;
}

function notApplicable(p: Package, e: Endpoint): string | null {
  const a = p.applicability;
  if (isExePackage(p) && olderVersion(e.agent_version ?? "", MIN_AGENT_EXE)) return `agent ${e.agent_version} too old for EXE packages (upgrade the agent to ${MIN_AGENT_EXE} or later)`;
  if (a.os && e.os && a.os.toLowerCase() !== e.os.toLowerCase()) return `${e.os} endpoint, ${a.os} package`;
  if (a.arch && a.arch !== "any" && a.arch !== e.arch) return `arch ${e.arch} ≠ ${a.arch}`;
  if ((a.min_build > 0 && e.build < a.min_build) || (a.max_build > 0 && e.build > a.max_build)) {
    return `package is for Windows ${buildRange(a.min_build, a.max_build)}, machine runs ${buildName(e.build)}`;
  }
  const eds = a.editions ?? [];
  if (eds.length && e.edition && !eds.some((x) => x.toLowerCase() === e.edition.toLowerCase())) return `edition ${e.edition} not in ${eds.join(", ")}`;
  return null;
}

/** What the deployment will do on one machine. */
type Outcome = "install" | "install_later" | "up_to_date" | "not_installed" | "not_applicable" | "unknown";

const OUTCOME: Record<Outcome, { state: string; label: string }> = {
  install: { state: "pending", label: "will install (unless an exception covers it)" },
  install_later: { state: "pending", label: "will install when back online (unless an exception covers it)" },
  up_to_date: { state: "verified", label: "already up to date · skipped" },
  not_installed: { state: "not_applicable", label: "app not installed · skipped" },
  not_applicable: { state: "not_applicable", label: "not applicable" },
  unknown: { state: "pending", label: "decided at its next check-in (no inventory yet)" },
};

type TargetPreviewProps = {
  pkg: Package | undefined;
  rings: RingDraft[];
  /** Already loaded by the caller (Patch this): skips this component's own fetch. */
  endpoints?: Endpoint[] | null;
  fleet?: Record<string, PackageFleet> | null;
  /** Told the counts whenever they change (null until the endpoint list is loaded). */
  onSummary?: (s: TargetSummary | null) => void;
};

/** What the live preview found: lets the parent block a deployment that would do nothing. */
export type TargetSummary = {
  /** Machines in the stages. */
  targeted: number;
  /** Machines that will install it (now or when back online). */
  willInstall: number;
  /** Machines decided at their next check-in (no inventory / need data yet). */
  unknown: number;
  /** Machines the package does not apply to (wrong Windows build, architecture, edition), and why. */
  notApplicable?: number;
  naReasons?: string[];
};

/** True when the preview is sure nobody installs it: every machine in the stages is up to date, lacks the app or is not applicable. */
export function nothingToDo(s: TargetSummary | null | undefined): boolean {
  return !!s && s.targeted > 0 && s.willInstall + s.unknown === 0;
}

/** Live "which machines get this, and what happens on each?" preview for the deployment form and Patch this. */
export function TargetPreview({ pkg, rings, endpoints, fleet: fleetProp, onSummary }: TargetPreviewProps) {
  const ownEps = endpoints === undefined;
  const ownFleet = fleetProp === undefined;
  const epsL = useLoad(() => (ownEps ? api.get<Endpoint[]>("/api/endpoints") : Promise.resolve(null)), [ownEps]);
  const fleetL = useLoad(() => (ownFleet ? api.get<Record<string, PackageFleet>>("/api/packages-needs") : Promise.resolve(null)), [ownFleet]);
  const eps = ownEps ? epsL.data : endpoints;
  const fleetData = ownFleet ? fleetL.data : fleetProp;
  const view = eps ? buildView(pkg, rings, eps, fleetData) : null;
  const sTargeted = view ? view.targeted.length : -1;
  const sWill = view ? view.willInstall : -1;
  const sUnknown = view ? view.unknown : -1;
  const naRows = view ? view.targeted.filter((r) => r.outcome === "not_applicable") : [];
  const sNA = naRows.length;
  const sReasons = Array.from(new Set(naRows.map((r) => r.na ?? ""))).filter(Boolean).sort().join("|");
  useEffect(() => {
    onSummary?.(sTargeted < 0 ? null : { targeted: sTargeted, willInstall: sWill, unknown: sUnknown, notApplicable: sNA, naReasons: sReasons ? sReasons.split("|") : [] });
  }, [sTargeted, sWill, sUnknown, sNA, sReasons]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => () => onSummary?.(null), []); // eslint-disable-line react-hooks/exhaustive-deps
  if (!view) return null;
  return <PreviewBody pkg={pkg} rings={rings} {...view} />;
}

type PreviewRow = { e: Endpoint; ring: number; na: string | null; outcome: Outcome };
type PreviewView = {
  targeted: PreviewRow[]; willInstall: number; skipped: number; unknown: number; missed: PreviewRow[]; allGroups: string[];
  /** Lower-cased host names used by more than one endpoint id. */
  dupNames: Set<string>;
};

function buildView(pkg: Package | undefined, rings: RingDraft[], eps: Endpoint[], fleetData: Record<string, PackageFleet> | null | undefined): PreviewView {
  const pf = pkg ? fleetData?.[pkg.package_id] : undefined;
  const needed = new Set(pf?.endpoint_ids ?? []);
  const upToDate = new Set(pf?.up_to_date_ids ?? []);
  const notInstalled = new Set(pf?.not_installed_ids ?? []);
  const stageGroups = rings.map((r) => ({ groups: split(r.groups) }));

  // One row per endpoint id (a list that names a machine twice must not count it twice).
  const seen = new Set<string>();
  const active = eps.filter((e) => e.status !== "retired" && !seen.has(e.endpoint_id) && (seen.add(e.endpoint_id), true));
  const rows = active.map((e) => {
    const ring = stageIndexFor(stageGroups, e);
    const na = pkg && ring >= 0 ? notApplicable(pkg, e) : null;
    let outcome: Outcome = "unknown";
    if (na) outcome = "not_applicable";
    else if (needed.has(e.endpoint_id)) outcome = e.status === "offline" || e.status === "stale" ? "install_later" : "install";
    else if (upToDate.has(e.endpoint_id)) outcome = "up_to_date";
    else if (notInstalled.has(e.endpoint_id)) outcome = "not_installed";
    return { e, ring, na, outcome };
  });
  const targeted = rows.filter((r) => r.ring >= 0);
  const count = (o: Outcome[]) => targeted.filter((r) => o.includes(r.outcome)).length;
  const willInstall = count(["install", "install_later"]);
  const skipped = count(["up_to_date", "not_installed", "not_applicable"]);
  const unknown = count(["unknown"]);
  const missed = rows.filter((r) => r.ring < 0);
  const allGroups = Array.from(new Set(active.flatMap((e) => e.groups ?? []))).sort();
  const byName = new Map<string, number>();
  for (const e of active) byName.set(e.hostname.toLowerCase(), (byName.get(e.hostname.toLowerCase()) ?? 0) + 1);
  const dupNames = new Set([...byName].filter(([, n]) => n > 1).map(([h]) => h));
  return { targeted, willInstall, skipped, unknown, missed, allGroups, dupNames };
}

const SHORT_ID = 8;

/** Host name; two different machines with the same name also show their short id and a "duplicate name" badge. */
function MachineName({ e, dup, link = true }: { e: Endpoint; dup: boolean; link?: boolean }) {
  const name = link ? <Link to={`/endpoints/${enc(e.endpoint_id)}`}>{e.hostname}</Link> : <>{e.hostname}</>;
  if (!dup) return name;
  return (
    <>
      {name} <code className="mono muted" title={e.endpoint_id}>{e.endpoint_id.slice(0, SHORT_ID)}</code>{" "}
      <span className="tag text-amber" title="Two enrolled machines report this host name; they are different endpoints">duplicate name</span>
    </>
  );
}

function PreviewBody({ pkg, rings, targeted, willInstall, skipped, unknown, missed, allGroups, dupNames }:
  PreviewView & { pkg: Package | undefined; rings: RingDraft[] }) {
  return (
    <fieldset className="fieldset target-preview">
      <legend>Which machines get this patch? <span className="muted">— live preview</span></legend>
      {!pkg && <div className="hint">Choose a package to see what happens on each machine.</div>}
      {pkg && targeted.length === 0 && (
        <div className="banner banner-error">
          <b>No machine is in these stages.</b> Groups in use: {allGroups.length ? allGroups.map((g) => <span key={g} className="tag">{g}</span>) : "none"} — or use <span className="tag">all</span>.
        </div>
      )}
      {pkg && targeted.length > 0 && (
        <div className={`banner ${willInstall + unknown > 0 ? "banner-ok" : "banner-warn"}`}>
          <b>{willInstall}</b> machine{willInstall === 1 ? "" : "s"} will install it (unless an exception covers {willInstall === 1 ? "it" : "them"})
          {skipped > 0 && <> · {skipped} skipped (already up to date, app not installed or not applicable)</>}
          {unknown > 0 && <> · {unknown} decided at their next check-in</>}
          {missed.length > 0 && <> · {missed.length} not in any stage</>}.
          {willInstall + unknown === 0 && <> Nothing to do: every machine in these stages is up to date or doesn't have the app.</>}
        </div>
      )}
      {targeted.length > 0 && (
        <div className="table-scroll">
        <table className="table table-compact">
          <thead><tr><th>Stage</th><th>Machine</th><th>Groups</th><th>Installed now</th><th>What happens</th></tr></thead>
          <tbody>
            {[...targeted].sort((a, b) => a.ring - b.ring || a.e.hostname.localeCompare(b.e.hostname)).map(({ e, ring, na, outcome }) => (
              <tr key={e.endpoint_id}>
                <td className="nowrap">{stageLabel(rings[ring]?.name, ring)}</td>
                <td><MachineName e={e} dup={dupNames.has(e.hostname.toLowerCase())} /> {e.status === "offline" || e.status === "stale" ? <span className="muted">({e.status})</span> : null}</td>
                <td>{(e.groups ?? []).map((g) => <span key={g} className="tag">{g}</span>)}</td>
                <td className="muted">{e.os_version || e.os}</td>
                <td><Pill state={OUTCOME[outcome].state} label={na ? `not applicable: ${na}` : OUTCOME[outcome].label} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}
      {missed.length > 0 && (
        <details>
          <summary className="muted">{missed.length} machine{missed.length === 1 ? " is" : "s are"} not in any stage (not touched)</summary>
          <ul className="plain">
            {missed.map(({ e }) => (
              <li key={e.endpoint_id}><MachineName e={e} dup={dupNames.has(e.hostname.toLowerCase())} link={false} /> <span className="muted">({e.os})</span> — groups {(e.groups ?? []).map((g) => <span key={g} className="tag">{g}</span>)}</li>
            ))}
          </ul>
        </details>
      )}
      <div className="hint">
        Third-party apps are only updated where they are installed; they are never installed on new machines.
        The server also skips machines covered by an active exception and apps managed by an app store when it assigns the deployment.
      </div>
    </fieldset>
  );
}
