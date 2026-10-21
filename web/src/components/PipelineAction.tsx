import { Link } from "react-router-dom";
import { enc } from "../api";
import { useCan } from "../auth";
import { paths } from "../paths";
import type { AcquisitionRequestRef, CatalogLink, PackageFleet } from "../types";
import { cantImportReason, type ImportInfo } from "./importability";
import { Pill, RelTime } from "./ui";
import "../patch.css";

/** "Importing… requested 2d ago" / "… seen by acquisition" for an update that is not imported yet. */
export function RequestedNote({ requested }: { requested: AcquisitionRequestRef | null | undefined }) {
  if (!requested) return null;
  if (requested.status === "unsupported" || requested.status === "failed" || requested.status === "stale") return <ImportProblem requested={requested} />;
  const label = { requested: "Importing… requested", seen: "Importing… seen by acquisition", fulfilled: "Imported · arrived" }[requested.status] ?? "Importing… requested";
  return (
    <span className="requested" title={`Acquisition request ${requested.request_id}`}>
      {label} <RelTime value={requested.at} />
    </span>
  );
}

/**
 * "Can't import: <reason>" (never fetchable this way) / "Import failed: <reason>" (may work next time) /
 * "Not picked up: <reason>" (a later acquisition run missed the request; ask again).
 */
export function ImportProblem({ requested }: { requested: AcquisitionRequestRef }) {
  const why = requested.reason?.trim();
  if (requested.status === "stale") {
    return (
      <span className="text-amber small" title={`Acquisition request ${requested.request_id}`}>
        Not picked up{why ? `: ${why}` : ""} <span className="muted"><RelTime value={requested.at} /></span>
      </span>
    );
  }
  if (requested.status === "unsupported") {
    return <span className="text-red small" title={`Acquisition request ${requested.request_id}`}>Can't import{why ? `: ${why}` : ""}</span>;
  }
  return (
    <span className="text-red small" title={`Acquisition request ${requested.request_id}`}>
      Import failed{why ? `: ${why}` : ""} <span className="muted"><RelTime value={requested.at} /></span>
    </span>
  );
}

/** "Can't import: <reason>" for an update the Library or the downloader says cannot be imported. */
export function CantImport({ reason }: { reason: string }) {
  return <span className="text-red small" title="No acquisition request is sent for it">Can't import: {reason}</span>;
}

/**
 * True when an update can be imported: not in the catalog, or its package was
 * rejected (a fresh download gets a new review). Revoked packages stay
 * revoked, and an update the Library says is not importable (or the
 * downloader reported it can never fetch) is not offered.
 */
export function isRequestable(link: CatalogLink | null | undefined, requested?: AcquisitionRequestRef | null, info?: ImportInfo | null): boolean {
  if (cantImportReason(info, requested) !== null) return false;
  return !link || link.state === "rejected";
}

type Props = {
  link: CatalogLink | null;
  requested?: AcquisitionRequestRef | null;
  fleet?: PackageFleet;
  /** Opens the Patch this drawer for the package. */
  onPatch: (packageId: string) => void;
  /** Importable rows: send an acquisition request for this row now (omit to hide the Import button). */
  onRequest?: () => void;
  /** This row's request is in flight. */
  requesting?: boolean;
  /** Any request is in flight (disables the button). */
  disabled?: boolean;
  /** An offpatch agent version: only the super admin (vendor) approves and deploys it. */
  agent?: boolean;
  /** The Library's verdict; "no" shows "Can't import: <reason>" instead of Import / Ask again. */
  importInfo?: ImportInfo | null;
};

function RequestButton({ label, title, onRequest, requesting, disabled }:
  { label: string; title: string; onRequest: () => void; requesting?: boolean; disabled?: boolean }) {
  return (
    <button className="btn btn-sm" onClick={onRequest} disabled={disabled || requesting} title={title}>
      {requesting ? "Sending…" : label}
    </button>
  );
}

/**
 * The one next action for an update, by where it stands in the pipeline:
 * not imported → Import (or "Can't import: why" / "Import failed: why · Try again");
 * rejected → state + Import again; revoked → cannot be imported again;
 * quarantined → Review & approve (Users and Admins) or Awaiting approval;
 * approved → Patch this…; deploying → the deployment.
 */
export function PipelineAction({ link, requested, fleet, onPatch, onRequest, requesting, disabled, agent = false, importInfo }: Props) {
  const isUser = useCan("user");
  const isSuper = useCan("super_admin");
  const canApprove = agent ? isSuper : isUser;
  const canDeploy = agent ? isSuper : isUser;
  const canRequest = !!onRequest && canDeploy;
  const unsupported = requested?.status === "unsupported";
  const failed = requested?.status === "failed";
  const cant = cantImportReason(importInfo, requested);
  if (!link && cant !== null) {
    return <div className="row-action"><CantImport reason={cant} /></div>;
  }
  if (!link) {
    return (
      <div className="row-action">
        <RequestedNote requested={requested} />
        {canRequest && !unsupported && (
          <RequestButton label={failed ? "Try again" : requested ? "Ask again" : "Import"} onRequest={onRequest!} requesting={requesting} disabled={disabled}
                         title={failed
                           ? "Send a new acquisition request; the last download failed but may work now"
                           : requested
                           ? "Send a new acquisition request for this update"
                           : "Download this update in the acquisition zone; it is verified, signed and comes back here for approval"} />
        )}
        {!canRequest && !requested && <span className="muted small">not imported</span>}
      </div>
    );
  }
  if (link.state === "revoked") {
    return (
      <div className="row-action">
        <Link to={paths.catalog(link.package_id)}><Pill state="revoked" /></Link>
        <span className="muted small" title="A revoked package is a security decision: a new download of the same package is not accepted">
          Revoked — cannot be imported again
        </span>
      </div>
    );
  }
  if (link.state === "rejected") {
    return (
      <div className="row-action">
        <Link to={paths.catalog(link.package_id)}><Pill state="rejected" /></Link>
        {cant !== null ? <CantImport reason={cant} /> : requested && requested.status !== "fulfilled" && <RequestedNote requested={requested} />}
        {canRequest && !unsupported && cant === null && (
          <RequestButton label={failed ? "Try again" : "Import again"} onRequest={onRequest!} requesting={requesting} disabled={disabled}
                         title="The previous package was rejected; import a fresh download for a new review" />
        )}
      </div>
    );
  }
  if (fleet?.active_deployment_id) {
    return (
      <div className="row-action">
        <Link className="btn btn-sm" to={`/deployments/${enc(fleet.active_deployment_id)}`}>Deploying →</Link>
      </div>
    );
  }
  if (link.state === "quarantined") {
    return (
      <div className="row-action">
        {canApprove
          ? <button className="btn btn-sm btn-primary" onClick={() => onPatch(link.package_id)}>Review &amp; approve</button>
          : <Link to={paths.catalog(link.package_id)}><Pill state="quarantined" label="awaiting approval" /></Link>}
      </div>
    );
  }
  // No machine needs it (up to date, app not installed or not applicable):
  // nothing to install, so no Patch this.
  if (link.state === "approved" && fleet && (fleet.needed ?? 0) === 0 && !fleet.active_deployment_id) {
    return (
      <div className="row-action">
        <Link to={paths.catalog(link.package_id)} title="No machine needs this package: up to date, app not installed or not applicable everywhere">
          <Pill state="approved" label="nothing to install" />
        </Link>
      </div>
    );
  }
  if (link.state === "approved") {
    return (
      <div className="row-action">
        {canDeploy
          ? <button className="btn btn-sm btn-primary" onClick={() => onPatch(link.package_id)}>Patch this…</button>
          : <Link to={paths.catalog(link.package_id)}><Pill state="approved" label="ready" /></Link>}
      </div>
    );
  }
  return (
    <div className="row-action">
      <Link to={paths.catalog(link.package_id)}><Pill state={link.state} /></Link>
    </div>
  );
}
