import { Link } from "react-router-dom";
import { enc } from "../api";
import { useCan } from "../auth";
import { paths } from "../paths";
import type { AcquisitionRequestRef, CatalogLink, PackageFleet } from "../types";
import { Pill, RelTime } from "./ui";
import "../patch.css";

/** "requested 2d ago · seen" for an update that is not imported yet. */
export function RequestedNote({ requested }: { requested: AcquisitionRequestRef | null | undefined }) {
  if (!requested) return null;
  const label = { requested: "requested", seen: "requested · seen by acquisition", fulfilled: "requested · arrived" }[requested.status] ?? "requested";
  return (
    <span className="requested" title={`Acquisition request ${requested.request_id}`}>
      {label} <RelTime value={requested.at} />
    </span>
  );
}

type Props = {
  link: CatalogLink | null;
  requested?: AcquisitionRequestRef | null;
  fleet?: PackageFleet;
  /** Opens the Patch this drawer for the package. */
  onPatch: (packageId: string) => void;
  /** Not imported: toggle the row in the acquisition-request selection (omit to hide). */
  selected?: boolean;
  onSelect?: () => void;
};

/**
 * The one next action for an update, by where it stands in the pipeline:
 * not imported → select / request; quarantined → Review & approve (approvers)
 * or Awaiting approval; approved → Patch this…; deploying → the deployment.
 */
export function PipelineAction({ link, requested, fleet, onPatch, selected, onSelect }: Props) {
  const canApprove = useCan("approver");
  const canDeploy = useCan("operator");
  if (!link) {
    return (
      <div className="row-action">
        <RequestedNote requested={requested} />
        {onSelect && canDeploy && (
          <button className={`btn btn-sm ${selected ? "btn-primary" : ""}`} onClick={onSelect}
                  title="Add to the acquisition request to export">
            {selected ? "Selected" : requested ? "Request again" : "Request"}
          </button>
        )}
        {!onSelect && !requested && <span className="muted small">not imported</span>}
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
