import { Link } from "react-router-dom";
import { paths } from "../paths";
import type { AcquisitionRequest } from "../types";
import { Mono } from "./ui";

/** Display names of what a request lists ("7-Zip, KB5034441, …"). */
export function requestNames(req: AcquisitionRequest): string {
  const names = [...req.apps.map((a) => a.name || a.winget_id), ...req.kbs.map((k) => k.kb)];
  return names.join(", ");
}

/**
 * Result of POST /api/acquisition-requests. queued_to non-empty: the server put
 * the request straight into the acquisition host's requests folder. Empty:
 * strict one-way transfer, the downloaded file must be carried there.
 */
export function RequestResultBanner({ req, onDismiss }: { req: AcquisitionRequest; onDismiss: () => void }) {
  const names = requestNames(req);
  const dismiss = <>{" "}<button className="btn btn-sm" onClick={onDismiss}>Dismiss</button></>;
  if (req.queued_to) {
    return (
      <div className="banner banner-ok" title={`Queued to ${req.queued_to}`}>
        Queued for download: <b>{names}</b>. The acquisition zone downloads and checks it and sends it back here; the row shows
        <i> requested → seen → arrived</i>, then approve it in the <Link to={paths.catalog()}>Catalog</Link>.
        {" "}Follow it on <Link to={paths.imports}>Imports</Link>.{dismiss}
      </div>
    );
  }
  return (
    <div className="banner banner-info">
      This server cannot send anything out, so the request was saved as a file: <Mono>{req.request_id}.json</Mono> (lists {names}).
      Give it to the acquisition team on approved media. The packages come back in a signed bundle; the row then shows
      <i> requested → seen → arrived</i> and you approve them in the Catalog.
      {" "}Follow it on <Link to={paths.imports}>Imports</Link>.{dismiss}
    </div>
  );
}
