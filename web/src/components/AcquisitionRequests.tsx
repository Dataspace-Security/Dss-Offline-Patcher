import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useCan } from "../auth";
import { paths } from "../paths";
import type { AcquisitionRequestItem, AcquisitionRequestRecord } from "../types";
import { acqStatusPill, showsReason } from "./AcqRequestStatus";
import { RequestResultBanner } from "./RequestResultBanner";
import { useImportRequest } from "./useImportRequest";
import { Empty, Mono, Pill, RelTime, Time, expandRowProps } from "./ui";
import "../ops.css";

/**
 * Tracked acquisition requests (P2.3): who exported what, whether the
 * downloader saw it, and which items arrived as packages.
 */
export function AcquisitionRequests({ data, error, onChanged }: {
  data: AcquisitionRequestRecord[] | null; error: string | null; onChanged?: () => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const canRequest = useCan("user");
  const imp = useImportRequest(onChanged);
  // "Ask again" for one item that was not picked up / failed: a new request for just that item.
  const askAgain = (i: AcquisitionRequestItem, busyKey: string) =>
    void imp.send({ apps: i.kind === "app" ? [i.key] : [], kbs: i.kind === "kb" ? [i.key] : [] }, busyKey);
  return (
    <section className="section">
      <div className="section-head">
        <h3>Acquisition requests {data && <span className="muted">· {data.length}</span>}</h3>
        <span>
          <Link className="btn btn-sm" to={paths.needed()}>What the fleet needs →</Link>{" "}
          <Link className="btn btn-sm" to={paths.library()}>Find software in the Library →</Link>
        </span>
      </div>
      <div className="hint">
        Every Import you send. <b>Seen</b> = the acquisition team's downloader reported working on it; <b>arrived</b> = it came back
        in a checked bundle and is in the Catalog; <b>not picked up</b> = a later download run missed it (ask again);
        <b>can't import</b> = it cannot be fetched this way; <b>import failed</b> = the last download failed and can be tried again.
      </div>
      {error && <div className="banner banner-warn">Request tracking is unavailable: {error}</div>}
      {imp.error && <div className="banner banner-error">Import failed: {imp.error}</div>}
      {imp.result && <RequestResultBanner req={imp.result} onDismiss={imp.dismiss} />}
      {data && data.length === 0 && <Empty>Nothing imported yet. Use Import on <Link to={paths.needed()}>Needed</Link> or in the <Link to={paths.library()}>Library</Link>.</Empty>}
      {data && data.length > 0 && (
        <table className="table">
          <thead><tr><th>Request</th><th>By</th><th>Exported</th><th>Seen by downloader</th><th>Items</th><th>Progress</th></tr></thead>
          <tbody>
            {data.map((r) => {
              const items = r.items ?? [];
              const fulfilled = items.filter((i) => i.status === "fulfilled").length;
              const stale = items.filter((i) => i.status === "stale").length;
              const isOpen = open === r.request_id;
              return (
                <Fragment key={r.request_id}>
                  <tr {...expandRowProps(isOpen, () => setOpen(isOpen ? null : r.request_id))}>
                    <td><span className="caret" aria-hidden="true">{isOpen ? "▾" : "▸"}</span> <Mono>{r.request_id}</Mono></td>
                    <td>{r.created_by || <span className="muted">—</span>}</td>
                    <td className="nowrap"><Time value={r.created_at} /></td>
                    <td className="nowrap">{r.seen_at ? <RelTime value={r.seen_at} /> : <span className="muted">not yet</span>}</td>
                    <td>
                      {items.slice(0, 4).map((i) => <span key={i.kind + i.key} className="tag">{i.key}{i.version ? ` ${i.version}` : ""}</span>)}
                      {items.length > 4 && <span className="muted">+{items.length - 4} more</span>}
                    </td>
                    <td className="nowrap">
                      <Pill state={fulfilled === items.length && items.length > 0 ? "verified" : r.seen_at ? "active" : "pending"}
                            label={`${fulfilled} / ${items.length} arrived`} />
                      {stale > 0 && <div className="cell-sub text-amber">{stale} not picked up</div>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="expand">
                      <td colSpan={6}>
                        <table className="table table-compact">
                          <thead><tr><th>Type</th><th>Item</th><th>Version</th><th>Status</th><th>Arrived</th><th>Package</th>{canRequest && <th />}</tr></thead>
                          <tbody>
                            {items.map((i) => {
                              const s = acqStatusPill(i.status);
                              return (
                                <tr key={i.kind + i.key + i.version}>
                                  <td><span className="tag">{i.kind === "kb" ? "Windows" : "App"}</span></td>
                                  <td><Mono>{i.key}</Mono></td>
                                  <td><Mono>{i.version || "—"}</Mono></td>
                                  <td title={s.help}>
                                    <Pill state={s.pill} label={s.label} />
                                    {i.reason && showsReason(i.status) && <div className="cell-sub">{i.reason}</div>}
                                  </td>
                                  <td className="nowrap">{i.fulfilled_at ? <RelTime value={i.fulfilled_at} /> : <span className="muted">—</span>}</td>
                                  <td>{i.package_id ? <Link to={paths.catalog(i.package_id)}><Mono>{i.package_id}</Mono></Link> : <span className="muted">—</span>}</td>
                                  {canRequest && (
                                    <td className="right">
                                      {(i.status === "stale" || i.status === "failed") && (
                                        <button className="btn btn-sm" disabled={imp.busy !== null}
                                                title="Send a new request for this item to the acquisition team"
                                                onClick={() => askAgain(i, `${r.request_id}:${i.kind}:${i.key}`)}>
                                          {imp.busy === `${r.request_id}:${i.kind}:${i.key}` ? "Sending…" : i.status === "stale" ? "Ask again" : "Try again"}
                                        </button>
                                      )}
                                    </td>
                                  )}
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                        {r.intel_generated_at && <div className="cell-sub">Based on update intelligence generated <Time value={r.intel_generated_at} hideRel />.</div>}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
