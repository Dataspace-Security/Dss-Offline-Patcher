import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { paths } from "../paths";
import type { AcquisitionRequestRecord } from "../types";
import { acqStatusPill } from "./AcqRequestStatus";
import { Empty, Mono, Pill, RelTime, Time, expandRowProps } from "./ui";
import "../ops.css";

/**
 * Tracked acquisition requests (P2.3): who exported what, whether the
 * downloader saw it, and which items arrived as packages.
 */
export function AcquisitionRequests({ data, error }: { data: AcquisitionRequestRecord[] | null; error: string | null }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <section className="section">
      <div className="section-head">
        <h3>Acquisition requests {data && <span className="muted">· {data.length}</span>}</h3>
        <Link className="btn btn-sm" to={paths.updates()}>Request updates on Updates →</Link>
      </div>
      <div className="hint">
        Requests exported on the Updates tab and carried to the acquisition zone. <b>Seen</b> = the downloader's signed status
        report listed the request; <b>arrived</b> = a validated bundle contained the update (then it is in the catalog).
      </div>
      {error && <div className="banner banner-warn">Request tracking is unavailable: {error}</div>}
      {data && data.length === 0 && <Empty>No acquisition request exported yet. On <Link to={paths.updates()}>Updates</Link>, select updates that are not imported and export a request.</Empty>}
      {data && data.length > 0 && (
        <table className="table">
          <thead><tr><th>Request</th><th>By</th><th>Exported</th><th>Seen by downloader</th><th>Items</th><th>Progress</th></tr></thead>
          <tbody>
            {data.map((r) => {
              const items = r.items ?? [];
              const fulfilled = items.filter((i) => i.status === "fulfilled").length;
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
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="expand">
                      <td colSpan={6}>
                        <table className="table table-compact">
                          <thead><tr><th>Type</th><th>Item</th><th>Version</th><th>Status</th><th>Arrived</th><th>Package</th></tr></thead>
                          <tbody>
                            {items.map((i) => {
                              const s = acqStatusPill(i.status);
                              return (
                                <tr key={i.kind + i.key + i.version}>
                                  <td><span className="tag">{i.kind === "kb" ? "Windows" : "App"}</span></td>
                                  <td><Mono>{i.key}</Mono></td>
                                  <td><Mono>{i.version || "—"}</Mono></td>
                                  <td title={s.help}><Pill state={s.pill} label={s.label} /></td>
                                  <td className="nowrap">{i.fulfilled_at ? <RelTime value={i.fulfilled_at} /> : <span className="muted">—</span>}</td>
                                  <td>{i.package_id ? <Link to={paths.catalog(i.package_id)}><Mono>{i.package_id}</Mono></Link> : <span className="muted">—</span>}</td>
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
