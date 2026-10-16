import { Fragment, useState } from "react";
import { api } from "../api";
import { Empty, ErrorBanner, KV, Mono, PageHeader, Pill, RelTime, Time } from "../components/ui";
import type { Bundle, Reconciliation, TransferReceipt } from "../types";
import { fmtBytes, shortHash, useLoad } from "../util";

export default function Intake() {
  const { data, error, reload } = useLoad(() => api.get<Bundle[]>("/api/bundles"), [], 15000);
  const [open, setOpen] = useState<number | null>(null);
  const recon = useLoad(() => api.get<Reconciliation>("/api/transfer/reconcile"), [], 30000);

  return (
    <>
      <PageHeader title="Intake" sub="Bundles received through the transfer boundary, newest first">
        <button className="btn" onClick={() => { void reload(); void recon.reload(); }}>Refresh</button>
      </PageHeader>
      <ReconciliationPanel r={recon.data} error={recon.error} />
      <h2>Bundles</h2>
      <ErrorBanner error={error} />
      {data && data.length === 0 && <Empty>No bundles received yet.</Empty>}
      {data && data.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 18 }} />
              <th>Received</th><th>Filename</th><th>Bundle ID</th><th>Source</th>
              <th className="num">Seq</th><th>State</th><th className="num">Packages</th>
            </tr>
          </thead>
          <tbody>
            {data.map((b) => {
              const isOpen = open === b.id;
              const failed = (b.checks ?? []).filter((c) => !c.ok).length;
              return (
                <Fragment key={b.id}>
                  <tr className={`clickable ${isOpen ? "selected" : ""}`} onClick={() => setOpen(isOpen ? null : b.id)}>
                    <td className="caret">{isOpen ? "▾" : "▸"}</td>
                    <td><Time value={b.received_at} /></td>
                    <td><Mono>{b.filename}</Mono></td>
                    <td><Mono>{b.bundle_id || "—"}</Mono></td>
                    <td>{b.source || "—"}</td>
                    <td className="num">{b.sequence}</td>
                    <td>
                      <Pill state={b.state} />
                      {failed > 0 && <span className="muted small"> {failed} failed check{failed > 1 ? "s" : ""}</span>}
                    </td>
                    <td className="num">{b.package_count}</td>
                  </tr>
                  {isOpen && (
                    <tr className="expand">
                      <td />
                      <td colSpan={7}>
                        <div className="expand-grid">
                          <div>
                            <h3>Validation checks</h3>
                            {(b.checks ?? []).length === 0 ? <span className="muted">No checks recorded.</span> : (
                              <ul className="checks">
                                {b.checks.map((c, i) => (
                                  <li key={i} className={c.ok ? "ok" : "bad"}>
                                    <span className="check-icon">{c.ok ? "✓" : "✕"}</span>
                                    <span className="check-name" title={c.name === "key_status" ? "Signing key status: retired keys are no longer accepted for new bundles" : undefined}>{c.name}</span>
                                    {c.detail && <span className="check-detail">{c.detail}</span>}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                          <div>
                            <h3>File</h3>
                            <KV rows={[
                              ["Intake ID", String(b.id)],
                              ["SHA-256", <Mono>{b.file_sha256}</Mono>],
                              ["Size", `${fmtBytes(b.file_size)} (${b.file_size.toLocaleString()} bytes)`],
                              ["Key ID", b.key_id ? <Mono>{b.key_id}</Mono> : ""],
                              ["Error", b.error ? <span className="text-red">{b.error}</span> : ""],
                            ]} />
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </>
  );
}

function ReconciliationPanel({ r, error }: { r: Reconciliation | null; error: string | null }) {
  const [tab, setTab] = useState<"missing" | "unreceipted" | "matched">("missing");
  const matched = r?.matched ?? [];
  const missing = r?.receipt_without_bundle ?? [];
  const unreceipted = r?.bundle_without_receipt ?? [];
  const invalid = r?.unsigned_or_invalid_receipts ?? 0;

  return (
    <section className="card section">
      <div className="section-head">
        <h2>Transfer reconciliation <span className="muted">· gateway receipts vs. bundles that arrived</span></h2>
      </div>
      <ErrorBanner error={error} />
      {r && (
        <>
          <div className="tiles tiles-4">
            <button className={`tile tile-btn ${missing.length ? "tile-red tile-alert" : "tile-green"}`} onClick={() => setTab("missing")}>
              <div className="tile-value">{missing.length}</div>
              <div className="tile-label">sent, never arrived</div>
            </button>
            <button className={`tile tile-btn ${unreceipted.length ? "tile-amber" : "tile-green"}`} onClick={() => setTab("unreceipted")}>
              <div className="tile-value">{unreceipted.length}</div>
              <div className="tile-label">arrived without receipt</div>
            </button>
            <button className="tile tile-btn tile-green" onClick={() => setTab("matched")}>
              <div className="tile-value">{matched.length}</div>
              <div className="tile-label">matched</div>
            </button>
            <div className={`tile ${invalid ? "tile-red tile-alert" : "tile-grey"}`}>
              <div className="tile-value">{invalid}</div>
              <div className="tile-label">unsigned / invalid receipts</div>
            </div>
          </div>
          {missing.length > 0 && (
            <div className="banner banner-error" style={{ marginTop: 12 }}>
              <b>{missing.length}</b> file{missing.length === 1 ? " was" : "s were"} sent through the gateway but never arrived here.
              Investigate the transfer path before assuming nothing was lost.
            </div>
          )}
          <div className="tabs" style={{ marginTop: 12 }}>
            <button className={`tab ${tab === "missing" ? "tab-on" : ""}`} onClick={() => setTab("missing")}>Receipt without bundle ({missing.length})</button>
            <button className={`tab ${tab === "unreceipted" ? "tab-on" : ""}`} onClick={() => setTab("unreceipted")}>Bundle without receipt ({unreceipted.length})</button>
            <button className={`tab ${tab === "matched" ? "tab-on" : ""}`} onClick={() => setTab("matched")}>Matched ({matched.length})</button>
          </div>
          {tab === "missing" && <ReceiptTable rows={missing} tone="red" empty="Every receipt has a matching bundle." />}
          {tab === "matched" && <ReceiptTable rows={matched} empty="No matched transfers yet." />}
          {tab === "unreceipted" && (
            unreceipted.length === 0 ? <Empty>Every bundle has a gateway receipt.</Empty> : (
              <table className="table table-compact">
                <thead><tr><th>Received</th><th>Filename</th><th>Bundle ID</th><th>SHA-256</th><th>State</th></tr></thead>
                <tbody>
                  {unreceipted.map((b) => (
                    <tr key={b.id} className="row-warn">
                      <td className="nowrap"><Time value={b.received_at} hideRel /></td>
                      <td><Mono>{b.filename}</Mono></td>
                      <td><Mono>{b.bundle_id || "—"}</Mono></td>
                      <td><Mono title={b.file_sha256}>{shortHash(b.file_sha256)}</Mono></td>
                      <td><Pill state={b.state} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
        </>
      )}
    </section>
  );
}

function ReceiptTable({ rows, tone, empty }: { rows: TransferReceipt[]; tone?: "red"; empty: string }) {
  if (rows.length === 0) return <Empty>{empty}</Empty>;
  return (
    <table className="table table-compact">
      <thead>
        <tr><th>Sent</th><th>Received</th><th>File</th><th>SHA-256</th><th className="num">Size</th><th>Adapter</th><th>Key</th><th>Signature</th></tr>
      </thead>
      <tbody>
        {rows.map((t) => (
          <tr key={t.id} className={tone === "red" ? "row-bad" : ""}>
            <td className="nowrap"><Time value={t.sent_at} hideRel /><div className="cell-sub"><RelTime value={t.sent_at} /></div></td>
            <td className="nowrap">{t.received_at ? <Time value={t.received_at} hideRel /> : <span className="muted">—</span>}</td>
            <td><Mono>{t.file}</Mono></td>
            <td><Mono title={t.file_sha256}>{shortHash(t.file_sha256)}</Mono></td>
            <td className="num nowrap">{fmtBytes(t.size)}</td>
            <td>{t.adapter || <span className="muted">—</span>}</td>
            <td>{t.key_id ? <Mono>{t.key_id}</Mono> : <span className="muted">—</span>}</td>
            <td>{t.signature_ok ? <Pill state="verified" label="valid" /> : <Pill state="failed" label="invalid" />}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
