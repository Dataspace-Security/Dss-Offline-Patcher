import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { api, downloadFileNamed, errMsg, qs } from "../api";
import { Empty, ErrorBanner, Mono, PageHeader, Pill, Time } from "../components/ui";
import type { AuditEvent, AuditVerify } from "../types";

const PAGE = 200;

/** Local calendar date as YYYY-MM-DD. */
function ymd(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
type Filters = { actor: string; action: string; object_id: string; package_id: string };
const KEYS: (keyof Filters)[] = ["actor", "action", "object_id", "package_id"];

export default function Audit() {
  const [sp, setSp] = useSearchParams();
  const applied: Filters = {
    actor: sp.get("actor") ?? "", action: sp.get("action") ?? "",
    object_id: sp.get("object_id") ?? "", package_id: sp.get("package_id") ?? "",
  };
  const appliedKey = KEYS.map((k) => applied[k]).join("\u0000");
  const [draft, setDraft] = useState<Filters>(applied);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [exportId, setExportId] = useState(applied.package_id);
  const [exportMsg, setExportMsg] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  // Audit log PDF for a period (default: this month so far).
  const [pdfFrom, setPdfFrom] = useState(() => { const n = new Date(); return ymd(new Date(n.getFullYear(), n.getMonth(), 1)); });
  const [pdfTo, setPdfTo] = useState(() => ymd(new Date()));
  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfMsg, setPdfMsg] = useState<string | null>(null);

  const load = async (before?: number) => {
    setLoading(true);
    setError(null);
    try {
      const page = await api.get<AuditEvent[]>(`/api/audit${qs({ ...applied, limit: PAGE, before_seq: before })}`);
      setEvents((prev) => (before ? [...prev, ...page] : page));
      setMore(page.length >= PAGE);
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setDraft(applied);
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appliedKey]);

  const apply = (e: FormEvent) => {
    e.preventDefault();
    const next: Record<string, string> = {};
    for (const k of KEYS) if (draft[k].trim()) next[k] = draft[k].trim();
    setSp(next);
  };

  const runVerify = async () => {
    setVerifying(true);
    try {
      setVerify(await api.get<AuditVerify>("/api/audit/verify"));
    } catch (e) {
      setVerify({ ok: false, count: 0, first_bad_seq: 0, error: errMsg(e) });
    } finally {
      setVerifying(false);
    }
  };

  const runExport = async (e: FormEvent) => {
    e.preventDefault();
    const id = exportId.trim();
    if (!id) return;
    setExporting(true);
    setExportMsg(null);
    try {
      const blob = await api.blob(`/api/audit/export${qs({ package_id: id })}`);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `lifecycle-${id.replace(/[^A-Za-z0-9._-]/g, "_")}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setExportMsg(`Downloaded lifecycle-${id}.json`);
    } catch (err) {
      setExportMsg(`Export failed: ${errMsg(err)}`);
    } finally {
      setExporting(false);
    }
  };

  const downloadPdf = async (e: FormEvent) => {
    e.preventDefault();
    if (!pdfFrom || !pdfTo || pdfFrom > pdfTo) return;
    setPdfBusy(true);
    setPdfMsg(null);
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const name = await downloadFileNamed(`/api/audit.pdf${qs({ from: pdfFrom, to: pdfTo, tz })}`, `DSS-Patcher-audit-log-${pdfFrom}_${pdfTo}.pdf`);
      setPdfMsg(`Downloaded ${name}`);
    } catch (err) {
      setPdfMsg(`PDF failed: ${errMsg(err)}`);
    } finally {
      setPdfBusy(false);
    }
  };

  const lastSeq = events.length ? events[events.length - 1].seq : undefined;
  const anyFilter = KEYS.some((k) => applied[k]);

  return (
    <>
      <PageHeader title="Audit" sub="Hash-chained, append-only event log, newest first">
        <button className="btn" onClick={runVerify} disabled={verifying}>{verifying ? "Verifying…" : "Verify chain"}</button>
      </PageHeader>

      {verify && (
        verify.ok
          ? <div className="banner banner-ok"><b>Chain intact.</b> {verify.count} events verified.</div>
          : <div className="banner banner-error">
              <b>Chain BROKEN.</b>{verify.first_bad_seq ? <> First bad link at seq <b>{verify.first_bad_seq}</b>.</> : null}
              {verify.count ? <> {verify.count} events checked.</> : null} {verify.error}
            </div>
      )}

      <div className="grid-2 audit-tools">
        <form className="card filters-card" onSubmit={apply}>
          <div className="form-grid form-grid-4">
            {KEYS.map((k) => (
              <label key={k} className="field">
                <span>{k.replace("_", " ")}</span>
                <input value={draft[k]} onChange={(e) => setDraft({ ...draft, [k]: e.target.value })} />
              </label>
            ))}
          </div>
          <div className="form-actions">
            {anyFilter && <button type="button" className="btn" onClick={() => setSp({})}>Clear</button>}
            <button className="btn btn-primary">Apply filters</button>
          </div>
        </form>
        <form className="card" onSubmit={runExport}>
          <label className="field">
            <span>Export lifecycle (package_id)</span>
            <div className="copybox">
              <input className="mono" value={exportId} onChange={(e) => setExportId(e.target.value)} placeholder="package_id" />
              <button className="btn" disabled={!exportId.trim() || exporting}>{exporting ? "Exporting…" : "Download JSON"}</button>
            </div>
          </label>
          <div className="hint">Package, bundle, deployments, exceptions and every audit event for one package, with chain status.</div>
          {exportMsg && <div className={exportMsg.startsWith("Export failed") ? "text-red small" : "text-green small"}>{exportMsg}</div>}
        </form>
        <form className="card" onSubmit={downloadPdf}>
          <div className="form-grid">
            <label className="field"><span>Audit log from</span><input type="date" value={pdfFrom} max={pdfTo || undefined} onChange={(e) => setPdfFrom(e.target.value)} /></label>
            <label className="field"><span>To</span><input type="date" value={pdfTo} min={pdfFrom || undefined} onChange={(e) => setPdfTo(e.target.value)} /></label>
          </div>
          <div className="form-actions">
            <button className="btn" disabled={pdfBusy || !pdfFrom || !pdfTo || pdfFrom > pdfTo}>{pdfBusy ? "Preparing…" : "Download PDF"}</button>
          </div>
          <div className="hint">Every audit event of the period with the chain status, as a PDF made by the server (audited).</div>
          {pdfMsg && <div className={pdfMsg.startsWith("PDF failed") ? "text-red small" : "text-green small"}>{pdfMsg}</div>}
        </form>
      </div>

      <ErrorBanner error={error} />
      {!loading && events.length === 0 && !error && <Empty>No audit events{anyFilter ? " match the filter" : ""}.</Empty>}
      {events.length > 0 && (
        <table className="table table-audit">
          <thead>
            <tr><th className="num">Seq</th><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Outcome</th><th>Details</th></tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.seq}>
                <td className="num"><Mono title={`hash ${ev.hash}\nprev ${ev.prev_hash}`}>{ev.seq}</Mono></td>
                <td className="nowrap"><Time value={ev.ts} /></td>
                <td>{ev.actor}</td>
                <td><Mono>{ev.action}</Mono></td>
                <td>
                  <span className="muted small">{ev.object_type}</span> <Mono>{ev.object_id}</Mono>
                  {ev.package_id && ev.package_id !== ev.object_id && <div className="cell-sub">pkg <Mono>{ev.package_id}</Mono></div>}
                </td>
                <td><Pill state={ev.outcome} /></td>
                <td className="json-cell"><code>{compact(ev.details)}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="load-more">
        {loading && <span className="muted">Loading…</span>}
        {!loading && more && lastSeq !== undefined && (
          <button className="btn" onClick={() => void load(lastSeq)}>Load more (before seq {lastSeq})</button>
        )}
        {!loading && !more && events.length > 0 && <span className="muted small">End of log · {events.length} events shown</span>}
      </div>
    </>
  );
}

function compact(d: Record<string, unknown> | null | undefined): string {
  if (!d || Object.keys(d).length === 0) return "";
  try {
    return JSON.stringify(d);
  } catch {
    return String(d);
  }
}
