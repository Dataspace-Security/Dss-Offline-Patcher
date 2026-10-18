import { useCallback, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, downloadFileNamed, errMsg, qs } from "../api";
import { ErrorBanner, PageHeader } from "../components/ui";
import { paths } from "../paths";
import type { CompliancePack } from "../compliance/types";
import { normalizePack } from "../compliance/normalize";
import { fmtStamp, PERIOD_LABELS, periodRange, type PeriodKind } from "../compliance/format";
import { ComplianceDocument } from "../compliance/ComplianceDocument";
import "../compliance/compliance.css";

const KINDS: PeriodKind[] = ["this_month", "last_month", "this_quarter", "custom"];
const DAY = /^\d{4}-\d{2}-\d{2}$/;

function initialKind(sp: URLSearchParams): PeriodKind {
  const k = sp.get("period") as PeriodKind | null;
  return k && KINDS.includes(k) ? k : "last_month";
}

export default function ComplianceReport() {
  const [sp, setSp] = useSearchParams();
  const [kind, setKind] = useState<PeriodKind>(() => initialKind(sp));
  const preset = kind === "custom" ? null : periodRange(kind);
  const [customFrom, setCustomFrom] = useState(() => (DAY.test(sp.get("from") ?? "") ? sp.get("from")! : periodRange("last_month").from));
  const [customTo, setCustomTo] = useState(() => (DAY.test(sp.get("to") ?? "") ? sp.get("to")! : periodRange("last_month").to));
  const from = preset ? preset.from : customFrom;
  const to = preset ? preset.to : customTo;
  const [redact, setRedact] = useState(() => sp.get("redact") === "1");

  const [pack, setPack] = useState<CompliancePack | null>(null);
  const [genKey, setGenKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [zipBusy, setZipBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pdfBusy, setPdfBusy] = useState(false);
  const seq = useRef(0);

  const periodError = !DAY.test(from) || !DAY.test(to) ? "Choose a start and end date." : from > to ? "The start date is after the end date." : null;
  const key = `${from}|${to}|${redact ? 1 : 0}`;
  const stale = !!pack && genKey !== key;

  const generate = useCallback(async () => {
    if (periodError) return;
    const my = ++seq.current;
    setBusy(true);
    setError(null);
    setSp((prev) => {
      const n = new URLSearchParams(prev);
      n.set("period", kind);
      if (kind === "custom") { n.set("from", from); n.set("to", to); } else { n.delete("from"); n.delete("to"); }
      if (redact) n.set("redact", "1"); else n.delete("redact");
      return n;
    }, { replace: true });
    try {
      const raw = await api.get<unknown>(`/api/reports/compliance-pack${qs({ from, to, redact: redact ? 1 : undefined })}`);
      if (my !== seq.current) return;
      setPack(normalizePack(raw));
      setGenKey(`${from}|${to}|${redact ? 1 : 0}`);
    } catch (e) {
      if (my === seq.current) setError(`Could not generate the report: ${errMsg(e)}`);
    } finally {
      if (my === seq.current) setBusy(false);
    }
  }, [from, to, redact, kind, periodError, setSp]);

  const downloadZip = async () => {
    if (periodError) return;
    setZipBusy(true);
    setError(null);
    try {
      const name = `DSS-Patcher-Compliance-Evidence-${from}_${to}${redact ? "-redacted" : ""}.zip`;
      await downloadFileNamed(`/api/reports/compliance-pack.zip${qs({ from, to, redact: redact ? 1 : undefined })}`, name);
    } catch (e) {
      setError(`Evidence package download failed: ${errMsg(e)}`);
    } finally {
      setZipBusy(false);
    }
  };

  // Download PDF: the server renders the report for the period (a new
  // report ID, audited) and names the file DSS-Patcher-compliance-report-….
  const downloadPdf = async () => {
    if (periodError) return;
    setPdfBusy(true);
    setError(null);
    try {
      const name = `DSS-Patcher-compliance-report-${from}_${to}${redact ? "-redacted" : ""}.pdf`;
      await downloadFileNamed(`/api/reports/compliance-pack.pdf${qs({ from, to, redact: redact ? 1 : undefined })}`, name);
    } catch (e) {
      setError(`PDF download failed: ${errMsg(e)}`);
    } finally {
      setPdfBusy(false);
    }
  };

  return (
    <div className="crep-page">
      <PageHeader title="Compliance report" sub="Auditor report for a period: controls PM-01 to PM-17, regulatory mapping, timeliness, evidence register and sign-off. Organization details come from the report profile." />
      <div className="crep-toolbar no-print" role="group" aria-label="Report period and export">
        <div className="crep-periods" role="radiogroup" aria-label="Reporting period">
          {KINDS.map((k) => (
            <button key={k} type="button" role="radio" aria-checked={kind === k} className={`chip ${kind === k ? "chip-on" : ""}`} onClick={() => setKind(k)}>
              {PERIOD_LABELS[k]}
            </button>
          ))}
        </div>
        {kind === "custom" ? (
          <div className="crep-custom">
            <label className="field"><span>From</span><input type="date" value={customFrom} max={customTo || undefined} onChange={(e) => setCustomFrom(e.target.value)} /></label>
            <label className="field"><span>To</span><input type="date" value={customTo} min={customFrom || undefined} onChange={(e) => setCustomTo(e.target.value)} /></label>
          </div>
        ) : (
          <span className="crep-range">{from} to {to}</span>
        )}
        <label className="check crep-redact" title="Replace hostnames, IP addresses and user IDs with stable pseudonyms in the report and the evidence package">
          <input type="checkbox" checked={redact} onChange={(e) => setRedact(e.target.checked)} /> Redact hostnames
        </label>
        <span className="spacer" />
        <button type="button" className="btn btn-primary" disabled={busy || !!periodError} onClick={() => void generate()}>
          {busy ? "Generating…" : pack ? "Regenerate" : "Generate"}
        </button>
        <button type="button" className="btn" disabled={pdfBusy || !!periodError} onClick={() => void downloadPdf()}
                title="The report for this period as a PDF file made by the server (also inside the evidence package as report.pdf)">
          {pdfBusy ? "Preparing…" : "Download PDF"}
        </button>
        <button type="button" className="btn" disabled={zipBusy || !!periodError} onClick={() => void downloadZip()}
                title="Signed package: report.pdf, report.md, summary.json, evidence CSVs E-001 to E-010, manifest.json, manifest.sig and signing-key.pub">
          {zipBusy ? "Preparing…" : "Download evidence package (ZIP)"}
        </button>
      </div>
      {periodError && <div className="banner banner-warn no-print">{periodError}</div>}
      <div className="no-print"><ErrorBanner error={error} /></div>
      {stale && (
        <div className="banner banner-info no-print">
          The period or redaction setting changed since this report was generated. <b>Regenerate</b> to update it before downloading.
        </div>
      )}
      {!pack && !busy && (
        <div className="empty no-print">
          Pick a reporting period and press <b>Generate</b>. Fill in the organization details first under{" "}
          <Link to={paths.reportProfile}>Report profile</Link>; anything not filled in shows as not assessed.
        </div>
      )}
      {pack && (
        <>
          <div className="crep-meta no-print">
            Report <span className="mono">{pack.meta.report_id || "—"}</span> · generated {fmtStamp(pack.meta.generated_at) || "—"}
            {pack.meta.redacted && " · redacted"}
          </div>
          <ComplianceDocument pack={pack} />
        </>
      )}
    </div>
  );
}
