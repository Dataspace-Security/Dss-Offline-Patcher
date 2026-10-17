import { useState } from "react";
import { Link } from "react-router-dom";
import { api, downloadFile, errMsg } from "../api";
import { paths } from "../paths";
import { Empty, ErrorBanner, PageHeader, Pill, RelTime, Time } from "../components/ui";
import type { ComplianceReport, SeverityStats } from "../types";
import { useLoad } from "../util";
import { Severity } from "./Catalog";

const SEVERITIES = ["critical", "important", "moderate", "low"];

/** Go time.Duration string ("336h0m0s", "72h", "30m") → "14 days" / "3 days" / "30m". */
export function fmtGoDuration(s: string | undefined): string {
  if (!s) return "—";
  const m = /^(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m)?(?:(\d+(?:\.\d+)?)s)?$/.exec(s);
  if (!m || !s.length) return s;
  const hours = Number(m[1] ?? 0) + Number(m[2] ?? 0) / 60 + Number(m[3] ?? 0) / 3600;
  if (hours >= 24 && hours % 24 === 0) return `${hours / 24} day${hours === 24 ? "" : "s"}`;
  if (hours >= 1) return `${Math.round(hours * 10) / 10} h`;
  return s;
}

function days(n: number | undefined): string {
  if (n === undefined || n === null || n < 0) return "—";
  return n.toFixed(1);
}

function pctTone(p: number): string {
  if (p >= 95) return "green";
  if (p >= 80) return "amber";
  return "red";
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

export default function Reports() {
  const { data: r, error, loadedAt, reload } = useLoad(() => api.get<ComplianceReport>("/api/reports/compliance"), [], 60000);
  const [dl, setDl] = useState<string | null>(null);
  const [dlError, setDlError] = useState<string | null>(null);

  const download = async (path: string, name: string) => {
    setDl(name);
    setDlError(null);
    try {
      await downloadFile(path, name);
    } catch (e) {
      setDlError(`Download failed: ${errMsg(e)}`);
    } finally {
      setDl(null);
    }
  };

  const sevKeys = r ? [...SEVERITIES.filter((s) => r.by_severity?.[s]), ...Object.keys(r.by_severity ?? {}).filter((s) => !SEVERITIES.includes(s))] : [];

  return (
    <div className="report">
      <PageHeader
        title="Compliance report"
        sub={r ? <>Generated <Time value={r.generated_at} /> · loaded <RelTime value={new Date(loadedAt || Date.now()).toISOString()} /></> : "Loading…"}
      >
        <div className="no-print actions-inline">
          <button className="btn" onClick={() => void reload()}>Refresh</button>
          <button className="btn" disabled={!!dl} onClick={() => void download("/api/reports/compliance.csv", `offpatch-compliance-${today()}.csv`)}>
            {dl?.includes("compliance") ? "Downloading…" : "Download compliance CSV"}
          </button>
          <button className="btn" disabled={!!dl} onClick={() => void download("/api/reports/endpoints.csv", `offpatch-endpoints-${today()}.csv`)}>
            {dl?.includes("endpoints") ? "Downloading…" : "Download endpoints CSV"}
          </button>
          <button className="btn btn-primary" onClick={() => window.print()} disabled={!r}>Print / save as PDF</button>
        </div>
      </PageHeader>
      <ErrorBanner error={error} />
      <ErrorBanner error={dlError} />
      {r && (
        <>
          <section className="section">
            <h2>Compliance by severity <span className="muted">· verified installs vs. the deadline from vendor release</span></h2>
            {sevKeys.length === 0 ? <Empty>No deployment targets yet.</Empty> : (
              <div className="tiles tiles-4">
                {sevKeys.map((sev) => <SevTile key={sev} sev={sev} st={r.by_severity[sev]} deadline={r.deadlines?.[sev]} />)}
              </div>
            )}
          </section>

          <div className="grid-3 report-grid">
            <section className="section">
              <h2>Fleet</h2>
              <table className="table table-compact">
                <tbody>
                  <tr><td>Endpoints</td><td className="num"><b>{r.fleet.total}</b></td></tr>
                  <tr><td>Reporting</td><td className="num"><b className={`text-${pctTone(r.fleet.pct_reporting)}`}>{r.fleet.pct_reporting.toFixed(1)}%</b> <span className="muted">({r.fleet.reporting})</span></td></tr>
                  <tr><td><Link to="/endpoints?status=offline">Offline</Link></td><td className={`num ${r.fleet.offline ? "text-red" : ""}`}><b>{r.fleet.offline}</b></td></tr>
                  <tr><td><Link to="/endpoints?status=stale">Stale</Link></td><td className={`num ${r.fleet.stale ? "text-amber" : ""}`}><b>{r.fleet.stale}</b></td></tr>
                  <tr><td><Link to="/endpoints?status=pending_reboot">Pending reboot</Link></td><td className="num"><b>{r.fleet.pending_reboot}</b></td></tr>
                </tbody>
              </table>
            </section>
            <section className="section">
              <h2>Exceptions</h2>
              <table className="table table-compact">
                <tbody>
                  <tr><td><Link to={paths.exceptions}>Active</Link></td><td className="num"><b>{r.exceptions.active}</b></td></tr>
                  <tr><td>Expiring in 7 days</td><td className={`num ${r.exceptions.expiring_in_7d ? "text-amber" : ""}`}><b>{r.exceptions.expiring_in_7d}</b></td></tr>
                  <tr><td>Oldest active</td><td className="num"><b>{r.exceptions.active ? `${days(r.exceptions.oldest_age_days)} d` : "—"}</b></td></tr>
                </tbody>
              </table>
            </section>
            <section className="section">
              <h2>Intake</h2>
              <table className="table table-compact">
                <tbody>
                  <tr><td><Link to={paths.transfers}>Bundles validated</Link></td><td className="num"><b>{r.intake.validated}</b></td></tr>
                  <tr><td>Bundles rejected</td><td className={`num ${r.intake.rejected ? "text-red" : ""}`}><b>{r.intake.rejected}</b></td></tr>
                </tbody>
              </table>
            </section>
          </div>

          <section className="section">
            <h2>Packages <span className="muted">· {r.packages.length} · latency in days</span></h2>
            {r.packages.length === 0 ? <Empty>No packages.</Empty> : (
              <table className="table table-compact report-table">
                <thead>
                  <tr>
                    <th>Package</th><th>Severity</th><th>State</th><th>Released</th><th>Deadline</th>
                    <th className="num">Targets</th><th className="num">Verified</th><th className="num">Outstanding</th>
                    <th className="num">Overdue</th><th className="num">Exc.</th><th className="num">Compliant</th>
                    <th className="num" title="Vendor release → received in the isolated zone">Rel→recv</th>
                    <th className="num" title="Received → approved">Recv→appr</th>
                    <th className="num" title="Approved → first verified install">Appr→1st</th>
                    <th className="num" title="Vendor release → 90% of targets verified">Rel→90%</th>
                  </tr>
                </thead>
                <tbody>
                  {r.packages.map((p) => (
                    <tr key={p.package_id} className={p.overdue > 0 ? "row-overdue" : ""}>
                      <td>
                        <Link to={paths.catalog(p.package_id)} className="cell-title">{p.title || p.package_id}</Link>
                        {p.title && <div className="cell-sub mono">{p.package_id}</div>}
                      </td>
                      <td><Severity s={p.severity} /></td>
                      <td><Pill state={p.state} /></td>
                      <td className="nowrap">{p.release_date ? p.release_date.slice(0, 10) : "—"}</td>
                      <td className="nowrap"><Time value={p.deadline} hideRel /></td>
                      <td className="num">{p.targets}</td>
                      <td className="num">{p.verified}</td>
                      <td className="num">{p.outstanding}</td>
                      <td className={`num ${p.overdue > 0 ? "text-red" : ""}`}><b>{p.overdue}</b></td>
                      <td className="num">{p.exceptions}</td>
                      <td className={`num text-${pctTone(p.pct_compliant)}`}>{p.targets ? `${p.pct_compliant.toFixed(1)}%` : "—"}</td>
                      <td className="num">{days(p.days_release_to_received)}</td>
                      <td className="num">{days(p.days_received_to_approved)}</td>
                      <td className="num">{days(p.days_approved_to_first_verified)}</td>
                      <td className="num">{days(p.days_release_to_90pct_verified)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div className="hint">“—” means the milestone has not been reached yet. Rows with overdue targets are highlighted.</div>
          </section>
        </>
      )}
    </div>
  );
}

function SevTile({ sev, st, deadline }: { sev: string; st: SeverityStats; deadline?: string }) {
  const tone = st.overdue > 0 ? "red" : pctTone(st.pct_compliant);
  return (
    <div className={`tile tile-${tone} ${st.overdue > 0 ? "tile-alert" : ""}`}>
      <div className="tile-label"><Severity s={sev} /> · deadline {fmtGoDuration(deadline)}</div>
      <div className="tile-value">{st.targets ? `${st.pct_compliant.toFixed(1)}%` : "—"}</div>
      <div className="tile-foot">
        {st.verified}/{st.targets} verified · {st.outstanding} outstanding
        <br />
        <span className={st.overdue ? "text-red" : ""}><b>{st.overdue}</b> overdue</span> · {st.exceptions} exceptions
      </div>
    </div>
  );
}
