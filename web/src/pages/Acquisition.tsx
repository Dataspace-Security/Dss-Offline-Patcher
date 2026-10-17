import { Link } from "react-router-dom";
import { api } from "../api";
import { paths } from "../paths";
import { Empty, ErrorBanner, Mono, Pill, RelTime, Time } from "../components/ui";
import { AcquisitionRequests } from "../components/AcquisitionRequests";
import type { AcquisitionRequestRecord } from "../types";

type Feed = { type: string; name: string; title?: string; latest_version?: string; status: string; detail?: string };
type Report = {
  source: string; host: string; schedule?: string; started_at: string; finished_at: string; outcome: "ok" | "partial" | "failed";
  error?: string; new_packages: string[]; already_sent: number; skipped_superseded?: string[]; failures: Record<string, string>;
  warnings?: string[]; bundle_id?: string; sent: boolean; feeds: Feed[];
};
type Rec = { id: number; source: string; received_at: string; finished_at: string; outcome: string; key_id: string; report: Report };
type Src = { source: string; last: Rec; stale: boolean; age_hours: number };
export type AcquisitionStatus = { sources: Src[]; history: Rec[]; stale_after_hours: number };

const outcomePill = (o: string) => <Pill state={o === "ok" ? "verified" : o === "partial" ? "pending_reboot" : "failed"} label={o} />;
const feedPill = (s: string) => <Pill state={s === "up_to_date" ? "verified" : s === "new" ? "active" : "failed"} label={s === "up_to_date" ? "no new version" : s === "new" ? "new version sent" : s.replace(/_/g, " ")} />;

export const fetchAcquisition = () => api.get<AcquisitionStatus>("/api/acquisition?limit=50");
export const fetchAcqRequests = () => api.get<AcquisitionRequestRecord[]>("/api/acquisition-requests");

/**
 * Transfers → "Downloaded in the acquisition zone": status of the unattended
 * downloader (pmctl auto) from its signed status reports, plus the tracked
 * acquisition requests.
 */
export function DownloadsSection({ data, error, requests, requestsError }: {
  data: AcquisitionStatus | null; error: string | null;
  requests: AcquisitionRequestRecord[] | null; requestsError: string | null;
}) {
  return (
    <>
      <ErrorBanner error={error} />
      {data && data.sources.length === 0 && (
        <Empty>No status report received yet. Run <Mono>pmctl auto</Mono> on the acquisition host; reports arrive with the next transfer.</Empty>
      )}
      {data?.sources.map((s) => {
        const r = s.last.report;
        return (
          <section key={s.source} className="card acq-card">
            <div className="section-head">
              <h3>
                {s.source} <span className="muted">· {r.host}</span>
              </h3>
              <div>
                {s.stale ? <Pill state="failed" label={`stale — no report for ${Math.round(s.age_hours)} h`} /> : outcomePill(r.outcome)}
              </div>
            </div>
            {s.stale && (
              <div className="banner banner-warn">
                No status report for more than {data.stale_after_hours} h. Silence is not success: check that the scheduled job runs on {r.host}.
              </div>
            )}
            <div className="acq-kpis">
              <div><div className="tile-label">Last run</div><Time value={r.finished_at} /></div>
              <div><div className="tile-label">Schedule</div>{r.schedule || <span className="muted">not set (add "schedule" to acquire.json)</span>}</div>
              <div><div className="tile-label">New this run</div><b>{r.new_packages.length}</b></div>
              <div><div className="tile-label">Already sent</div>{r.already_sent}</div>
              <div><div className="tile-label">Bundle</div>{r.bundle_id ? <><Mono>{r.bundle_id}</Mono> {r.sent ? <Pill state="verified" label="sent" /> : <Pill state="failed" label="not sent" />}</> : <span className="muted">none needed</span>}</div>
            </div>
            {r.error && <div className="banner banner-error"><b>Run failed:</b> {r.error}</div>}
            <h4>Feeds</h4>
            <table className="table table-compact">
              <thead><tr><th>Type</th><th>Feed</th><th>Latest found</th><th>Status</th><th>Detail</th></tr></thead>
              <tbody>
                {(r.feeds ?? []).map((f) => (
                  <tr key={f.type + f.name}>
                    <td><span className="tag">{f.type}</span></td>
                    <td>{f.title || f.name}<div className="cell-sub"><Mono>{f.name}</Mono></div></td>
                    <td><Mono>{f.latest_version || "—"}</Mono></td>
                    <td>{feedPill(f.status)}</td>
                    <td className="detail-cell">{f.detail || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {r.new_packages.length > 0 && (
              <p>
                New packages sent (awaiting intake &amp; approval):{" "}
                {r.new_packages.map((p) => <Link key={p} to={paths.catalog(p)} className="tag">{p}</Link>)}
              </p>
            )}
            {(r.skipped_superseded ?? []).length > 0 && <p className="muted">Skipped as superseded: {r.skipped_superseded!.join(", ")}</p>}
            {(r.warnings ?? []).length > 0 && <div className="banner banner-warn">{r.warnings!.map((w) => <div key={w}>{w}</div>)}</div>}
          </section>
        );
      })}
      <AcquisitionRequests data={requests} error={requestsError} />
      {data && data.history.length > 0 && (
        <section className="section">
          <h3>Run history <span className="muted">· last {data.history.length}</span></h3>
          <table className="table">
            <thead><tr><th>Finished</th><th>Source</th><th>Outcome</th><th>New</th><th>Failures</th><th>Bundle</th><th>Received</th></tr></thead>
            <tbody>
              {data.history.map((h) => (
                <tr key={h.id}>
                  <td className="nowrap"><Time value={h.finished_at} hideRel /></td>
                  <td>{h.source}</td>
                  <td>{outcomePill(h.outcome)}</td>
                  <td>{h.report.new_packages.length ? h.report.new_packages.join(", ") : <span className="muted">—</span>}</td>
                  <td className="detail-cell">{Object.entries(h.report.failures ?? {}).map(([k, v]) => <div key={k}><b>{k}</b>: {v}</div>)}</td>
                  <td>{h.report.bundle_id ? <Mono>{h.report.bundle_id}</Mono> : <span className="muted">—</span>}</td>
                  <td className="nowrap"><RelTime value={h.received_at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
