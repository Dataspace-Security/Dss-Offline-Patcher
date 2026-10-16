import { Link } from "react-router-dom";
import { api, enc } from "../api";
import { Empty, ErrorBanner, Mono, PageHeader, Pill, RelTime, Time } from "../components/ui";
import { useLoad } from "../util";

type Feed = { type: string; name: string; title?: string; latest_version?: string; status: string; detail?: string };
type Report = {
  source: string; host: string; schedule?: string; started_at: string; finished_at: string; outcome: "ok" | "partial" | "failed";
  error?: string; new_packages: string[]; already_sent: number; skipped_superseded?: string[]; failures: Record<string, string>;
  warnings?: string[]; bundle_id?: string; sent: boolean; feeds: Feed[];
};
type Rec = { id: number; source: string; received_at: string; finished_at: string; outcome: string; key_id: string; report: Report };
type Src = { source: string; last: Rec; stale: boolean; age_hours: number };
type Resp = { sources: Src[]; history: Rec[]; stale_after_hours: number };

const outcomePill = (o: string) => <Pill state={o === "ok" ? "verified" : o === "partial" ? "pending_reboot" : "failed"} label={o} />;
const feedPill = (s: string) => <Pill state={s === "up_to_date" ? "verified" : s === "new" ? "active" : "failed"} label={s === "up_to_date" ? "no new version" : s === "new" ? "new version sent" : s.replace(/_/g, " ")} />;

export default function AcquisitionPage() {
  const { data, error, reload } = useLoad(() => api.get<Resp>("/api/acquisition?limit=50"), [], 30000);
  return (
    <>
      <PageHeader
        title="Acquisition"
        sub="Status of the unattended downloader (pmctl auto) in the connected zone, as reported by its signed status reports."
      >
        <button className="btn" onClick={reload}>Refresh</button>
      </PageHeader>
      <div className="banner banner-info">
        The isolated server cannot contact the acquisition host (one-way transfer by design), so it cannot start a run.
        Each <Mono>pmctl auto</Mono> run sends a signed status report inward; this page shows the latest one.
        To run now, on the acquisition host: <Mono>pmctl auto -config acquire.json</Mono> (or <Mono>launchctl kickstart gui/$(id -u)/com.offpatch.acquire</Mono>).
      </div>
      <ErrorBanner error={error} />
      {data && data.sources.length === 0 && (
        <Empty>No status report received yet. Run <Mono>pmctl auto</Mono> on the acquisition host; reports arrive with the next transfer.</Empty>
      )}
      {data?.sources.map((s) => {
        const r = s.last.report;
        return (
          <section key={s.source} className="card acq-card">
            <div className="section-head">
              <h2>
                {s.source} <span className="muted">· {r.host}</span>
              </h2>
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
            <h3>Feeds</h3>
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
                {r.new_packages.map((p) => <Link key={p} to={`/catalog/${enc(p)}`} className="tag">{p}</Link>)}
              </p>
            )}
            {(r.skipped_superseded ?? []).length > 0 && <p className="muted">Skipped as superseded: {r.skipped_superseded!.join(", ")}</p>}
            {(r.warnings ?? []).length > 0 && <div className="banner banner-warn">{r.warnings!.map((w) => <div key={w}>{w}</div>)}</div>}
          </section>
        );
      })}
      {data && data.history.length > 0 && (
        <section className="section">
          <h2>Run history <span className="muted">· last {data.history.length}</span></h2>
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
