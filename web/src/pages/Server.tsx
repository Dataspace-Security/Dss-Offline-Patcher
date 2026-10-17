import { Link } from "react-router-dom";
import { api } from "../api";
import { paths } from "../paths";
import { ErrorBanner, KV, Mono, PageHeader, Pill, Time } from "../components/ui";
import { fmtBytes, useLoad } from "../util";

type Sys = {
  version: string; go_version: string; platform: string; started_at: string; uptime_seconds: number; listen: string;
  security: { tls: boolean; mtls_agents: boolean; insecure_http: boolean; sso: boolean; static_tokens: boolean; require_mfa: boolean };
  policy: { approval_policy: Record<string, number> | null; separation_of_duties: boolean; patch_deadlines: Record<string, string> };
  trust: { root_key_configured: boolean; trust_document_sequence: string; bundle_keys: { key_id: string; sources: string[] | null; status: string }[] };
  intake: { interval: string; inbox: string; bundles_waiting: number; last_bundle_received_at: string; max_bundles_per_hour: number;
    max_bytes_per_hour: number; content_scanner: boolean; max_bundle_bytes: number };
  storage: { data_dir: string; database_bytes: number; repository_objects: number; repository_bytes: number };
  audit: { chain_ok: boolean; events: number; export_dir: string; exported_to_seq: string; checkpoint_interval: string; retention: string };
  agents: { checkin_interval_seconds: number; offline_after: string; stale_inventory_after: string; download_rate_kbps: number };
  open_alerts: number;
};

const yes = (b: boolean, good = true) => <Pill state={b === good ? "verified" : "pending_reboot"} label={b ? "yes" : "no"} />;

function uptime(s: number): string {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

export default function ServerPage() {
  const { data: s, error, reload } = useLoad(() => api.get<Sys>("/api/system"), [], 30000);
  return (
    <>
      <PageHeader title="Server" sub="Management server configuration and health (isolated zone). Secrets are never shown.">
        <button className="btn" onClick={reload}>Refresh</button>
      </PageHeader>
      <ErrorBanner error={error} />
      {s && (
        <>
          {s.security.insecure_http && (
            <div className="banner banner-warn"><b>Lab mode:</b> TLS is off and agents use bearer secrets (<Mono>insecure_http</Mono>). Never use this outside an isolated lab.</div>
          )}
          <div className="grid-2">
            <section className="card">
              <h2>Server</h2>
              <KV rows={[
                ["Version", <Mono>{s.version}</Mono>],
                ["Running since", <><Time value={s.started_at} /> <span className="muted">(up {uptime(s.uptime_seconds)})</span></>],
                ["Listening on", <Mono>{s.listen}</Mono>],
                ["Platform", `${s.platform} · ${s.go_version}`],
                ["Open alerts", <Link to={paths.alerts}>{s.open_alerts}</Link>],
              ]} />
            </section>
            <section className="card">
              <h2>Security</h2>
              <KV rows={[
                ["TLS", yes(s.security.tls)],
                ["Agent mTLS certificates", yes(s.security.mtls_agents)],
                ["Single sign-on (OIDC)", yes(s.security.sso)],
                ["MFA required", yes(s.security.require_mfa)],
                ["Static admin tokens", yes(s.security.static_tokens, false)],
                ["Two-person approval", s.policy.approval_policy && Object.keys(s.policy.approval_policy).length
                  ? Object.entries(s.policy.approval_policy).map(([k, v]) => `${k}: ${v}`).join(", ") : "1 approver for all severities"],
                ["Separation of duties", yes(s.policy.separation_of_duties)],
              ]} />
            </section>
            <section className="card">
              <h2>Intake (transfer boundary)</h2>
              <KV rows={[
                ["Inbox", <Mono>{s.intake.inbox}</Mono>],
                ["Bundles waiting", s.intake.bundles_waiting ? <b className="text-amber">{s.intake.bundles_waiting}</b> : "0"],
                ["Last bundle received", s.intake.last_bundle_received_at ? <Time value={s.intake.last_bundle_received_at} /> : "never"],
                ["Scan interval", s.intake.interval],
                ["Rate limit", s.intake.max_bundles_per_hour || s.intake.max_bytes_per_hour
                  ? `${s.intake.max_bundles_per_hour || "∞"} bundles / ${s.intake.max_bytes_per_hour ? fmtBytes(s.intake.max_bytes_per_hour) : "∞"} per hour` : "none"],
                ["Content scanner", yes(s.intake.content_scanner)],
                ["Max bundle size", fmtBytes(s.intake.max_bundle_bytes)],
              ]} />
              <p><Link to={paths.transfers}>Transfers: acquisition status, intake &amp; reconciliation →</Link></p>
            </section>
            <section className="card">
              <h2>Signing keys</h2>
              <KV rows={[
                ["Root key (rotation)", yes(s.trust.root_key_configured)],
                ["Trust document", s.trust.trust_document_sequence ? `sequence ${s.trust.trust_document_sequence}` : "none (keys from config)"],
              ]} />
              <table className="table table-compact">
                <thead><tr><th>Bundle key</th><th>Sources</th><th>Status</th></tr></thead>
                <tbody>
                  {s.trust.bundle_keys.map((k) => (
                    <tr key={k.key_id}><td><Mono>{k.key_id}</Mono></td><td>{(k.sources ?? []).join(", ") || "—"}</td><td><Pill state={k.status === "active" ? "verified" : "stale"} label={k.status} /></td></tr>
                  ))}
                </tbody>
              </table>
            </section>
            <section className="card">
              <h2>Storage</h2>
              <KV rows={[
                ["Data directory", <Mono>{s.storage.data_dir}</Mono>],
                ["Database", fmtBytes(s.storage.database_bytes)],
                ["Repository", `${s.storage.repository_objects} approved files · ${fmtBytes(s.storage.repository_bytes)}`],
              ]} />
            </section>
            <section className="card">
              <h2>Audit &amp; agents</h2>
              <KV rows={[
                ["Audit chain", s.audit.chain_ok ? <Pill state="verified" label={`intact · ${s.audit.events} events`} /> : <Pill state="failed" label="BROKEN" />],
                ["Off-box export", s.audit.export_dir ? <><Mono>{s.audit.export_dir}</Mono> · every {s.audit.checkpoint_interval} · to seq {s.audit.exported_to_seq || "—"}</> : <span className="text-amber">not configured</span>],
                ["Retention", s.audit.retention === "0s" ? "keep forever" : s.audit.retention],
                ["Agent check-in", `every ${s.agents.checkin_interval_seconds} s`],
                ["Offline after / stale after", `${s.agents.offline_after} / ${s.agents.stale_inventory_after}`],
                ["Download limit", s.agents.download_rate_kbps ? `${s.agents.download_rate_kbps} kbit/s` : "unlimited"],
              ]} />
            </section>
          </div>
        </>
      )}
    </>
  );
}
