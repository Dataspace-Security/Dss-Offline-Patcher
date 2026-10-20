import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, downloadFileNamed, errMsg } from "../api";
import { ErrorBanner, KV, Mono, PageHeader, Pill, Time } from "../components/ui";
import { paths } from "../paths";
import { shortHash, useLoad } from "../util";
import { SourceForm } from "../autodownload/SourceForm";
import { AppsTable, SourcesTable, WindowsTable } from "../autodownload/Tables";
import {
  normalizePolicy, toPayload,
  type AcqPolicy, type PendingChange, type PolicyProposed, type PolicyResponse, type PolicySaved, type PolicyVersion, type RunRequested,
  type SourceEntry, type SourceResult,
} from "../autodownload/types";

const POLICY = "/api/acquisition/policy";

type Notice = { tone: "ok" | "warn" | "info"; text: string } | null;

/**
 * Settings → Auto-download (super admin only; the server refuses everyone
 * else). What the downloader fetches on every run, on top of the
 * installer's settings (acquire.json).
 */
export default function AutoDownloadPage() {
  const loaded = useLoad(() => api.get<PolicyResponse>(POLICY), [], 60000);
  const history = useLoad(() => api.get<PolicyVersion[]>(`${POLICY}/history`), []);
  const server = loaded.data;
  const [draft, setDraft] = useState<AcqPolicy | null>(null);
  const [baseVersion, setBaseVersion] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [editing, setEditing] = useState<number | null | undefined>(undefined); // undefined = closed, null = new

  // The draft starts from what was loaded; background refreshes do not overwrite edits.
  useEffect(() => {
    if (server && draft === null) {
      setDraft(normalizePolicy(server.policy));
      setBaseVersion(server.version);
    }
  }, [server, draft]);

  const p = draft ?? normalizePolicy(server?.policy);
  const dirty = useMemo(
    () => !!server && !!draft && (JSON.stringify(toPayload(draft)) !== JSON.stringify(toPayload(normalizePolicy(server.policy))) || server.is_default),
    [server, draft],
  );
  const results = useMemo(() => {
    const m = new Map<string, SourceResult>();
    for (const r of server?.downloader?.sources ?? []) m.set(`${r.kind}:${r.kind === "app" ? r.id.toLowerCase() : r.id}`, r);
    return m;
  }, [server]);
  const update = (next: Partial<AcqPolicy>) => { setNotice(null); setDraft({ ...p, ...next }); };

  const save = async () => {
    if (baseVersion === null) return;
    setSaving(true);
    setError(null);
    setConflict(false);
    try {
      const r = await api.put<PolicySaved | PolicyProposed>(`${POLICY}?base_version=${baseVersion}`, toPayload(p));
      if ("needs_approval" in r) {
        // Adds or changes a download source: a second super admin approves it.
        setDraft(normalizePolicy(r.pending.policy));
        setNotice({ tone: "info", text: `Not applied yet: this change ${r.pending.source_changes.join("; ")}. Another super admin must approve it below before it reaches the downloader.` });
        await loaded.reload();
        return;
      }
      setDraft(normalizePolicy(r.policy));
      setBaseVersion(r.version);
      setNotice(r.queued_error
        ? { tone: "warn", text: `Saved as version ${r.version}, but it could not be handed to the downloader (${r.queued_error}). Use "Hand over again" or download the file and copy it to the downloader's requests folder.` }
        : r.queued_to
          ? { tone: "ok", text: `Saved as version ${r.version} and handed to the downloader. It applies the change on its next run (usually within a minute on this server).` }
          : { tone: "info", text: `Saved as version ${r.version}. The downloader is on another machine: download the policy file and copy it into its requests folder, like a request file.` });
      await Promise.all([loaded.reload(), history.reload()]);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setConflict(true);
      setError(errMsg(e));
    } finally {
      setSaving(false);
    }
  };

  const reloadDiscard = async () => {
    setDraft(null);
    setConflict(false);
    setError(null);
    await Promise.all([loaded.reload(), history.reload()]);
  };

  const act = async (fn: () => Promise<Notice>) => {
    setError(null);
    try {
      setNotice(await fn());
      await loaded.reload();
    } catch (e) {
      setError(errMsg(e));
    }
  };
  const runNow = () => act(async () => {
    const r = await api.post<RunRequested>("/api/acquisition/run", {});
    return { tone: "ok", text: `The downloader was asked to run now (${r.run_id}). Results show here and under Patches → Imports when it finishes.` };
  });
  const requeue = () => act(async () => {
    await api.post(`${POLICY}/queue`, {});
    return { tone: "ok", text: "Handed to the downloader again." };
  });
  const approve = (sha256: string) => act(async () => {
    const r = await api.post<PolicySaved>(`${POLICY}/pending/approve`, { sha256 });
    setDraft(normalizePolicy(r.policy));
    setBaseVersion(r.version);
    await history.reload();
    return r.queued_error
      ? { tone: "warn", text: `Approved as version ${r.version}, but it could not be handed to the downloader (${r.queued_error}).` }
      : { tone: "ok", text: `Approved as version ${r.version}${r.queued_to ? " and handed to the downloader" : ": download the policy file and copy it to the downloader"}.` };
  });
  const reject = (mine: boolean) => act(async () => {
    const reason = window.prompt(mine ? "Withdraw your proposed change? Reason (optional):" : "Reject this change? Reason (optional):");
    if (reason === null) return null;
    await api.post(`${POLICY}/pending/reject`, { reason });
    setDraft(null);
    return { tone: "info", text: mine ? "Your proposal was withdrawn." : "The proposed change was rejected." };
  });
  const download = (version?: number) => act(async () => {
    const name = await downloadFileNamed(`${POLICY}/file${version ? `?version=${version}` : ""}`, "policy.json");
    return { tone: "info", text: `Downloaded ${name}. Copy it into the downloader's requests folder (the same place request files go).` };
  });

  const editSource = (s: SourceEntry) => {
    const list = editing === null || editing === undefined ? [...p.sources, s] : p.sources.map((x, i) => (i === editing ? s : x));
    update({ sources: list });
    setEditing(undefined);
  };

  return (
    <>
      <PageHeader title="Auto-download"
        sub="What the downloader fetches on every run. The installer's settings (acquire.json) stay the base; what you set here is added on top, and can switch parts of it off.">
        {server?.delivery.direct && <button className="btn" onClick={() => void runNow()} title="Ask the downloader to run once now">Run now</button>}
        {server && server.version > 0 && <button className="btn" onClick={() => void download()}>Download policy file</button>}
        <button className="btn btn-primary" disabled={!dirty || saving} onClick={() => void save()}>{saving ? "Saving…" : "Save"}</button>
      </PageHeader>
      <ErrorBanner error={loaded.error} />
      {error && (
        <div className="banner banner-warn">
          {conflict ? <><b>Someone else saved a newer version.</b> {error} </> : error}{" "}
          {conflict && <button className="btn btn-sm" onClick={() => void reloadDiscard()}>Reload (drops your changes)</button>}
        </div>
      )}
      {notice && <div className={`banner banner-${notice.tone}`}>{notice.text}</div>}
      {server?.banner && <div className="banner banner-info">{server.banner}</div>}

      {server?.pending && (
        <PendingCard pending={server.pending} canApprove={server.can_approve}
          onApprove={() => void approve(server.pending!.sha256)} onReject={() => void reject(!server.can_approve)} />
      )}
      {server && <StatusCard server={server} savedHistory={history.data ?? []} onRequeue={() => void requeue()} />}

      {server && (
        <>
          <section className="card section">
            <h2>Windows updates</h2>
            <WindowsTable rows={p.windows} choices={server.windows_choices ?? []} results={results} onChange={(windows) => update({ windows })} />
          </section>
          <section className="card section">
            <h2>Apps</h2>
            <AppsTable rows={p.apps} results={results} onChange={(apps) => update({ apps })} />
          </section>
          <section className="card section">
            <h2>Download sources</h2>
            <SourcesTable rows={p.sources} results={results} onChange={(sources) => update({ sources })} onEdit={(i) => setEditing(i)} />
          </section>
          <section className="card section">
            <h2>Limits</h2>
            <div className="form-grid">
              <label className="field">
                <span>Most to download in one run (GB)</span>
                <input type="number" min={0} max={10000} value={p.limits.max_download_gb_per_run}
                  onChange={(e) => update({ limits: { ...p.limits, max_download_gb_per_run: Math.max(0, Math.floor(Number(e.target.value) || 0)) } })} />
                <span className="hint">0 = no limit. When reached, the rest is downloaded on the next run.</span>
              </label>
              <label className="field">
                <span>Versions to keep on the downloader</span>
                <input type="number" min={0} max={100} value={p.limits.keep_last_n_versions}
                  onChange={(e) => update({ limits: { ...p.limits, keep_last_n_versions: Math.max(0, Math.floor(Number(e.target.value) || 0)) } })} />
                <span className="hint">For the apps and vendor downloads above. 0 = delete old files by age (the installer's setting).</span>
              </label>
            </div>
          </section>
          {server.default_feeds.length > 0 && (
            <section className="card section">
              <h2>Also from the installer's settings</h2>
              <p className="hint">These come from acquire.json and keep running; change them there.</p>
              <ul>{server.default_feeds.map((f) => <li key={f}>{f}</li>)}</ul>
            </section>
          )}
          <HistoryCard rows={history.data ?? []} error={history.error} onDownload={(v) => void download(v)} />
        </>
      )}
      {editing !== undefined && (
        <SourceForm initial={editing === null ? null : p.sources[editing]} others={p.sources.filter((_, i) => i !== editing)}
          onClose={() => setEditing(undefined)} onSave={editSource} />
      )}
    </>
  );
}

function StatusCard({ server, savedHistory, onRequeue }: { server: PolicyResponse; savedHistory: PolicyVersion[]; onRequeue: () => void }) {
  const d = server.downloader;
  const applied = d?.policy_version ?? 0;
  const saved = server.version;
  const last = savedHistory[0];
  let appliedRow;
  if (!d) appliedRow = <span className="muted">The downloader has not reported yet.</span>;
  else if (!d.reports_policy) appliedRow = <span className="text-amber">The downloader runs an older version that does not read this policy. Update pmctl on the downloader.</span>;
  else if (saved === 0) appliedRow = <span className="muted">Nothing saved yet: the downloader uses acquire.json only.</span>;
  else if (applied === saved) appliedRow = <><Pill state="verified" label={`version ${applied}`} /> Applied by the downloader at <Time value={d.policy_applied_at} /></>;
  else appliedRow = (
    <>
      <Pill state="pending" label={`waiting for version ${saved}`} />{" "}
      {applied ? <>The downloader still uses version {applied}. </> : <>The downloader has not applied a policy yet. </>}
      {server.delivery.direct ? <button className="btn btn-sm" onClick={onRequeue}>Hand over again</button> : <>Copy the policy file to the downloader.</>}
    </>
  );
  return (
    <section className="card section">
      <h2>Status</h2>
      <KV rows={[
        ["This page", saved > 0
          ? <>Version {saved}, saved by {server.edited_by.replace(/^user:/, "")} <Time value={server.edited_at} /> <Mono title={server.sha256}>{shortHash(server.sha256)}</Mono></>
          : <>Not saved yet. Starting point: {server.default_source === "acquire.json" ? "the installer's settings (acquire.json)" : server.default_source === "downloader" ? "the installer's settings, as reported by the downloader" : "empty"}.</>],
        ["Downloader", appliedRow],
        ...(d?.policy_error ? [["Refused", <span className="text-red">{d.policy_error}</span>] as [string, ReactNode]] : []),
        ...(d?.policy_signature ? [["Signature", d.policy_signature.startsWith("ed25519:")
          ? <><Pill state="verified" label="verified" /> <Mono>{d.policy_signature}</Mono></>
          : <span className="text-amber">{d.policy_signature}. Pin the signing key below in the downloader's acquire.json.</span>] as [string, ReactNode]] : []),
        ["Signing key", server.signing.error
          ? <span className="text-red">{server.signing.error}</span>
          : <><Mono>{server.signing.key_id}</Mono> <span className="muted">· acquire.json on the downloader: </span>
            <Mono title="policy_public_keys">{`"policy_public_keys": ["${server.signing.public_key}"]`}</Mono></>],
        ["Last run", d ? <><Time value={d.finished_at} /> on {d.host || d.source} · {d.outcome} · <Link to={paths.imports}>details</Link></> : <span className="muted">—</span>],
        ["Schedule", <>{d?.schedule || "hourly (systemd timer offpatch-acquire.timer)"} <span className="muted">· set by the installer, shown here only</span></>],
        ["Hand-over", server.delivery.direct
          ? "Automatic: saved versions go straight to the downloader on this server."
          : "By hand: the downloader is on another machine. Download the policy file and copy it into its requests folder."],
        ...(server.last_run_request ? [["Run now", <>Asked by {server.last_run_request.requested_by.replace(/^user:/, "")} <Time value={server.last_run_request.requested_at} />
          {d?.run_request === server.last_run_request.run_id ? " · done" : " · waiting for the downloader"}</>] as [string, ReactNode]] : []),
        ...(last && last.version === saved ? [["Last change", last.summary.join("; ")] as [string, ReactNode]] : []),
      ]} />
    </section>
  );
}

type PendingCardProps = { pending: PendingChange; canApprove: boolean; onApprove: () => void; onReject: () => void };

/** A source change waiting for a second super admin (the proposer cannot approve it). */
function PendingCard({ pending, canApprove, onApprove, onReject }: PendingCardProps) {
  const who = pending.proposed_by.replace(/^user:/, "");
  return (
    <section className="card section">
      <h2>Waiting for approval</h2>
      <p className="hint">
        Adding or changing a download source needs a second super admin. Nothing reaches the downloader until it is approved.
      </p>
      <KV rows={[
        ["Proposed by", <>{who} <Time value={pending.proposed_at} /> <Mono title={pending.sha256}>{shortHash(pending.sha256)}</Mono></>],
        ["Needs approval because it", pending.source_changes.join("; ")],
        ["All changes", pending.summary.length ? pending.summary.join("; ") : "—"],
        ["Based on", pending.base_version > 0 ? `version ${pending.base_version}` : "the installer's settings"],
      ]} />
      <div className="actions-inline">
        {canApprove
          ? <button className="btn btn-primary" onClick={onApprove}>Approve</button>
          : <span className="muted">You proposed this change: another super admin must approve it.</span>}
        <button className="btn" onClick={onReject}>{canApprove ? "Reject" : "Withdraw"}</button>
      </div>
    </section>
  );
}

function HistoryCard({ rows, error, onDownload }: { rows: PolicyVersion[]; error: string | null; onDownload: (v: number) => void }) {
  return (
    <section className="card section">
      <h2>History</h2>
      <ErrorBanner error={error} />
      {rows.length === 0 ? <p className="muted">No versions saved yet.</p> : (
        <table className="table table-compact">
          <thead><tr><th>Version</th><th>Saved by</th><th>When</th><th>What changed</th><th /></tr></thead>
          <tbody>
            {rows.map((v) => (
              <tr key={v.version}>
                <td><Mono title={v.sha256}>{v.version}</Mono></td>
                <td>{v.edited_by.replace(/^user:/, "")}</td>
                <td><Time value={v.edited_at} /></td>
                <td className="small">{v.summary.length ? v.summary.join("; ") : "—"}</td>
                <td className="right"><button className="btn btn-sm" onClick={() => onDownload(v.version)}>Download</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
