import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api, enc, errMsg } from "../api";
import { useCan } from "../auth";
import { Empty, ErrorBanner, KV, Mono, PageHeader, Pill, ReasonModal, RelTime, Time } from "../components/ui";
import { AvailablePatches } from "../components/AvailablePatches";
import type { Endpoint, EndpointDetail } from "../types";
import { parseTime, splitList, useLoad, useNow } from "../util";

export default function EndpointDetailPage() {
  const { id = "" } = useParams();
  const canEdit = useCan("operator");
  const { data: e, error, reload } = useLoad(() => api.get<EndpointDetail>(`/api/endpoints/${enc(id)}`), [id], 15000);
  const [invFilter, setInvFilter] = useState("");
  const [retiring, setRetiring] = useState(false);
  const now = useNow(60000);

  if (!e) {
    return (
      <>
        <PageHeader title="Endpoint" sub={<Link to="/endpoints">← Endpoints</Link>} />
        <ErrorBanner error={error} />
      </>
    );
  }

  const retired = e.status === "retired";

  const inv = (e.inventory ?? []).filter((i) =>
    !invFilter || `${i.id} ${i.name} ${i.version}`.toLowerCase().includes(invFilter.toLowerCase()));

  return (
    <>
      <PageHeader title={<>{e.hostname} <Pill state={e.status} /></>}
                  sub={<><Link to="/endpoints">← Endpoints</Link> · <Mono>{e.endpoint_id}</Mono></>}>
        {canEdit && !retired && (
          <button className="btn btn-danger" onClick={() => setRetiring(true)}>Retire endpoint…</button>
        )}
      </PageHeader>
      <ErrorBanner error={error} />
      {retired && (
        <div className="banner banner-info">
          <b>Retired</b> <Time value={e.retired_at} />{e.retired_reason && <> — {e.retired_reason}</>}. Its credentials no longer work and it is
          excluded from compliance totals and new deployments.
        </div>
      )}
      {(e.status === "offline" || e.status === "stale") && (
        <div className="banner banner-warn">
          This endpoint is <b>{e.status}</b>. Its patch state is unknown — silence is never compliance.
        </div>
      )}
      <div className="grid-2">
        <section className="card">
          <h2>System</h2>
          <KV rows={[
            ["OS", `${e.os} ${e.os_version}`],
            ["Edition", e.edition],
            ["Build", String(e.build || "—")],
            ["Arch", e.arch],
            ["Agent", e.agent_version],
            ["Last seen", <Time value={e.last_seen} />],
            ["Inventory", <Time value={e.inventory_at} />],
            ["Reboot pending", e.reboot_pending ? <Pill state="pending_reboot" label="yes" /> : "no"],
            ["Enrolled", <Time value={e.enrolled_at} />],
            ["Certificate", <CertExpiry value={e.cert_not_after} now={now} />],
            ...(e.reboot_requested_at && parseTime(e.reboot_requested_at) ? [["Reboot requested", <Time value={e.reboot_requested_at} />] as [string, ReactNode]] : []),
          ]} />
        </section>
        <section className="card">
          <h2>Assignment</h2>
          <EditForm e={e} canEdit={canEdit && !retired} onSaved={() => void reload()} />
        </section>
      </div>

      <AvailablePatches endpointId={e.endpoint_id} hostname={e.hostname} />

      <section className="section">
        <h2>Deployment targets <span className="muted">· {(e.targets ?? []).length}</span></h2>
        {(e.targets ?? []).length === 0 ? <Empty>Not targeted by any deployment.</Empty> : (
          <table className="table">
            <thead><tr><th>Deployment</th><th>Package</th><th>Ring</th><th>State</th><th className="num">Attempts</th><th className="num">Exit</th><th>Detail</th><th>Updated</th></tr></thead>
            <tbody>
              {e.targets.map((t) => (
                <tr key={t.deployment_id}>
                  <td><Link to={`/deployments/${enc(t.deployment_id)}`}><Mono>{t.deployment_id}</Mono></Link></td>
                  <td><Link to={`/catalog/${enc(t.package_id)}`}><Mono>{t.package_id}</Mono></Link></td>
                  <td>{t.ring + 1}</td>
                  <td><Pill state={t.state} /></td>
                  <td className="num">{t.attempts}</td>
                  <td className="num"><Mono>{t.exit_code}</Mono></td>
                  <td className="detail-cell">{t.detail || <span className="muted">—</span>}</td>
                  <td className="nowrap"><RelTime value={t.updated_at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Inventory <span className="muted">· {(e.inventory ?? []).length} items · reported <RelTime value={e.inventory_at} /></span></h2>
          <input className="search" placeholder="Filter inventory…" value={invFilter} onChange={(ev) => setInvFilter(ev.target.value)} />
        </div>
        {inv.length === 0 ? <Empty>No inventory items.</Empty> : (
          <table className="table table-compact">
            <thead><tr><th>Kind</th><th>ID</th><th>Name</th><th>Version</th></tr></thead>
            <tbody>
              {inv.map((i, n) => (
                <tr key={`${i.kind}-${i.id}-${n}`}>
                  <td><span className="tag">{i.kind}</span></td>
                  <td><Mono>{i.id}</Mono></td>
                  <td>{i.name}</td>
                  <td>{i.version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {retiring && (
        <ReasonModal
          title={`Retire ${e.hostname}`}
          description={
            <>
              <div className="banner banner-warn">
                <b>Its credentials stop working immediately.</b> The agent's certificate and device secret are revoked, its open
                deployment targets are closed, and it drops out of compliance totals. To bring the machine back it must be
                re-enrolled with a new enrollment token.
              </div>
            </>
          }
          confirmLabel="Retire endpoint"
          danger
          onClose={() => setRetiring(false)}
          onSubmit={async (reason) => {
            await api.post<Endpoint>(`/api/endpoints/${enc(e.endpoint_id)}/retire`, { reason });
            await reload();
          }}
        />
      )}
    </>
  );
}

function CertExpiry({ value, now }: { value: string; now: number }) {
  const d = parseTime(value);
  if (!d) return <span className="muted">no client certificate (lab mode or not yet issued)</span>;
  const days = Math.floor((d.getTime() - now) / 86400000);
  return (
    <>
      <Time value={value} />
      {days < 0 ? <Pill state="failed" label="expired" />
        : days < 14 ? <Pill state="pending" label={`expires in ${days}d`} /> : null}
    </>
  );
}

function EditForm({ e, canEdit, onSaved }: { e: Endpoint; canEdit: boolean; onSaved: () => void }) {
  const [groups, setGroups] = useState((e.groups ?? []).join(", "));
  const [site, setSite] = useState(e.site);
  const [owner, setOwner] = useState(e.owner);
  const [criticality, setCriticality] = useState(e.criticality);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [dirty, setDirty] = useState(false);

  // Keep the form in sync with polled data unless the user is editing.
  useEffect(() => {
    if (dirty) return;
    setGroups((e.groups ?? []).join(", "));
    setSite(e.site);
    setOwner(e.owner);
    setCriticality(e.criticality);
  }, [e, dirty]);

  const mark = <T,>(fn: (v: T) => void) => (v: T) => { fn(v); setDirty(true); setSaved(false); };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.patch<Endpoint>(`/api/endpoints/${enc(e.endpoint_id)}`, {
        groups: splitList(groups), site: site.trim(), owner: owner.trim(), criticality: criticality.trim(),
      });
      setDirty(false);
      setSaved(true);
      onSaved();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="form" onSubmit={submit}>
      <label className="field">
        <span>Groups <em className="muted">comma-separated</em></span>
        <input value={groups} disabled={!canEdit} onChange={(ev) => mark(setGroups)(ev.target.value)} />
      </label>
      <div className="form-grid">
        <label className="field">
          <span>Site</span>
          <input value={site} disabled={!canEdit} onChange={(ev) => mark(setSite)(ev.target.value)} />
        </label>
        <label className="field">
          <span>Owner</span>
          <input value={owner} disabled={!canEdit} onChange={(ev) => mark(setOwner)(ev.target.value)} />
        </label>
        <label className="field">
          <span>Criticality</span>
          <input list="criticality-opts" value={criticality} disabled={!canEdit} onChange={(ev) => mark(setCriticality)(ev.target.value)} />
          <datalist id="criticality-opts">
            <option value="low" /><option value="medium" /><option value="high" /><option value="critical" />
          </datalist>
        </label>
      </div>
      <ErrorBanner error={error} />
      {canEdit ? (
        <div className="form-actions">
          {saved && <span className="text-green small">Saved</span>}
          {dirty && <button type="button" className="btn" onClick={() => setDirty(false)}>Discard</button>}
          <button className="btn btn-primary" disabled={!dirty || busy}>{busy ? "Saving…" : "Save changes"}</button>
        </div>
      ) : <div className="hint">Editing requires the operator role.</div>}
    </form>
  );
}
