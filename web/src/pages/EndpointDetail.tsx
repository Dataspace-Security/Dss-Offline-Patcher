import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api, enc, errMsg } from "../api";
import { paths } from "../paths";
import { useCan } from "../auth";
import { Empty, ErrorBanner, KV, Mono, PageHeader, Pill, ReasonModal, RelTime, TargetPill, Time } from "../components/ui";
import { EndpointUpdatesTable } from "../components/AvailablePatches";
import { HardwareCard } from "../components/Hardware";
import type { Endpoint, EndpointDetail } from "../types";
import { parseTime, splitList, useLoad, useNow } from "../util";

/** "Restart needed" and why it has not happened yet (the pending_reboot target detail from the server). */
function RestartNeeded({ e }: { e: EndpointDetail }) {
  const why = Array.from(new Set(e.targets.filter((t) => t.state === "pending_reboot").map((t) => t.detail).filter(Boolean)));
  return (
    <>
      <Pill state="pending_reboot" />
      {why.map((d) => <div key={d} className="cell-sub text-amber">{d}</div>)}
    </>
  );
}

export default function EndpointDetailPage() {
  const { id = "" } = useParams();
  const canEdit = useCan("user");
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
      {e.status === "lost_after_install" && (
        <div className="banner banner-error">
          <b>Lost after install:</b> this endpoint stopped checking in after installing
          {" "}{e.targets.filter((t) => t.state === "lost_after_install").map((t) => t.package_id).join(", ")}.
          {" "}Check it (boot failure, blue screen, network stack?). It counts as a failure towards its deployment's auto-pause and recovers
          automatically when the agent checks in and the install verifies.
        </div>
      )}
      {e.status === "awaiting_checkin" && (
        <div className="banner banner-info">
          <b>Waiting for first check-in.</b> The agent is enrolled but has not sent its inventory yet, so its patch state is not known.
          It normally reports within a few minutes; check that the agent service is running if it stays like this.
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
            ["OS", <>{e.os} {e.os_version}{e.missing?.os_support === "out_of_support" && (
              <div className="banner banner-error" style={{ marginTop: 6 }}>
                <b>This Windows version no longer receives updates from Microsoft</b> (last cumulative update {e.missing.os_last_update}).
                No Windows patch will apply to it; upgrade Windows to keep this machine secure.
              </div>)}</>],
            ["Edition", e.edition],
            ["Build", String(e.build || "—")],
            ["Arch", e.arch],
            ["Agent", e.agent_version],
            ["Last seen", <Time value={e.last_seen} />],
            ["Inventory", <Time value={e.inventory_at} />],
            ["Restart", e.reboot_pending || e.targets.some((t) => t.state === "pending_reboot") ? <RestartNeeded e={e} /> : "not needed"],
            ...(e.targets.some((t) => t.state === "deferred") ? [["Deferred", <span className="text-amber">{e.targets.filter((t) => t.state === "deferred").map((t) => t.detail).filter(Boolean)[0] ?? "pre-install check not met"}</span>] as [string, ReactNode]] : []),
            ["Enrolled", <Time value={e.enrolled_at} />],
            ["Certificate", <CertExpiry value={e.cert_not_after} now={now} />],
            ...(e.reboot_requested_at && parseTime(e.reboot_requested_at) ? [["Reboot requested", <Time value={e.reboot_requested_at} />] as [string, ReactNode]] : []),
          ]} />
        </section>
        <HardwareCard hw={e.hardware} now={now} />
        <section className="card">
          <h2>Assignment</h2>
          <EditForm e={e} canEdit={canEdit && !retired} onSaved={() => void reload()} />
        </section>
      </div>

      <EndpointUpdatesTable endpointId={e.endpoint_id} hostname={e.hostname} os={e.os} />

      <section className="section">
        <h2>Deployment targets <span className="muted">· {(e.targets ?? []).length}</span></h2>
        {(e.targets ?? []).length === 0 ? <Empty>Not targeted by any deployment.</Empty> : (
          <table className="table">
            <thead><tr><th>Deployment</th><th>Package</th><th>Operation</th><th>Stage</th><th>State</th><th className="num">Attempts</th><th className="num">Exit</th><th>Detail</th><th>Updated</th></tr></thead>
            <tbody>
              {e.targets.map((t) => (
                <tr key={t.deployment_id}>
                  <td><Link to={`/deployments/${enc(t.deployment_id)}`}><Mono>{t.deployment_id}</Mono></Link></td>
                  <td><Link to={paths.catalog(t.package_id)}><Mono>{t.package_id}</Mono></Link></td>
                  <td>{t.operation === "rollback" ? <span className="text-amber">rollback</span> : "install"}</td>
                  <td>{t.ring + 1}</td>
                  <td><TargetPill state={t.state} operation={t.operation} /></td>
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
                  <td className="nowrap"><span className="tag">{i.kind}</span>{i.source === "appstore" && <span className="tag" title="Installed from the Mac App Store, which keeps it updated">App Store</span>}</td>
                  <td><Mono>{i.id}</Mono></td>
                  <td>
                    {i.name}
                    {i.scope === "user" && <span className="muted small" title="Installed for one user only (in that user's profile), not for the whole machine"> (per user)</span>}
                  </td>
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
      ) : null}
    </form>
  );
}
