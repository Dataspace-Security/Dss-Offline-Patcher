import { useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, enc, errMsg } from "../api";
import { useCan } from "../auth";
import { Empty, ErrorBanner, Mono, Modal, PageHeader, Pill, ReasonModal, Time } from "../components/ui";
import type { Endpoint, Exception, NewException, Package } from "../types";
import { toRFC3339, useLoad } from "../util";

function excStatus(x: Exception): "active" | "expired" | "revoked" {
  if (x.revoked) return "revoked";
  return x.active ? "active" : "expired";
}

export default function Exceptions() {
  const canManage = useCan("approver");
  const { data, error, reload } = useLoad(() => api.get<Exception[]>("/api/exceptions"), [], 30000);
  const eps = useLoad(() => api.get<Endpoint[]>("/api/endpoints"), []);
  const pkgs = useLoad(() => api.get<Package[]>("/api/packages"), []);
  const [filter, setFilter] = useState<"" | "active" | "expired" | "revoked">("active");
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<Exception | null>(null);

  const host = (id: string) => eps.data?.find((e) => e.endpoint_id === id)?.hostname;
  const pkgTitle = (id: string) => pkgs.data?.find((p) => p.package_id === id)?.title;

  const rows = useMemo(() => (data ?? []).filter((x) => !filter || excStatus(x) === filter), [data, filter]);
  const count = (s: string) => (data ?? []).filter((x) => excStatus(x) === s).length;

  return (
    <>
      <PageHeader title="Exceptions" sub="Time-boxed, owned risk acceptances. Endpoints covered show as “exception”, not compliant.">
        {canManage && <button className="btn btn-primary" onClick={() => setCreating(true)}>New exception</button>}
      </PageHeader>
      <div className="tabs">
        {(["active", "expired", "revoked", ""] as const).map((s) => (
          <button key={s || "all"} className={`tab ${filter === s ? "tab-on" : ""}`} onClick={() => setFilter(s)}>
            {s || "all"} <span className="muted">{s ? count(s) : (data ?? []).length}</span>
          </button>
        ))}
      </div>
      <ErrorBanner error={error} />
      {data && rows.length === 0 && <Empty>No {filter} exceptions.</Empty>}
      {rows.length > 0 && (
        <table className="table">
          <thead>
            <tr><th>Endpoint</th><th>Package</th><th>Status</th><th>Owner</th><th>Reason</th><th>Compensating controls</th><th>Expires</th><th>Created</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((x) => {
              const st = excStatus(x);
              return (
                <tr key={x.exception_id}>
                  <td><Link to={`/endpoints/${enc(x.endpoint_id)}`}>{host(x.endpoint_id) ?? <Mono>{x.endpoint_id}</Mono>}</Link></td>
                  <td>{x.package_id
                    ? <Link to={`/catalog/${enc(x.package_id)}`}>{pkgTitle(x.package_id) ?? <Mono>{x.package_id}</Mono>}</Link>
                    : <i>All packages</i>}</td>
                  <td><Pill state={st === "active" ? "exception" : st} label={st} /></td>
                  <td>{x.owner}</td>
                  <td className="detail-cell">{x.reason}</td>
                  <td className="detail-cell">{x.compensating_controls || <span className="muted">—</span>}</td>
                  <td className="nowrap"><Time value={x.expires_at} /></td>
                  <td className="nowrap"><Time value={x.created_at} hideRel /><div className="cell-sub">{x.created_by}</div></td>
                  <td className="right">
                    {canManage && st === "active" && <button className="btn btn-sm btn-danger-ghost" onClick={() => setRevoking(x)}>Revoke…</button>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {creating && (
        <CreateException endpoints={eps.data ?? []} packages={pkgs.data ?? []}
          onClose={() => setCreating(false)} onCreated={() => { setCreating(false); void reload(); }} />
      )}
      {revoking && (
        <ReasonModal
          title="Revoke exception"
          description={<>Endpoint <b>{host(revoking.endpoint_id) ?? revoking.endpoint_id}</b>, {revoking.package_id ? pkgTitle(revoking.package_id) ?? revoking.package_id : "all packages"}.</>}
          confirmLabel="Revoke"
          danger
          onClose={() => setRevoking(null)}
          onSubmit={async (reason) => {
            await api.post<Exception>(`/api/exceptions/${enc(revoking.exception_id)}/revoke`, { reason });
            await reload();
          }}
        />
      )}
    </>
  );
}

function CreateException({ endpoints, packages, onClose, onCreated }: {
  endpoints: Endpoint[]; packages: Package[]; onClose: () => void; onCreated: () => void;
}) {
  const [endpointId, setEndpointId] = useState("");
  const [packageId, setPackageId] = useState("");
  const [owner, setOwner] = useState("");
  const [reason, setReason] = useState("");
  const [controls, setControls] = useState("");
  const [expires, setExpires] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const expDate = expires ? new Date(expires) : null;
  const expValid = !!expDate && !isNaN(expDate.getTime()) && expDate.getTime() > Date.now();
  const valid = endpointId && owner.trim() && reason.trim() && expValid;

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    setError(null);
    const body: NewException = {
      endpoint_id: endpointId, package_id: packageId, owner: owner.trim(), reason: reason.trim(),
      compensating_controls: controls.trim(), expires_at: toRFC3339(expires),
    };
    try {
      await api.post<Exception>("/api/exceptions", body);
      onCreated();
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  const sortedEps = [...endpoints].sort((a, b) => a.hostname.localeCompare(b.hostname));

  return (
    <Modal title="New exception" onClose={onClose} wide footer={
      <>
        <button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" disabled={!valid || busy} onClick={() => void submit()}>{busy ? "Creating…" : "Create exception"}</button>
      </>
    }>
      <form className="form" onSubmit={submit}>
        <div className="form-grid">
          <label className="field">
            <span>Endpoint <em className="req">required</em></span>
            <select value={endpointId} onChange={(e) => setEndpointId(e.target.value)}>
              <option value="">— select endpoint —</option>
              {sortedEps.map((e) => <option key={e.endpoint_id} value={e.endpoint_id}>{e.hostname} ({e.status})</option>)}
            </select>
          </label>
          <label className="field">
            <span>Package</span>
            <select value={packageId} onChange={(e) => setPackageId(e.target.value)}>
              <option value="">All packages</option>
              {packages.map((p) => <option key={p.package_id} value={p.package_id}>{p.title || p.package_id} {p.kb ? `(${p.kb})` : ""} · {p.state}</option>)}
            </select>
          </label>
          <label className="field">
            <span>Owner <em className="req">required</em></span>
            <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Accountable person or team" />
          </label>
          <label className="field">
            <span>Expires at <em className="req">required, local time</em></span>
            <input type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
            {expires && !expValid && <small className="text-red">Must be in the future.</small>}
            {expValid && <small className="hint">Sent as {toRFC3339(expires)}</small>}
          </label>
        </div>
        <label className="field">
          <span>Reason <em className="req">required</em></span>
          <textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        <label className="field">
          <span>Compensating controls</span>
          <textarea rows={2} value={controls} onChange={(e) => setControls(e.target.value)} />
        </label>
        <ErrorBanner error={error} />
      </form>
    </Modal>
  );
}
