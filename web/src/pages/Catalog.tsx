import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, enc, errMsg, qs } from "../api";
import { deployToEndpoints } from "../components/AvailablePatches";

type Need = { package_id: string; needed: number; endpoint_ids: string[]; hostnames: string[] };
import { useCan, useMe } from "../auth";
import { Empty, ErrorBanner, KV, Mono, PageHeader, Pill, ReasonModal, Time } from "../components/ui";
import type { Package, PackageState } from "../types";
import { fmtBytes, shortHash, useLoad } from "../util";

const STATES: PackageState[] = ["quarantined", "approved", "rejected", "revoked"];

export default function Catalog() {
  const [sp, setSp] = useSearchParams();
  const state = sp.get("state") ?? "";
  const { packageId } = useParams();
  const navigate = useNavigate();
  const list = useLoad(() => api.get<Package[]>(`/api/packages${qs({ state })}`), [state], 30000);
  const needs = useLoad(() => api.get<Record<string, Need>>("/api/packages-needs"), [], 60000);

  const select = (id: string | null) =>
    navigate({ pathname: id ? `/catalog/${enc(id)}` : "/catalog", search: sp.toString() ? `?${sp}` : "" });

  return (
    <>
      <PageHeader title="Catalog" sub="Packages extracted from validated bundles. Nothing is deployable until approved.">
        <label className="inline-field">
          State
          <select value={state} onChange={(e) => setSp(e.target.value ? { state: e.target.value } : {})}>
            <option value="">All</option>
            {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
      </PageHeader>
      <ErrorBanner error={list.error} />
      <div className={packageId ? "split" : ""}>
        <div className="split-main">
          {list.data && list.data.length === 0 && <Empty>No packages{state ? ` in state “${state}”` : ""}.</Empty>}
          {list.data && list.data.length > 0 && (
            <table className="table">
              <thead>
                <tr>
                  <th>Title</th><th>KB / Product</th><th>Severity</th><th>Kind</th><th>Size</th><th>State</th><th title="Endpoints whose inventory shows they still need this patch">Needed by</th><th>Created</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((p) => (
                  <tr key={p.package_id} className={`clickable ${packageId === p.package_id ? "selected" : ""}`}
                      onClick={() => select(p.package_id)}>
                    <td>
                      <div className="cell-title">{p.title || p.package_id}</div>
                      <div className="cell-sub">
                        {p.vendor} {p.version && `· ${p.version}`}{p.package_name && <> · <Mono>{p.package_name}</Mono></>}
                        {p.superseded_by && <span className="text-amber"> · superseded</span>}
                      </div>
                    </td>
                    <td><Mono>{p.kb || p.product_code || "—"}</Mono></td>
                    <td><Severity s={p.severity} /></td>
                    <td><span className="tag">{p.kind}</span></td>
                    <td className="nowrap">{fmtBytes(p.size)}</td>
                    <td>
                      <Pill state={p.state} />
                      {p.state === "quarantined" && (p.approvals_required ?? 0) > 1 && (
                        <div className="cell-sub">{(p.approvals ?? []).length} of {p.approvals_required} approvals</div>
                      )}
                    </td>
                    <td className="num">{needs.data ? (needs.data[p.package_id]?.needed ? <b className="text-amber">{needs.data[p.package_id].needed}</b> : <span className="muted">0</span>) : "…"}</td>
                    <td><Time value={p.created_at} hideRel /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        {packageId && (
          <PackagePanel key={packageId} id={packageId} onClose={() => select(null)} onChanged={() => void list.reload()} />
        )}
      </div>
    </>
  );
}

export function Severity({ s }: { s: string }) {
  return <span className={`sev sev-${s}`}>{s || "—"}</span>;
}

type Action = "approve" | "reject" | "revoke";

function PackagePanel({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data: p, error, setData } = useLoad(() => api.get<Package>(`/api/packages/${enc(id)}`), [id]);
  const needs = useLoad(() => api.get<Record<string, Need>>("/api/packages-needs"), [id]);
  const need = needs.data?.[id];
  const [deploying, setDeploying] = useState(false);
  const [deployErr, setDeployErr] = useState<string | null>(null);
  const canApprove = useCan("approver");
  const canDeploy = useCan("operator");
  const me = useMe();
  const [action, setAction] = useState<Action | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const navigate = useNavigate();

  const run = async (a: Action, reason: string) => {
    const updated = await api.post<Package>(`/api/packages/${enc(id)}/${a}`, { reason });
    setData(updated);
    setNotice(a === "approve" && updated.state === "quarantined"
      ? `Recorded; needs another approver (${(updated.approvals ?? []).length} of ${updated.approvals_required || "?"} approvals).`
      : null);
    onChanged();
  };

  const approvals = p?.approvals ?? [];
  const approvalsRequired = p?.approvals_required ?? 0;
  // The server records approvers as "user:<name>".
  const alreadyApproved = !!me && approvals.some((a) => a.by === me.user || a.by === `user:${me.user}`);

  return (
    <aside className="panel">
      <div className="panel-head">
        <div>
          <div className="panel-title">{p?.title || id}</div>
          <Mono>{id}</Mono>
        </div>
        <button className="btn-icon" onClick={onClose} aria-label="Close">×</button>
      </div>
      <ErrorBanner error={error} />
      {p && (
        <>
          <div className="panel-actions">
            <Pill state={p.state} />
            <span className="spacer" />
            {p.state === "quarantined" && canApprove && (
              <>
                <button className="btn btn-primary" onClick={() => setAction("approve")} disabled={alreadyApproved}
                        title={alreadyApproved ? "You have already approved this package; another approver is needed" : undefined}>
                  Approve…
                </button>
                <button className="btn btn-danger" onClick={() => setAction("reject")}>Reject…</button>
              </>
            )}
            {p.state === "approved" && canDeploy && need && need.needed > 0 && (
              <button className="btn btn-primary" disabled={deploying} title={need.hostnames.join(", ")}
                onClick={async () => {
                  setDeploying(true);
                  try {
                    const d = await deployToEndpoints(p.package_id, p.title, need.endpoint_ids.slice(0, 500), `${need.needed} endpoint${need.needed === 1 ? "" : "s"} that need it`);
                    navigate(`/deployments/${enc(d.deployment_id)}`);
                  } catch (e) {
                    setDeployErr(errMsg(e));
                    setDeploying(false);
                  }
                }}>
                Deploy to the {need.needed} endpoint{need.needed === 1 ? "" : "s"} that need it
              </button>
            )}
            {p.state === "approved" && canDeploy && (
              <button className="btn btn-primary" onClick={() => navigate(`/deployments/new?package_id=${enc(p.package_id)}`)}>
                Deploy…
              </button>
            )}
            {p.state === "approved" && canApprove && (
              <button className="btn btn-danger" onClick={() => setAction("revoke")}>Revoke…</button>
            )}
          </div>
          {p.superseded_by && (
            <div className="banner banner-warn">Superseded by <Link to={`/catalog/${enc(p.superseded_by)}`}><Mono>{p.superseded_by}</Mono></Link>; prefer deploying the newer package.</div>
          )}
          {p.state === "quarantined" && !canApprove && (
            <div className="hint">Approval requires the approver role.</div>
          )}
          {notice && <div className="banner banner-info">{notice}</div>}
          {(approvalsRequired > 1 || approvals.length > 0) && (
            <>
              <h3>Approvals · {approvals.length} of {approvalsRequired || 1}</h3>
              {approvals.length === 0 ? <div className="muted small">No approvals yet.</div> : (
                <ul className="approvals">
                  {approvals.map((a, i) => (
                    <li key={i}>
                      <b>{a.by}</b> <Time value={a.at} />
                      {a.reason && <div className="cell-sub">{a.reason}</div>}
                    </li>
                  ))}
                </ul>
              )}
              {p.state === "quarantined" && approvals.length < approvalsRequired && (
                <div className="hint">Two-person rule: {approvalsRequired - approvals.length} more approval(s) from a different approver before it is published.</div>
              )}
            </>
          )}
          <h3>Package</h3>
          <ErrorBanner error={deployErr} />
          <KV rows={[
            ["Needed by", need ? (need.needed ? <><b>{need.needed}</b> endpoint{need.needed === 1 ? "" : "s"}: {need.hostnames.slice(0, 20).join(", ")}{need.hostnames.length > 20 ? " …" : ""}</> : "no endpoint needs it (up to date, not installed, or not applicable)") : "…"],
            ["Vendor", p.vendor],
            ["Kind", <span className="tag">{p.kind}</span>],
            ["Package name", p.package_name ? <Mono>{p.package_name}</Mono> : ""],
            ["Version", p.version],
            ["KB", p.kb],
            ["Product code", p.product_code ? <Mono>{p.product_code}</Mono> : ""],
            ["Severity", <Severity s={p.severity} />],
            ["Release date", p.release_date],
            ["Supersedes", (p.supersedes ?? []).length ? (p.supersedes.map((s) => <Mono key={s}>{s}</Mono>)) : ""],
            ["Superseded by", p.superseded_by ? <Link to={`/catalog/${enc(p.superseded_by)}`}><Mono>{p.superseded_by}</Mono></Link> : ""],
            ["Prerequisites", (p.prerequisites ?? []).length ? p.prerequisites.map((s) => <Mono key={s}>{s}</Mono>) : ""],
            ["Bundle", <Link to="/intake"><Mono>{p.bundle_id}</Mono></Link>],
          ]} />
          <h3>Applicability</h3>
          <KV rows={[
            ["OS", p.applicability?.os],
            ["Arch", p.applicability?.arch],
            ["Build range", p.applicability ? `${p.applicability.min_build || "any"} – ${p.applicability.max_build || "any"}` : ""],
            ["Editions", (p.applicability?.editions ?? []).length ? p.applicability.editions!.map((e) => <span key={e} className="tag">{e}</span>) : "any"],
          ]} />
          <h3>Content</h3>
          <KV rows={[
            ["File", <Mono>{p.file_name}</Mono>],
            ["Size", `${fmtBytes(p.size)} (${(p.size ?? 0).toLocaleString()} bytes)`],
            ["SHA-256", <Mono title={p.sha256}>{p.sha256}</Mono>],
            ["Source URL", p.source_url ? <span className="break">{p.source_url}</span> : ""],
          ]} />
          <h3>Vendor signature</h3>
          <KV rows={[
            ["Status", p.vendor_signature?.status ? <Pill state={sigTone(p.vendor_signature.status)} label={p.vendor_signature.status} /> : ""],
            ["Signer", p.vendor_signature?.signer],
            ["Checked", <Time value={p.vendor_signature?.checked_at} />],
          ]} />
          <div className="hint">Recorded by pmctl at acquisition; not re-executed in the isolated zone.</div>
          <h3>State</h3>
          <KV rows={[
            ["State", <Pill state={p.state} />],
            ["Reason", p.state_reason],
            ["By", p.state_by],
            ["At", <Time value={p.state_at} />],
            ["Created", <Time value={p.created_at} />],
          ]} />
          <div className="panel-foot">
            <Link to={`/audit?package_id=${enc(p.package_id)}`}>Audit trail for this package →</Link>
            <span className="muted small"> sha {shortHash(p.sha256)}</span>
          </div>
        </>
      )}
      {action && p && (
        <ReasonModal
          title={`${action[0].toUpperCase()}${action.slice(1)} package`}
          description={
            <>
              <b>{p.title || p.package_id}</b>
              <div className="muted small">
                {action === "approve" && (approvals.length + 1 < approvalsRequired
                  ? `Records your approval (${approvals.length + 1} of ${approvalsRequired}). The package is published only after another approver also approves.`
                  : "Copies the content into the immutable repository and makes it deployable.")}
                {action === "reject" && "Rejects the package. It will never become deployable."}
                {action === "revoke" && "Stops new assignments. Active deployments of this package are cancelled automatically."}
              </div>
            </>
          }
          confirmLabel={action[0].toUpperCase() + action.slice(1)}
          danger={action !== "approve"}
          onClose={() => setAction(null)}
          onSubmit={(r) => run(action, r)}
        />
      )}
    </aside>
  );
}

function sigTone(status: string): string {
  const s = status.toLowerCase();
  if (s === "valid" || s === "ok" || s === "verified") return "verified";
  if (s === "unknown" || s === "notsigned" || s === "not_checked" || s === "") return "stale";
  return "failed";
}
