import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api, enc, qs } from "../api";
import { paths } from "../paths";
import { useCan, useMe } from "../auth";
import { LifecycleTimeline } from "../components/LifecycleTimeline";
import { FleetLine, PatchThis } from "../components/PatchThis";
import { approvedBy, fetchFleet, fetchPolicy } from "../components/patchPlan";
import { CopyBox, Empty, ErrorBanner, KV, Mono, PageHeader, Pill, ReasonModal, Time, expandRowProps } from "../components/ui";
import type { Package, PackageFleet, PackageKind, PackageState } from "../types";
import { fmtBytes, shortHash, useLoad } from "../util";
import "../patch.css";

const STATES: PackageState[] = ["quarantined", "approved", "rejected", "revoked"];

/** Kind filter: Windows updates (.msu), applications, or the offpatch agent itself. */
type KindFilter = "" | "windows" | "apps" | "agent";
const KIND_FILTERS: { value: KindFilter; label: string }[] = [
  { value: "", label: "All" }, { value: "windows", label: "Windows" }, { value: "apps", label: "Apps" }, { value: "agent", label: "Agent" },
];
function kindGroup(k: PackageKind): Exclude<KindFilter, ""> {
  return k === "msu" ? "windows" : k === "agent" ? "agent" : "apps";
}

function FleetNum({ n, tone }: { n: number | undefined; tone?: string }) {
  if (n === undefined) return <span className="muted">…</span>;
  return n ? <b className={tone ? `text-${tone}` : undefined}>{n}</b> : <span className="muted">0</span>;
}

export default function Catalog() {
  const [sp, setSp] = useSearchParams();
  const state = sp.get("state") ?? "";
  const kind = (sp.get("kind") ?? "") as KindFilter;
  const onlyNeeded = sp.get("needed") === "1";
  const { packageId } = useParams();
  const navigate = useNavigate();
  const list = useLoad(() => api.get<Package[]>(`/api/packages${qs({ state })}`), [state], 30000);
  const needs = useLoad(fetchFleet, [], 60000);
  const setParam = (k: string, v: string) => {
    const n = new URLSearchParams(sp);
    if (v) n.set(k, v); else n.delete(k);
    setSp(n);
  };
  const all = list.data ?? [];
  const kindCount = (k: KindFilter) => all.filter((p) => !k || kindGroup(p.kind) === k).length;
  const fleetOf = (id: string): PackageFleet | undefined => needs.data?.[id];
  const rows = all.filter((p) => (!kind || kindGroup(p.kind) === kind) && (!onlyNeeded || (fleetOf(p.package_id)?.needed ?? 0) > 0));
  const num = (id: string, f: (x: PackageFleet) => number) => (needs.data ? (fleetOf(id) ? f(fleetOf(id)!) : 0) : undefined);

  const select = (id: string | null) =>
    navigate({ pathname: paths.catalog(id), search: sp.toString() ? `?${sp}` : "" });

  return (
    <>
      <PageHeader title="Catalog" sub="Packages extracted from validated bundles. Nothing is deployable until approved.">
        <div className="cat-filters">
          <label className="inline-field">
            State
            <select value={state} onChange={(e) => setParam("state", e.target.value)}>
              <option value="">All</option>
              {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="check" title="Only packages that at least one endpoint still needs">
            <input type="checkbox" checked={onlyNeeded} onChange={(e) => setParam("needed", e.target.checked ? "1" : "")} /> needed only
          </label>
        </div>
      </PageHeader>
      <div className="chips">
        {KIND_FILTERS.map((k) => (
          <button key={k.value} className={`chip ${kind === k.value ? "chip-on" : ""}`} onClick={() => setParam("kind", k.value)}>
            {k.label} <b>{list.data ? kindCount(k.value) : "…"}</b>
          </button>
        ))}
      </div>
      <ErrorBanner error={list.error} />
      <ErrorBanner error={needs.error ? `Fleet status: ${needs.error}` : null} />
      <div className={packageId ? "split" : ""}>
        <div className="split-main">
          {list.data && all.length === 0 && !state && (
            <Empty>
              The catalog is empty. Packages arrive in signed bundles: check <Link to={paths.transfers}>Transfers</Link> (what the
              acquisition zone fetched and what came through the transfer).
            </Empty>
          )}
          {list.data && (all.length > 0 || !!state) && rows.length === 0 && (
            <Empty>No packages match{state ? ` state “${state}”` : ""}{kind ? ` · ${kind}` : ""}{onlyNeeded ? " · needed" : ""}.</Empty>
          )}
          {rows.length > 0 && (
            <table className="table">
              <thead>
                <tr>
                  <th>Title</th><th>KB / Product</th><th>Severity</th><th>Kind</th>{!packageId && <th>Size</th>}<th>State</th>
                  <th className="num" title="Endpoints whose inventory shows they still need this patch">Needed</th>
                  <th className="num" title="Inventory already shows it (or a newer version / superseding KB)">Up to date</th>
                  <th className="num" title="Targets in an active or paused deployment that are not finished">Deploying</th>
                  <th className="num" title="Installed by offpatch and confirmed by inventory">Verified</th>
                  <th className="num" title="Failed or lost after install">Failed</th>
                  {!packageId && <th>Created</th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((p) => (
                  <tr key={p.package_id} {...expandRowProps(packageId === p.package_id, () => select(p.package_id))}>
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
                    {!packageId && <td className="nowrap">{fmtBytes(p.size)}</td>}
                    <td>
                      <Pill state={p.state} />
                      {p.state === "quarantined" && (p.approvals_required ?? 0) > 1 && (
                        <div className="cell-sub">{(p.approvals ?? []).length} of {p.approvals_required} approvals</div>
                      )}
                    </td>
                    <td className="num"><FleetNum n={num(p.package_id, (f) => f.needed)} tone="amber" /></td>
                    <td className="num"><FleetNum n={num(p.package_id, (f) => f.up_to_date)} /></td>
                    <td className="num">
                      {fleetOf(p.package_id)?.active_deployment_id ? (
                        <Link to={`/deployments/${enc(fleetOf(p.package_id)!.active_deployment_id)}`} onClick={(e) => e.stopPropagation()}
                              title="Open the active deployment">
                          <FleetNum n={num(p.package_id, (f) => f.deploying)} tone="blue" />
                        </Link>
                      ) : <FleetNum n={num(p.package_id, (f) => f.deploying)} tone="blue" />}
                    </td>
                    <td className="num"><FleetNum n={num(p.package_id, (f) => f.verified)} tone="green" /></td>
                    <td className="num"><FleetNum n={num(p.package_id, (f) => f.failed)} tone="red" /></td>
                    {!packageId && <td><Time value={p.created_at} hideRel /></td>}
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
  const needs = useLoad(fetchFleet, [id], 60000);
  const policy = useLoad(fetchPolicy, []);
  const need = needs.data?.[id];
  const canApprove = useCan("approver");
  const canDeploy = useCan("operator");
  const me = useMe();
  const [action, setAction] = useState<Action | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [justApproved, setJustApproved] = useState(false);
  const [patching, setPatching] = useState(false);
  const navigate = useNavigate();

  const run = async (a: Action, reason: string) => {
    const updated = await api.post<Package>(`/api/packages/${enc(id)}/${a}`, { reason });
    setData(updated);
    setNotice(a === "approve" && updated.state === "quarantined"
      ? `Recorded; needs another approver (${(updated.approvals ?? []).length} of ${updated.approvals_required || "?"} approvals).`
      : null);
    setJustApproved(a === "approve" && updated.state === "approved");
    void needs.reload();
    onChanged();
  };

  const approvals = p?.approvals ?? [];
  const approvalsRequired = p?.approvals_required ?? 0;
  const alreadyApproved = approvedBy(p ?? undefined, me);
  const sod = !!policy.data?.separation_of_duties;

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
            {p.state === "approved" && canDeploy && (
              <button className="btn btn-primary" onClick={() => setPatching(true)}
                      title="Guided deployment: Standard (test machines first, then all machines), Emergency, or the full form">
                Patch this…
              </button>
            )}
            {(p.state === "approved" || p.state === "revoked") && canDeploy && (p.rollback_unsupported
              ? <button className="btn" disabled title={p.rollback_unsupported}>Rollback not supported</button>
              : <button className="btn btn-danger-ghost" title="Agents uninstall this package, stage by stage"
                  onClick={() => navigate(`/deployments/new?operation=rollback&package_id=${enc(p.package_id)}`)}>Roll back…</button>)}
            {p.state === "approved" && canApprove && (
              <button className="btn btn-danger" onClick={() => setAction("revoke")}>Revoke…</button>
            )}
          </div>
          {p.superseded_by && (
            <div className="banner banner-warn">Superseded by <Link to={paths.catalog(p.superseded_by)}><Mono>{p.superseded_by}</Mono></Link>; prefer deploying the newer package.</div>
          )}
          {p.state === "quarantined" && !canApprove && (
            <div className="hint">Approval requires the approver role.</div>
          )}
          {p.state === "quarantined" && canApprove && sod && !alreadyApproved && (
            <div className="hint">Separation of duties is on: if you approve this package, another operator must deploy it.</div>
          )}
          {notice && <div className="banner banner-info">{notice}</div>}
          {justApproved && p.state === "approved" && (
            <div className="banner banner-ok next-step">
              <span><b>Approved.</b> {need && <><b>{need.needed}</b> endpoint{need.needed === 1 ? "" : "s"} need it.</>}</span>
              {sod ? (
                <span>Separation of duties is on: hand it to an operator. <CopyBox value={`${window.location.origin}${paths.catalog(p.package_id)}`} /></span>
              ) : canDeploy ? (
                <button className="btn btn-sm btn-primary" onClick={() => setPatching(true)}>Patch this…</button>
              ) : (
                <span>Hand off to an operator to deploy it.</span>
              )}
            </div>
          )}
          <h3>Fleet</h3>
          {need ? (
            <>
              <div className="fleet-grid">
                {([["needs it", need.needed, "amber"], ["up to date", need.up_to_date, ""], ["not installed", need.not_installed, ""],
                   ["deploying", need.deploying, "blue"], ["verified", need.verified, "green"], ["failed", need.failed, "red"]] as [string, number, string][]).map(([l, n, t]) => (
                  <div key={l} className="fleet-cell"><div className={`n ${n && t ? `text-${t}` : ""}`}>{n ?? 0}</div><div className="l">{l}</div></div>
                ))}
              </div>
              {(need.exception ?? 0) > 0 && <div className="hint">{need.exception} active exception{need.exception === 1 ? "" : "s"}.</div>}
              {need.active_deployment_id && (
                <div className="hint">Deploying in <Link to={`/deployments/${enc(need.active_deployment_id)}`}><Mono>{need.active_deployment_id}</Mono></Link>.</div>
              )}
            </>
          ) : (
            <div className="muted small">{needs.error ? `Fleet status unavailable: ${needs.error}` : needs.data ? <FleetLine fleet={null} /> : "…"}</div>
          )}
          <LifecycleTimeline pkg={p} fleet={need} />
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
          <KV rows={[
            ["Needed by", need ? (need.needed ? <><b>{need.needed}</b> endpoint{need.needed === 1 ? "" : "s"}: {need.hostnames.slice(0, 20).join(", ")}{need.hostnames.length > 20 ? " …" : ""}</> : "no endpoint needs it (up to date, not installed, or not applicable)") : "…"],
            ["Vendor", p.vendor],
            ["Kind", <span className="tag">{p.kind}</span>],
            ["Rollback", p.rollback_unsupported ? <span className="text-amber">not supported — {p.rollback_unsupported}</span> : "supported (uninstall via rollback deployment)"],
            ["Package name", p.package_name ? <Mono>{p.package_name}</Mono> : ""],
            ["Version", p.version],
            ["KB", p.kb],
            ["Product code", p.product_code ? <Mono>{p.product_code}</Mono> : ""],
            ["Severity", <Severity s={p.severity} />],
            ["Release date", p.release_date],
            ["Supersedes", (p.supersedes ?? []).length ? (p.supersedes.map((s) => <Mono key={s}>{s}</Mono>)) : ""],
            ["Superseded by", p.superseded_by ? <Link to={paths.catalog(p.superseded_by)}><Mono>{p.superseded_by}</Mono></Link> : ""],
            ["Prerequisites", (p.prerequisites ?? []).length ? p.prerequisites.map((s) => <Mono key={s}>{s}</Mono>) : ""],
            ["Bundle", <Link to={paths.transfers}><Mono>{p.bundle_id}</Mono></Link>],
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
            <Link to={paths.audit({ package_id: p.package_id })}>Audit trail for this package →</Link>
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
      {patching && p && (
        <PatchThis packageId={p.package_id} onClose={() => setPatching(false)} onChanged={(u) => { setData(u); onChanged(); }} />
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
