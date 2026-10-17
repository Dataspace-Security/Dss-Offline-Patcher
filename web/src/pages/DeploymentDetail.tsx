import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, enc } from "../api";
import { useCan } from "../auth";
import { CountsBar, Empty, ErrorBanner, KV, Mono, PageHeader, Pill, ReasonModal, RelTime, TargetPill, Time, targetLabel } from "../components/ui";
import type { Deployment, DeploymentDetail, Package } from "../types";
import { useLoad } from "../util";
import { REBOOT_POLICIES, ringLabel } from "./Deployments";

type Action = "pause" | "resume" | "cancel" | "advance";

export default function DeploymentDetailPage() {
  const { id = "" } = useParams();
  const canOperate = useCan("operator");
  const { data: d, error, reload, loadedAt } = useLoad(
    () => api.get<DeploymentDetail>(`/api/deployments/${enc(id)}`), [id], 5000);
  const pkg = useLoad(() => (d ? api.get<Package>(`/api/packages/${enc(d.package_id)}`) : Promise.resolve(null)), [d?.package_id]);
  const [action, setAction] = useState<Action | null>(null);
  const [ringFilter, setRingFilter] = useState<string>("");
  const [stateFilter, setStateFilter] = useState<string>("");

  const targets = useMemo(() => {
    const t = d?.targets ?? [];
    return t
      .filter((x) => ringFilter === "" || String(x.ring) === ringFilter)
      .filter((x) => stateFilter === "" || x.state === stateFilter)
      .sort((a, b) => a.ring - b.ring || a.hostname.localeCompare(b.hostname));
  }, [d, ringFilter, stateFilter]);

  const run = async (a: Action, reason: string) => {
    await api.post<Deployment>(`/api/deployments/${enc(id)}/${a}`, { reason });
    await reload();
  };

  if (!d) {
    return (
      <>
        <PageHeader title="Deployment" sub={<Link to="/deployments">← Deployments</Link>} />
        <ErrorBanner error={error} />
      </>
    );
  }

  const total = d.rings?.length ?? 0;
  const canAdvance = d.state === "active" && d.current_ring < total - 1;
  const ringName = (i: number) => d.rings?.[i]?.name ?? `ring ${i + 1}`;
  const states = Array.from(new Set((d.targets ?? []).map((t) => t.state))).sort();
  const rollback = d.operation === "rollback";
  const lost = (d.targets ?? []).filter((t) => t.state === "lost_after_install");
  const deferred = (d.targets ?? []).filter((t) => t.state === "deferred");
  const p = pkg.data;
  const canRollBack = !rollback && p && (p.state === "approved" || p.state === "revoked");

  return (
    <>
      <PageHeader
        title={<>{d.name || d.deployment_id} {d.emergency && <span className="flag-emergency">EMERGENCY</span>}{rollback && <span className="flag-emergency flag-rollback">ROLLBACK</span>}</>}
        sub={<><Link to="/deployments">← Deployments</Link> · <Mono>{d.deployment_id}</Mono> · updated <RelTime value={new Date(loadedAt || Date.now()).toISOString()} /></>}
      >
        <Pill state={d.state} />
        {canOperate && d.state === "active" && <button className="btn" onClick={() => setAction("pause")}>Pause…</button>}
        {canOperate && d.state === "paused" && <button className="btn btn-primary" onClick={() => setAction("resume")}>Resume…</button>}
        {canOperate && canAdvance && <button className="btn btn-primary" onClick={() => setAction("advance")}>Advance ring…</button>}
        {canOperate && (d.state === "active" || d.state === "paused") &&
          <button className="btn btn-danger" onClick={() => setAction("cancel")}>Cancel…</button>}
        {canOperate && canRollBack && (p.rollback_unsupported
          ? <button className="btn" disabled title={p.rollback_unsupported}>Rollback not supported</button>
          : d.state === "active" || d.state === "paused"
          ? <button className="btn" disabled title="Cancel this deployment first: an install and a rollback of the same package cannot run at the same time">Roll back…</button>
          : <Link className="btn btn-danger-ghost" to={`/deployments/new?operation=rollback&package_id=${enc(d.package_id)}`}
              title="Create a rollback deployment: agents uninstall this package, ring by ring">Roll back…</Link>)}
      </PageHeader>
      <ErrorBanner error={error} />
      {d.state_reason && (
        <div className={`banner ${d.state === "paused" || d.state === "cancelled" ? "banner-warn" : "banner-info"}`}>
          <b>{d.state}:</b> {d.state_reason}
        </div>
      )}
      {d.emergency && (
        <div className="banner banner-error"><b>Emergency justification:</b> {d.justification || "—"}</div>
      )}
      {rollback && (
        <div className="banner banner-warn">
          <b>Rollback:</b> agents uninstall <Mono>{d.package_id}</Mono> ({p?.kind === "msu" ? `wusa /uninstall /kb:${(p.kb || "").replace(/^KB/i, "")}` : p?.kind === "msi" ? `msiexec /x ${p.product_code}` : p?.kind === "deb" ? `dpkg -r ${p.package_name}` : p?.kind === "rpm" ? `rpm -e ${p.package_name}` : "uninstall"}).
          {" "}Verified = inventory no longer shows it. Justification: {d.justification || "—"}
        </div>
      )}
      {lost.length > 0 && (
        <div className="banner banner-error">
          <b>{lost.length} endpoint{lost.length === 1 ? "" : "s"} stopped checking in after {rollback ? "the uninstall" : "installing"}:</b>{" "}
          {lost.map((t, i) => <span key={t.endpoint_id}>{i > 0 && ", "}<Link to={`/endpoints/${enc(t.endpoint_id)}`}>{t.hostname || t.endpoint_id}</Link></span>)}.
          {" "}They count as failures towards auto-pause. Check them (boot failure?) before resuming; they recover automatically when they check in and verify.
        </div>
      )}
      {deferred.length > 0 && (
        <div className="banner banner-info">
          <b>{deferred.length} deferred</b> by pre-install checks (free disk space / battery) — retried at each check-in, not counted as failures.
        </div>
      )}

      <div className="grid-2">
        <section className="card">
          <h2>Progress</h2>
          <CountsBar counts={d.counts ?? {}} rollback={rollback} />
          <div className="rings-progress">
            {(d.rings ?? []).map((r, i) => {
              const cls = d.state === "completed" || i < d.current_ring ? "done" : i === d.current_ring ? "current" : "future";
              return (
                <div key={i} className={`ring-step ring-${cls}`}>
                  <div className="ring-num">{i + 1}</div>
                  <div>
                    <div className="ring-name">{r.name}</div>
                    <div className="cell-sub">{(r.groups ?? []).join(", ")}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
        <section className="card">
          <h2>Settings</h2>
          <KV rows={[
            ["Package", <Link to={`/catalog/${enc(d.package_id)}`}><Mono>{d.package_id}</Mono></Link>],
            ["Operation", rollback ? <Pill state="failed" label="rollback (uninstall)" /> : "install"],
            ["Current ring", `${ringLabel(d)} · ${ringName(Math.min(d.current_ring, total - 1))}`],
            ["Max failure", `${d.max_failure_pct}%`],
            ["Max retries", String(d.max_retries)],
            ["Window (UTC)", d.window_start || d.window_end ? `${d.window_start || "?"} – ${d.window_end || "?"}` : "always"],
            ["Deadline", d.deadline ? <Time value={d.deadline} /> : "none"],
            ["Max concurrent", d.max_concurrent ? String(d.max_concurrent) : "unlimited"],
            ["Reboot policy", REBOOT_POLICIES.find((r) => r.value === d.reboot_policy)?.label ?? (d.reboot_policy || "never")],
            ["Maint. windows", d.ignore_windows ? <Pill state="pending" label="ignored" /> : "respected"],
            ["Health checks", (d.health_checks ?? []).length
              ? (d.health_checks.map((c, i) => <span key={i} className="tag">{c.type === "tcp_listening" ? `tcp :${c.name}` : `service ${c.name}`}</span>))
              : "none"],
            ["Created", <><Time value={d.created_at} /> by {d.created_by}</>],
            ["Updated", <Time value={d.updated_at} />],
          ]} />
          <div className="panel-foot"><Link to={`/audit?object_id=${enc(d.deployment_id)}`}>Audit trail →</Link></div>
        </section>
      </div>

      <section className="section">
        <div className="section-head">
          <h2>Targets <span className="muted">· {(d.targets ?? []).length}</span></h2>
          <div className="filters">
            <select value={ringFilter} onChange={(e) => setRingFilter(e.target.value)}>
              <option value="">All rings</option>
              {(d.rings ?? []).map((r, i) => <option key={i} value={String(i)}>{i + 1}. {r.name}</option>)}
            </select>
            <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
              <option value="">All states</option>
              {states.map((s) => <option key={s} value={s}>{targetLabel(s, d.operation)}</option>)}
            </select>
          </div>
        </div>
        {targets.length === 0 ? <Empty>No targets{ringFilter || stateFilter ? " match the filter" : " yet"}.</Empty> : (
          <table className="table">
            <thead>
              <tr><th>Hostname</th><th>Ring</th><th>State</th><th className="num">Attempts</th><th className="num">Exit code</th><th>Health</th><th>Detail</th><th>Updated</th></tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.endpoint_id}>
                  <td><Link to={`/endpoints/${enc(t.endpoint_id)}`}>{t.hostname || t.endpoint_id}</Link></td>
                  <td>{t.ring + 1}. {ringName(t.ring)}</td>
                  <td><TargetPill state={t.state} operation={t.operation} /></td>
                  <td className="num">{t.attempts}</td>
                  <td className="num"><Mono>{t.exit_code}</Mono></td>
                  <td>{t.health ? <span title={t.health_detail || undefined}><Pill state={t.health === "ok" ? "verified" : "failed"} label={t.health} /></span> : <span className="muted">—</span>}
                    {t.health === "failed" && t.health_detail && <div className="cell-sub">{t.health_detail}</div>}</td>
                  <td className="detail-cell">{t.detail || <span className="muted">—</span>}</td>
                  <td className="nowrap"><RelTime value={t.updated_at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {action && (
        <ReasonModal
          title={{ pause: "Pause deployment", resume: "Resume deployment", cancel: "Cancel deployment", advance: "Advance to next ring" }[action]}
          description={
            action === "advance" ? <>Move from ring <b>{ringName(d.current_ring)}</b> to <b>{ringName(d.current_ring + 1)}</b>. The server refuses if the current ring still has in-flight targets.</>
              : action === "cancel" ? "Cancelling is final. No further assignments will be issued."
              : action === "pause" ? "Stops new assignments until resumed."
              : "New assignments will be issued for the current ring again."
          }
          confirmLabel={{ pause: "Pause", resume: "Resume", cancel: "Cancel deployment", advance: "Advance" }[action]}
          danger={action === "cancel"}
          required={action !== "advance"}
          onClose={() => setAction(null)}
          onSubmit={(r) => run(action, r)}
        />
      )}
    </>
  );
}
