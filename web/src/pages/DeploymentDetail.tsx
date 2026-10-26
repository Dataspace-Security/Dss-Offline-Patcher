import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api, enc } from "../api";
import { paths } from "../paths";
import { useCan } from "../auth";
import { ApprovalPanel, DeploymentStatePill } from "../components/DeploymentApproval";
import { KindTag, TargetDetailText, isAgentTooOld, isExePackage, rollbackBlocker, signerText } from "../components/exeParts";
import { fetchPolicy, isAgentPackage } from "../components/patchPlan";
import { CountsBar, Empty, ErrorBanner, KV, Mono, PageHeader, Pill, ReasonModal, Time, targetLabel } from "../components/ui";
import { TargetProgress } from "../components/TargetProgress";
import { AskApproverModal, RaiseExceptionModal } from "../components/TargetException";
import {
  IN_FLIGHT, exhaustedInCurrentRing, isExhausted, isFailing, isLiveDeployment, readyToAdvance, ringSummaries, type RingSummary,
} from "../components/rollout";
import { usePageVisible } from "../components/usePageVisible";
import type { Deployment, DeploymentDetail, Endpoint, Package, Target } from "../types";
import { parseTime, relTime, useLoad } from "../util";
import { ClockProvider, useClock } from "../components/Clock";
import { REBOOT_POLICIES } from "./Deployments";
import { AUTO_NEXT_HINT, stageGroupsText, stageLabel } from "../components/deployLabels";
import "../ops.css";

type Action = "pause" | "resume" | "cancel" | "advance" | "retry_failed";

const FAST_POLL_MS = 3000;
const SLOW_POLL_MS = 30000;

// Failing first, then work in progress, then waiting, then done.
function targetRank(t: Target): number {
  if (isFailing(t)) return 0;
  if (IN_FLIGHT.includes(t.state)) return 1;
  if (t.state === "pending" || t.state === "deferred") return 2;
  return 3;
}

export default function DeploymentDetailPage() {
  const { id = "" } = useParams();
  const isUser = useCan("user");
  const isSuper = useCan("super_admin");
  // Exceptions are an Admin decision; Users can ask an Admin; viewers see no actions.
  const canException = useCan("admin");
  const policy = useLoad(fetchPolicy, []);
  const visible = usePageVisible();
  const [live, setLive] = useState(true); // until the first load says otherwise
  const pollMs = visible && live ? FAST_POLL_MS : SLOW_POLL_MS;
  const { data: d, error, reload, loadedAt } = useLoad(
    () => api.get<DeploymentDetail>(`/api/deployments/${enc(id)}`), [id, pollMs], pollMs);
  useEffect(() => { if (d) setLive(isLiveDeployment(d)); }, [d]);
  const pkg = useLoad(() => (d ? api.get<Package>(`/api/packages/${enc(d.package_id)}`) : Promise.resolve(null)), [d?.package_id]);
  // Last contact per endpoint (check-ins); live heartbeats are newer when present.
  const eps = useLoad(() => (isLiveDeployment(d) ? api.get<Endpoint[]>("/api/endpoints") : Promise.resolve(null)), [live, !!d], SLOW_POLL_MS);
  // How long a silent agent gets before "confirming by inventory" turns into
  // a staleness warning: a multiple of the site's own configured check-in
  // interval (not a flat guess), so a longer-than-default interval doesn't
  // read as every install's verification being stuck.
  const sysCfg = useLoad(() => api.get<{ agents: { checkin_interval_seconds: number } }>("/api/system"), [], SLOW_POLL_MS);
  const staleAfterSec = Math.max(180, (sysCfg.data?.agents.checkin_interval_seconds ?? 60) * 3);
  const [action, setAction] = useState<Action | null>(null);
  const [ringFilter, setRingFilter] = useState<string>("");
  const [stateFilter, setStateFilter] = useState<string>("");
  // Machines the package does not apply to are hidden unless asked for.
  const [showNA, setShowNA] = useState(false);
  const [excFor, setExcFor] = useState<Target | null>(null);

  const lastSeen = useMemo(() => {
    const m = new Map<string, string>();
    for (const e of eps.data ?? []) m.set(e.endpoint_id, e.last_seen);
    return m;
  }, [eps.data]);

  const targets = useMemo(() => {
    const t = d?.targets ?? [];
    return t
      .filter((x) => ringFilter === "" || String(x.ring) === ringFilter)
      .filter((x) => stateFilter === "" || (stateFilter === "_failing" ? isFailing(x) : x.state === stateFilter))
      .filter((x) => showNA || stateFilter === "not_applicable" || x.state !== "not_applicable")
      .sort((a, b) => a.ring - b.ring || targetRank(a) - targetRank(b) || a.hostname.localeCompare(b.hostname));
  }, [d, ringFilter, stateFilter, showNA]);

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
  const ringName = (i: number) => stageLabel(d.rings?.[i]?.name, i);
  const naCount = (d.targets ?? []).filter((t) => t.state === "not_applicable").length;
  const states = Array.from(new Set((d.targets ?? []).map((t) => t.state))).sort();
  const rollback = d.operation === "rollback";
  const lost = (d.targets ?? []).filter((t) => t.state === "lost_after_install");
  const deferred = (d.targets ?? []).filter((t) => t.state === "deferred");
  const oldAgent = (d.targets ?? []).filter((t) => t.state === "not_applicable" && isAgentTooOld(t.detail));
  const failing = (d.targets ?? []).filter(isFailing);
  const exhausted = exhaustedInCurrentRing(d);
  const rings = ringSummaries(d);
  const ready = readyToAdvance(d);
  // auto_advance: the server starts the next stage by itself once the current one finished without too many failures.
  const autoNext = !!d.auto_advance && total > 1;
  const isLive = isLiveDeployment(d);
  const pending = d.state === "pending_approval";
  const liveCount = (d.targets ?? []).filter((t) => t.live).length;
  const p = pkg.data;
  // Running an agent-version rollout (pause, resume, next stage, retry,
  // cancel) is the vendor's, like creating it (server: 403 for bank roles).
  const canOperate = isUser && (isSuper || !p || !isAgentPackage(p));
  // Rolling back an agent version is the vendor's (super admin) call, like deploying it.
  const canRollBack = !rollback && p && (p.state === "approved" || p.state === "revoked") && (isSuper || !isAgentPackage(p));
  const lastContact = (t: Target): string | undefined => {
    const a = parseTime(t.live?.at);
    const b = parseTime(lastSeen.get(t.endpoint_id));
    if (a && (!b || a > b)) return t.live?.at;
    return lastSeen.get(t.endpoint_id);
  };

  return (
    <ClockProvider ms={1000}>
      <PageHeader
        title={<>{d.name || d.deployment_id} {d.emergency && <span className="flag-emergency">EMERGENCY</span>}{rollback && <span className="flag-emergency flag-rollback">ROLLBACK</span>}</>}
        sub={<>
          <Link to="/deployments">← Deployments</Link> · <Mono>{d.deployment_id}</Mono> ·{" "}
          {isLive && visible
            ? <span className="live-badge"><span className="live-dot" />Live · every {FAST_POLL_MS / 1000}s{liveCount > 0 && <> · {liveCount} agent{liveCount === 1 ? "" : "s"} reporting</>}</span>
            : <span className="muted">refresh every {SLOW_POLL_MS / 1000}s</span>}
          {" "}· updated {loadedAt ? <ClockRel value={new Date(loadedAt).toISOString()} /> : "—"}
        </>}
      >
        <DeploymentStatePill d={d} policy={policy.data} />
        {canOperate && d.state === "active" && <button className="btn" onClick={() => setAction("pause")}>Pause…</button>}
        {canOperate && d.state === "paused" && <button className="btn btn-primary" onClick={() => setAction("resume")}>Resume…</button>}
        {canOperate && canAdvance && <button className="btn btn-primary" onClick={() => setAction("advance")}>Start next stage…</button>}
        {canOperate && isLive && exhausted.length > 0 &&
          <button className="btn" onClick={() => setAction("retry_failed")} title="Reset the attempts of failed targets in the current stage">Retry failed ({exhausted.length})…</button>}
        {canOperate && (isLive || pending) &&
          <button className="btn btn-danger" onClick={() => setAction("cancel")}>Cancel…</button>}
        {canOperate && canRollBack && (rollbackBlocker(p)
          ? <button className="btn" disabled title={`Rollback: ${rollbackBlocker(p)}`}>Rollback not supported</button>
          : isLive || pending
          ? <button className="btn" disabled title="Cancel this deployment first: an install and a rollback of the same package cannot run at the same time">Roll back…</button>
          : <Link className="btn btn-danger-ghost" to={`/deployments/new?operation=rollback&package_id=${enc(d.package_id)}`}
              title="Create a rollback deployment: agents uninstall this package, stage by stage">Roll back…</Link>)}
      </PageHeader>
      <ErrorBanner error={error} />
      <ApprovalPanel d={d} policy={policy.data} onChanged={reload} />
      {d.state_reason && d.state !== "rejected" && d.state !== "pending_approval" && (
        <div className={`banner ${d.state === "paused" || d.state === "cancelled" ? "banner-warn" : "banner-info"}`}>
          <b>{d.state}:</b> {d.state_reason}
        </div>
      )}
      {ready && autoNext && !ready.empty && (
        <div className="banner banner-ok next-step">
          <div>
            <b>{stageLabel(ready.name, ready.index)} finished:</b>{" "}
            {ready.verified} verified, {ready.failed} failed{ready.skipped ? `, ${ready.skipped} not applicable / excepted` : ""}.
            {" "}<b>{ringName(ready.index + 1)}</b> starts automatically in a moment.
          </div>
          {canOperate && <button className="btn" onClick={() => setAction("advance")}>Start it now…</button>}
        </div>
      )}
      {ready && !(autoNext && !ready.empty) && (
        <div className="banner banner-ok next-step">
          <div>
            <b>{ready.empty ? `${stageLabel(ready.name, ready.index)} has no endpoints.` : `${stageLabel(ready.name, ready.index)} finished:`}</b>{" "}
            {ready.empty
              ? <>No endpoint was in {ready.groups.length ? ready.groups.map((g) => <span key={g} className="tag">{g}</span>) : "its groups"} when it was approved (machines added later are left out). The deployment waits here until the next stage is started.</>
              : <>{ready.verified} verified, {ready.failed} failed{ready.skipped ? `, ${ready.skipped} not applicable / excepted` : ""}.</>}
            {" "}Start <b>{ringName(ready.index + 1)}</b>?
          </div>
          {canOperate
            ? <button className="btn btn-primary" onClick={() => setAction("advance")}>Start {ringName(ready.index + 1)}…</button>
            : <span className="muted">{p && isAgentPackage(p) ? "The vendor (super admin) starts the next stage." : "A User or Admin starts the next stage."}</span>}
        </div>
      )}
      {d.state === "paused" && (
        <section className="card paused-help">
          <h2>Paused — what to do</h2>
          {failing.length === 0
            ? <p className="muted">No failing targets right now. Resume when ready.</p>
            : (
              <>
                <p><b>{failing.length}</b> target{failing.length === 1 ? "" : "s"} caused or count towards the pause (threshold {d.max_failure_pct}%):</p>
                <table className="table table-compact">
                  <thead><tr><th>Hostname</th><th>Stage</th><th>State</th><th className="num">Exit code</th><th className="num">Attempts</th><th>Detail</th></tr></thead>
                  <tbody>
                    {failing.map((t) => (
                      <tr key={t.endpoint_id}>
                        <td><Link to={`/endpoints/${enc(t.endpoint_id)}`}>{t.hostname || t.endpoint_id}</Link></td>
                        <td>{ringName(t.ring)}</td>
                        <td><Pill state={t.state} label={targetLabel(t.state, t.operation)} />{t.health === "failed" && <Pill state="failed" label="health" />}</td>
                        <td className="num"><Mono>{t.exit_code}</Mono></td>
                        <td className="num">{t.attempts}{isExhausted(t, d) && <div className="cell-sub">no retries left</div>}</td>
                        <td className="detail-cell">{t.detail ? <TargetDetailText detail={t.detail} /> : t.health_detail || <span className="muted">—</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          <ol className="recovery">
            <li>Open the failing endpoints and read the exit code and detail (disk full, installer busy, missing prerequisite…).</li>
            <li>Fix the cause, then <b>Retry failed</b> to reset their attempts{canOperate && exhausted.length > 0 && <> — <button className="btn btn-sm" onClick={() => setAction("retry_failed")}>Retry failed ({exhausted.length})…</button></>}.</li>
            <li>If an endpoint cannot be patched, raise an exception for it (Admin) so it no longer counts as a failure.</li>
            <li><b>Resume</b> the deployment{canOperate && <> — <button className="btn btn-sm btn-primary" onClick={() => setAction("resume")}>Resume…</button></>}.</li>
          </ol>
        </section>
      )}
      {d.emergency && (
        <div className="banner banner-error"><b>Emergency justification:</b> {d.justification || "—"}</div>
      )}
      {rollback && (
        <div className="banner banner-warn">
          <b>Rollback:</b> agents uninstall <Mono>{d.package_id}</Mono> ({p?.kind === "msu" ? `wusa /uninstall /kb:${(p.kb || "").replace(/^KB/i, "")}` : p?.kind === "msi" ? `msiexec /x ${p.product_code}` : p?.kind === "deb" ? `dpkg -r ${p.package_name}` : p?.kind === "rpm" ? `rpm -e ${p.package_name}` : p?.kind === "exe" ? "the app's quiet uninstall from Apps & features" : "uninstall"}).
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
      {oldAgent.length > 0 && (
        <div className="banner banner-warn">
          <b>{oldAgent.length} endpoint{oldAgent.length === 1 ? "" : "s"} skipped (not applicable):</b> the agent is too old for EXE packages.{" "}
          {isSuper
            ? <>Upgrade the agent to 0.9.0 or later on {oldAgent.length === 1 ? "it" : "them"} (<Link to={paths.agentVersions()}>Upgrade agent</Link>), then deploy this package again.</>
            : <>The vendor (super admin) upgrades the agent; then this package can be deployed to {oldAgent.length === 1 ? "it" : "them"}.</>}
        </div>
      )}
      {(d.scope_excluded ?? 0) > 0 && (
        <div className="banner banner-warn">
          <b>{d.scope_excluded} endpoint{d.scope_excluded === 1 ? "" : "s"} left out:</b> {d.scope_excluded === 1 ? "it" : "they"} joined this
          {rollback ? " rollback" : " deployment"}'s groups after it was approved for {d.scope_endpoints ?? 0} endpoint{d.scope_endpoints === 1 ? "" : "s"}.
          {" "}Approval covers only those; create a new {rollback ? "rollback" : "deployment"} (with its own approvals) to include the others.
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
          <CountsBar counts={d.counts ?? {}} rollback={rollback} running={d.state === "active" || d.state === "paused"} />
          <div className="ring-summaries">
            {rings.map((r) => <RingRow key={r.index} r={r} d={d} />)}
          </div>
          {autoNext && d.current_ring < total - 1 && (d.state === "active" || d.state === "paused") && <div className="hint">{AUTO_NEXT_HINT}</div>}
        </section>
        <section className="card">
          <h2>Settings</h2>
          <KV rows={[
            ["Package", <Link to={paths.catalog(d.package_id)}><Mono>{d.package_id}</Mono></Link>],
            ...(p && isExePackage(p) ? [
              ["Kind", <KindTag p={p} />] as [string, ReactNode],
              ["Signer", signerText(p) || "—"] as [string, ReactNode],
              ["Silent arguments", p.exe?.silent_args?.length ? <Mono>{p.exe.silent_args.join(" ")}</Mono> : "—"] as [string, ReactNode],
              ["Detection", p.exe?.detect?.display_name ? <>{p.exe.detect.display_name}{p.exe.detect.display_version ? <> <Mono>{p.exe.detect.display_version}</Mono></> : null}</> : "—"] as [string, ReactNode],
              ["Rollback", rollbackBlocker(p) ? <span className="text-amber">Rollback: {rollbackBlocker(p)}</span> : "supported"] as [string, ReactNode],
            ] : []),
            ["Operation", rollback ? <Pill state="failed" label="rollback (uninstall)" /> : "install"],
            ["Current stage", total ? `${ringName(Math.min(Math.max(d.current_ring, 0), total - 1))} (of ${total})` : "—"],
            ...(total > 1 && d.current_ring < total - 1 ? [["Next stage", autoNext ? "starts automatically once the current stage succeeds" : "started by a User or Admin"] as [string, string]] : []),
            ["Max failure", `${d.max_failure_pct}%`],
            ["Max retries", String(d.max_retries)],
            ["Window (UTC)", d.window_start || d.window_end ? `${d.window_start || "?"} – ${d.window_end || "?"}` : "always"],
            ["Deadline", d.deadline ? <Time value={d.deadline} /> : "none"],
            ["Machines at once", d.max_concurrent ? String(d.max_concurrent) : "no extra limit (network limits apply)"],
            ["Reboot policy", REBOOT_POLICIES.find((r) => r.value === d.reboot_policy)?.label ?? (d.reboot_policy || "never")],
            ["Maint. windows", d.ignore_windows ? <Pill state="pending" label="ignored" /> : "respected"],
            ["Open apps", d.keep_apps_open ? "left open (the machine waits until the app is closed)" : "closed before the update; services stopped and started again"],
            ["Health checks", (d.health_checks ?? []).length
              ? (d.health_checks.map((c, i) => <span key={i} className="tag">{c.type === "tcp_listening" ? `tcp :${c.name}` : `service ${c.name}`}</span>))
              : "none"],
            ["Created", <><Time value={d.created_at} /> by {d.created_by}</>],
            ["Updated", <Time value={d.updated_at} />],
          ]} />
          <div className="panel-foot"><Link to={paths.audit({ object_id: d.deployment_id })}>Audit trail →</Link></div>
        </section>
      </div>

      <section className="section">
        <div className="section-head">
          <h2>Targets <span className="muted">· {(d.targets ?? []).length - naCount}{naCount > 0 && ` (+${naCount} not applicable)`}</span></h2>
          <div className="filters">
            <select value={ringFilter} onChange={(e) => setRingFilter(e.target.value)}>
              <option value="">All stages</option>
              {(d.rings ?? []).map((r, i) => <option key={i} value={String(i)}>{stageLabel(r.name, i)}</option>)}
            </select>
            <select value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
              <option value="">All states</option>
              {failing.length > 0 && <option value="_failing">Failing ({failing.length})</option>}
              {states.map((s) => <option key={s} value={s}>{targetLabel(s, d.operation)}</option>)}
            </select>
            {naCount > 0 && stateFilter !== "not_applicable" && (
              <label className="check small">
                <input type="checkbox" checked={showNA} onChange={(e) => setShowNA(e.target.checked)} /> show {naCount} not applicable
              </label>
            )}
          </div>
        </div>
        {targets.length === 0 ? <Empty>{naCount > 0 && !showNA && !stateFilter && !ringFilter
          ? <>No machine in this deployment needs the package: all {naCount} are not applicable (for example, the app is not installed on them). <button type="button" className="btn-link" onClick={() => setShowNA(true)}>Show them</button></>
          : <>No targets{ringFilter || stateFilter ? " match the filter" : " yet — endpoints in the current stage get a target when they next check in"}.</>}</Empty> : (
          <table className="table targets-live">
            <thead>
              <tr><th>Hostname</th><th>Stage</th><th style={{ width: "26%" }}>Progress</th><th>Last contact</th><th className="num">Attempts</th><th className="num">Exit code</th><th>Health</th><th>Detail</th><th>Updated</th><th /></tr>
            </thead>
            <tbody>
              {targets.map((t) => {
                const contact = lastContact(t);
                const bad = isFailing(t);
                return (
                  <tr key={t.endpoint_id} className={bad ? "row-bad" : ""}>
                    <td><Link to={`/endpoints/${enc(t.endpoint_id)}`}>{t.hostname || t.endpoint_id}</Link></td>
                    <td className="nowrap">{ringName(t.ring)}</td>
                    <td><LiveTargetProgress t={t} currentRing={d.current_ring} deploymentLive={d.state === "active"} lastContact={contact} staleAfterSec={staleAfterSec} /></td>
                    <td className="nowrap">{contact ? <span title={contact}><ClockRel value={contact} /></span> : <span className="muted">—</span>}</td>
                    <td className="num">{t.state === "not_applicable" || t.state === "exception"
                      ? <span className="muted">—</span>
                      : <>{t.attempts}{d.max_retries >= 0 && <span className="muted"> / {d.max_retries + 1}</span>}</>}</td>
                    <td className="num">{t.exit_code || t.state === "failed" ? <Mono>{t.exit_code}</Mono> : <span className="muted">—</span>}</td>
                    <td>{t.health ? <span title={t.health_detail || undefined}><Pill state={t.health === "ok" ? "verified" : "failed"} label={t.health} /></span> : <span className="muted">—</span>}
                      {t.health === "failed" && t.health_detail && <div className="cell-sub">{t.health_detail}</div>}</td>
                    <td className="detail-cell"><TargetDetailText detail={t.detail} /></td>
                    <td className="nowrap"><ClockRel value={t.updated_at} /></td>
                    <td className="nowrap">
                      {bad && !rollback && isUser && (canException
                        ? <button className="btn btn-sm" onClick={() => setExcFor(t)}>Raise exception…</button>
                        : <button className="btn btn-sm" onClick={() => setExcFor(t)} title="Only Admins can create exceptions">Ask an Admin…</button>)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>

      {action && (
        <ReasonModal
          title={{ pause: "Pause deployment", resume: "Resume deployment", cancel: "Cancel deployment", advance: "Start next stage", retry_failed: "Retry failed targets" }[action]}
          description={
            action === "advance" ? <>Finish <b>{ringName(d.current_ring)}</b> and start <b>{ringName(d.current_ring + 1)}</b>. The server refuses if the current stage still has targets in progress.</>
              : action === "cancel" ? (pending ? "Cancelling is final. The deployment never starts." : "Cancelling is final. No further assignments will be issued.")
              : action === "pause" ? "Stops new assignments until resumed."
              : action === "retry_failed" ? <>
                  Reset the attempts of <b>{exhausted.length}</b> failed target{exhausted.length === 1 ? "" : "s"} in <b>{ringName(d.current_ring)}</b>
                  {" "}({exhausted.slice(0, 8).map((t) => t.hostname || t.endpoint_id).join(", ")}{exhausted.length > 8 ? ", …" : ""}); agents try again at their next check-in.
                  {d.state === "paused" && <> The deployment stays paused: resume it afterwards.</>}
                </>
              : "New assignments will be issued for the current stage again."
          }
          confirmLabel={{ pause: "Pause", resume: "Resume", cancel: "Cancel deployment", advance: "Start next stage", retry_failed: "Retry failed" }[action]}
          danger={action === "cancel"}
          required={action !== "advance"}
          onClose={() => setAction(null)}
          onSubmit={(r) => run(action, r)}
        />
      )}
      {excFor && (canException
        ? <RaiseExceptionModal target={excFor} deployment={d} onClose={() => setExcFor(null)} onDone={() => void reload()} />
        : <AskApproverModal target={excFor} deployment={d} onClose={() => setExcFor(null)} />)}
    </ClockProvider>
  );
}

/** Relative time that follows the page clock (only this text re-renders each second). */
function ClockRel({ value }: { value: string | undefined }) {
  return <>{relTime(value, useClock())}</>;
}

function LiveTargetProgress(props: { t: Target; currentRing: number; deploymentLive: boolean; lastContact?: string; staleAfterSec?: number }) {
  return <TargetProgress {...props} now={useClock()} />;
}

function RingRow({ r, d }: { r: RingSummary; d: DeploymentDetail }) {
  const cls = d.state === "completed" || r.index < d.current_ring ? "done" : r.index === d.current_ring ? "current" : "future";
  const reached = r.index <= d.current_ring;
  const pct = (v: number) => (r.total ? `${(v / r.total) * 100}%` : "0%");
  return (
    <div className={`ring-sum ring-${cls}`}>
      <div className="ring-num">{r.index + 1}</div>
      <div className="ring-sum-body">
        <div className="ring-sum-head">
          <span className="ring-name">{stageLabel(r.name, r.index)}</span>
          <span className="cell-sub" title={r.groups.join(", ")}>{stageGroupsText(r.groups)}</span>
          <span className="spacer" />
          {r.finished && <Pill state="verified" label="finished" />}
          {cls === "current" && !r.finished && !r.empty && d.state === "active" && <Pill state="active" label="in progress" />}
        </div>
        {r.empty
          ? <div className="cell-sub">{reached ? "no endpoints in this stage (yet)"
              : d.auto_advance && d.state !== "cancelled" ? `not reached yet · starts automatically once ${stageLabel(d.rings?.[r.index - 1]?.name, r.index - 1)} succeeds`
              : "not reached yet"}</div>
          : (
            <>
              <div className="countbar ring-bar" title={`${r.verified} verified, ${r.failed} failed, ${r.inProgress} in progress, ${r.waiting} waiting, ${r.skipped} skipped`}
                   role="progressbar" aria-label={`${stageLabel(r.name, r.index)}: verified`} aria-valuemin={0} aria-valuemax={r.total} aria-valuenow={r.verified}
                   aria-valuetext={`${r.verified} of ${r.total} verified`}>
                <span className="seg seg-green" style={{ width: pct(r.verified) }} />
                <span className="seg seg-blue" style={{ width: pct(r.inProgress) }} />
                <span className="seg seg-red" style={{ width: pct(r.failed) }} />
                <span className="seg seg-not_applicable" style={{ width: pct(r.skipped) }} />
              </div>
              <div className="ring-sum-text">
                <b className="text-green">{r.verified}</b> verified · <b className={r.failed ? "text-red" : ""}>{r.failed}</b> failed
                {r.exhausted > 0 && <span className="muted"> ({r.exhausted} no retries left)</span>}
                {" "}· <b>{r.inProgress}</b> in progress · {r.waiting} waiting{r.skipped ? ` · ${r.skipped} skipped` : ""}
                <span className="muted"> · {r.total} total</span>
              </div>
            </>
          )}
      </div>
    </div>
  );
}
