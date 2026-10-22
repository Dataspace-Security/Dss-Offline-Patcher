import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, enc, errMsg } from "../api";
import { paths } from "../paths";
import { useCan } from "../auth";
import { AgentSetupGuide } from "../components/AgentSetup";
import { usedPct } from "../components/Hardware";
import { CopyBox, Empty, ErrorBanner, Modal, PageHeader, Pill, RelTime, Time } from "../components/ui";
import type { Endpoint, EndpointStatus, EnrollmentToken } from "../types";
import { fmtBytes, relTime, splitList, useLoad, useNow } from "../util";

const STATUSES: EndpointStatus[] = [
  "lost_after_install", "offline", "stale", "failed", "out_of_support", "pending_reboot", "exception", "noncompliant",
  "updates_available", "awaiting_checkin", "compliant", "retired",
];

/** Site filter value for endpoints without a site. */
const NO_SITE = "(none)";

export default function Endpoints() {
  const canEdit = useCan("user");
  const [sp, setSp] = useSearchParams();
  const statusFilter = splitList(sp.get("status") ?? "");
  const outdatedOnly = sp.get("outdated") === "1";
  const groupFilter = sp.get("group") ?? "";
  const siteFilter = sp.get("site") ?? "";
  const [q, setQ] = useState("");
  const [showToken, setShowToken] = useState(sp.get("enroll") === "1");
  const [showRetired, setShowRetired] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);
  const now = useNow();
  const { data, error, reload } = useLoad(() => api.get<Endpoint[]>("/api/endpoints"), [], 15000);

  // Retired endpoints are hidden unless asked for (toggle, or the "retired" chip).
  const includeRetired = showRetired || statusFilter.includes("retired");

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data ?? [])
      .filter((e) => includeRetired || e.status !== "retired")
      .filter((e) => statusFilter.length === 0 || statusFilter.includes(e.status))
      .filter((e) => !outdatedOnly || missingTotal(e) > 0)
      .filter((e) => !groupFilter || (e.groups ?? []).includes(groupFilter))
      .filter((e) => !siteFilter || (siteFilter === NO_SITE ? !e.site : e.site === siteFilter))
      .filter((e) => !needle || [e.hostname, e.site, e.owner, ...(e.groups ?? [])].join(" ").toLowerCase().includes(needle))
      .sort((a, b) => STATUSES.indexOf(a.status) - STATUSES.indexOf(b.status) || a.hostname.localeCompare(b.hostname));
  }, [data, q, statusFilter.join(","), includeRetired, outdatedOnly, groupFilter, siteFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  const live = (data ?? []).filter((e) => e.status !== "retired");
  const groupOptions = [...new Set(live.flatMap((e) => e.groups ?? []))].sort();
  const siteOptions = [...new Set(live.map((e) => e.site).filter(Boolean))].sort();
  const hasNoSite = live.some((e) => !e.site);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const e of data ?? []) c[e.status] = (c[e.status] ?? 0) + 1;
    return c;
  }, [data]);
  const activeCount = (data ?? []).filter((e) => e.status !== "retired").length;
  const outdatedCount = (data ?? []).filter((e) => e.status !== "retired" && missingTotal(e) > 0).length;

  // Keep the other filters when one changes.
  const setFilters = (status: string[], outdated: boolean, group = groupFilter, site = siteFilter) => {
    const next: Record<string, string> = {};
    if (status.length) next.status = status.join(",");
    if (outdated) next.outdated = "1";
    if (group) next.group = group;
    if (site) next.site = site;
    setSp(next);
  };

  const toggle = (s: string) => {
    const next = statusFilter.includes(s) ? statusFilter.filter((x) => x !== s) : [...statusFilter, s];
    setFilters(next, outdatedOnly);
  };

  // Only rows currently visible (and not retired) are selectable.
  const selectable = rows.filter((e) => e.status !== "retired");
  const visibleSelected = selectable.filter((e) => selected.has(e.endpoint_id));
  const allOn = selectable.length > 0 && visibleSelected.length === selectable.length;
  const toggleOne = (id: string) => {
    const n = new Set(selected);
    if (n.has(id)) n.delete(id); else n.add(id);
    setSelected(n);
  };
  const toggleAll = () => setSelected(allOn ? new Set() : new Set(selectable.map((e) => e.endpoint_id)));

  return (
    <>
      <PageHeader title="Endpoints" sub={`${activeCount} enrolled${counts.retired ? ` · ${counts.retired} retired` : ""} · silent endpoints are shown as offline or stale, never as compliant`}>
        <input className="search" placeholder="Filter host, group, site, owner…" value={q} onChange={(e) => setQ(e.target.value)} />
        {canEdit && <Link className="btn" to={paths.addEndpoints}>Agent setup guide</Link>}
        {canEdit && <button className="btn btn-primary" onClick={() => setShowToken(true)}>Create enrollment token</button>}
      </PageHeader>
      <div className="chips">
        {STATUSES.map((s) => (
          <button key={s} className={`chip ${statusFilter.includes(s) ? "chip-on" : ""}`} onClick={() => toggle(s)}>
            <Pill state={s} /> <b>{counts[s] ?? 0}</b>
          </button>
        ))}
        <button className={`chip ${outdatedOnly ? "chip-on" : ""}`} onClick={() => setFilters(statusFilter, !outdatedOnly)}
                title="Endpoints missing at least one Windows update or application update (from update intelligence)">
          <Pill state="noncompliant" label="outdated only" /> <b>{outdatedCount}</b>
        </button>
        <select className="chip-select" aria-label="Group" value={groupFilter} onChange={(e) => setFilters(statusFilter, outdatedOnly, e.target.value, siteFilter)}>
          <option value="">All groups</option>
          {groupOptions.map((g) => <option key={g} value={g}>Group: {g}</option>)}
        </select>
        <select className="chip-select" aria-label="Site" value={siteFilter} onChange={(e) => setFilters(statusFilter, outdatedOnly, groupFilter, e.target.value)}>
          <option value="">All sites</option>
          {siteOptions.map((s) => <option key={s} value={s}>Site: {s}</option>)}
          {hasNoSite && <option value={NO_SITE}>No site</option>}
        </select>
        {(statusFilter.length > 0 || outdatedOnly || groupFilter || siteFilter) && <button className="btn btn-sm" onClick={() => setSp({})}>Clear</button>}
        <span className="spacer" />
        <label className="check small">
          <input type="checkbox" checked={includeRetired} disabled={statusFilter.includes("retired")}
                 onChange={(e) => setShowRetired(e.target.checked)} />
          Show retired
        </label>
      </div>
      {canEdit && visibleSelected.length > 0 && (
        <div className="bulkbar">
          <b>{visibleSelected.length}</b> selected
          <button className="btn btn-sm btn-primary" onClick={() => setBulkOpen(true)}>Edit groups…</button>
          <button className="btn btn-sm" onClick={() => setSelected(new Set())}>Clear selection</button>
        </div>
      )}
      <ErrorBanner error={error} />
      {data && data.length > 0 && rows.length === 0 && <Empty>No endpoints match the filter.</Empty>}
      {data && data.length === 0 && (
        <Empty>
          <p><b>No endpoints enrolled yet.</b> Create an enrollment token, then run the one-line installer on each Windows PC.
            Tip: put 2–5 test machines in group <span className="tag">pilot</span> — standard deployments patch these test machines first.</p>
          {canEdit
            ? <button className="btn btn-primary" onClick={() => setShowToken(true)}>Create enrollment token</button>
            : <span className="muted">A User or Admin creates enrollment tokens.</span>}{" "}
          {canEdit && <Link className="btn" to={paths.addEndpoints}>Agent setup guide</Link>}
        </Empty>
      )}
      {rows.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              {canEdit && (
                <th style={{ width: 28 }}>
                  <input type="checkbox" className="rowcheck" checked={allOn} onChange={toggleAll} aria-label="Select all" />
                </th>
              )}
              <th>Hostname</th><th>Status</th><th title="Missing Windows updates + application updates (update intelligence); ready = approved packages it needs">Outdated</th><th>OS</th><th>Arch</th><th>RAM</th><th>Disk free</th><th>Groups</th><th>Site</th><th>Owner</th>
              <th>Last seen</th><th>Inventory age</th><th>Reboot</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.endpoint_id}
                  className={e.status === "retired" ? "row-disabled" : e.status === "offline" || e.status === "stale" ? "row-silent" : selected.has(e.endpoint_id) ? "selected" : ""}>
                {canEdit && (
                  <td>
                    {e.status !== "retired" && (
                      <input type="checkbox" className="rowcheck" checked={selected.has(e.endpoint_id)}
                             onChange={() => toggleOne(e.endpoint_id)} aria-label={`Select ${e.hostname}`} />
                    )}
                  </td>
                )}
                <td><Link to={`/endpoints/${enc(e.endpoint_id)}`} className="cell-title">{e.hostname}</Link></td>
                <td><Pill state={e.status} /></td>
                <td className="nowrap"><OutdatedCell e={e} /></td>
                <td className="nowrap">
                  {e.os_version || e.os}
                  <div className="cell-sub">{e.edition ? `${e.edition} · ` : ""}build {e.build || "—"}</div>
                </td>
                <td>{e.arch}</td>
                <td className="nowrap">{e.hardware?.memory_bytes ? fmtBytes(e.hardware.memory_bytes) : <span className="muted">—</span>}</td>
                <td className="nowrap"><DiskFree e={e} /></td>
                <td>{(e.groups ?? []).map((g) => <span key={g} className="tag">{g}</span>)}</td>
                <td>{e.site || <span className="muted">—</span>}</td>
                <td>{e.owner || <span className="muted">—</span>}</td>
                <td className="nowrap"><RelTime value={e.last_seen} /></td>
                <td className="nowrap" title={e.inventory_at}>{relTime(e.inventory_at, now).replace(/ ago$/, "")}</td>
                <td>{e.reboot_pending ? <Pill state="pending_reboot" /> : <span className="muted">no</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {showToken && canEdit && <EnrollmentModal onClose={() => { setShowToken(false); if (sp.get("enroll")) setSp({}); }} />}
      {bulkOpen && (
        <BulkGroupsModal
          endpoints={visibleSelected}
          onClose={() => setBulkOpen(false)}
          onDone={() => { setSelected(new Set()); void reload(); }}
        />
      )}
    </>
  );
}

type BulkResult = { endpoint: Endpoint; ok: boolean; error?: string; skipped?: boolean };

/** Add/remove groups on several endpoints via sequential PATCH /api/endpoints/{id} calls. */
function BulkGroupsModal({ endpoints, onClose, onDone }: { endpoints: Endpoint[]; onClose: () => void; onDone: () => void }) {
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<BulkResult[]>([]);
  const [finished, setFinished] = useState(false);
  const addList = splitList(add);
  const removeList = splitList(remove);
  const conflict = addList.filter((g) => removeList.includes(g));
  const valid = (addList.length > 0 || removeList.length > 0) && conflict.length === 0;

  const apply = async () => {
    setRunning(true);
    setResults([]);
    const out: BulkResult[] = [];
    for (const ep of endpoints) {
      const current = ep.groups ?? [];
      const next = [...current.filter((g) => !removeList.includes(g))];
      for (const g of addList) if (!next.includes(g)) next.push(g);
      const unchanged = next.length === current.length && next.every((g) => current.includes(g));
      if (unchanged) {
        out.push({ endpoint: ep, ok: true, skipped: true });
      } else {
        try {
          await api.patch<Endpoint>(`/api/endpoints/${enc(ep.endpoint_id)}`, { groups: next });
          out.push({ endpoint: ep, ok: true });
        } catch (e) {
          out.push({ endpoint: ep, ok: false, error: errMsg(e) });
        }
      }
      setResults([...out]);
    }
    setRunning(false);
    setFinished(true);
    onDone();
  };

  const failed = results.filter((r) => !r.ok);
  const changed = results.filter((r) => r.ok && !r.skipped).length;
  const skipped = results.filter((r) => r.skipped).length;

  return (
    <Modal
      title={`Edit groups on ${endpoints.length} endpoint${endpoints.length === 1 ? "" : "s"}`}
      onClose={() => { if (!running) onClose(); }}
      wide
      footer={finished
        ? <button className="btn btn-primary" onClick={onClose}>Done</button>
        : <>
            <button className="btn" onClick={onClose} disabled={running}>Cancel</button>
            <button className="btn btn-primary" onClick={() => void apply()} disabled={!valid || running}>
              {running ? `Applying ${results.length}/${endpoints.length}…` : "Apply"}
            </button>
          </>}
    >
      <div className="form-grid">
        <label className="field">
          <span>Add groups <em className="muted">comma-separated</em></span>
          <input value={add} onChange={(e) => setAdd(e.target.value)} disabled={running || finished} autoFocus placeholder="pilot" />
        </label>
        <label className="field">
          <span>Remove groups <em className="muted">comma-separated</em></span>
          <input value={remove} onChange={(e) => setRemove(e.target.value)} disabled={running || finished} placeholder="broad" />
        </label>
      </div>
      {conflict.length > 0 && <div className="banner banner-error">A group can't be both added and removed: {conflict.join(", ")}</div>}
      <div className="hint">
        Changes are applied one endpoint at a time and each is recorded in the audit log. Group membership decides which
        deployment stages and maintenance windows apply to an endpoint.
      </div>
      {(running || finished) && (
        <>
          <div className="countbar" title={`${results.length}/${endpoints.length}`} role="progressbar" aria-label="Group changes applied"
               aria-valuemin={0} aria-valuemax={endpoints.length} aria-valuenow={results.length}>
            <span className="seg seg-green" style={{ width: `${((results.length - failed.length) / endpoints.length) * 100}%` }} />
            <span className="seg seg-red" style={{ width: `${(failed.length / endpoints.length) * 100}%` }} />
          </div>
          {finished && (
            <div className={`banner ${failed.length ? "banner-warn" : "banner-ok"}`}>
              {changed} updated{skipped ? `, ${skipped} already up to date` : ""}{failed.length ? `, ${failed.length} failed` : ""}.
            </div>
          )}
          {failed.length > 0 && (
            <table className="table table-compact">
              <thead><tr><th>Endpoint</th><th>Error</th></tr></thead>
              <tbody>
                {failed.map((r) => (
                  <tr key={r.endpoint.endpoint_id}><td>{r.endpoint.hostname}</td><td className="text-red">{r.error}</td></tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </Modal>
  );
}

function EnrollmentModal({ onClose }: { onClose: () => void }) {
  const [groups, setGroups] = useState("");
  const [site, setSite] = useState("");
  const [hours, setHours] = useState("24");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EnrollmentToken | null>(null);
  const [uses, setUses] = useState("1");
  const h = Number(hours);
  const u = Number(uses);
  const usesOk = Number.isInteger(u) && u >= 1 && u <= 10000;
  const hoursOk = Number.isFinite(h) && h > 0 && (u <= 1 || h <= 336);
  const valid = usesOk && hoursOk;

  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.post<EnrollmentToken>("/api/enrollment-tokens", {
        groups: splitList(groups), site: site.trim(), expires_in_hours: h, max_uses: u,
      }));
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title={result ? "Enroll an endpoint" : "Create enrollment token"}
      onClose={onClose}
      xwide={!!result}
      footer={result
        ? <button className="btn btn-primary" onClick={onClose}>Done</button>
        : <>
            <button className="btn" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" disabled={!valid || busy} onClick={create}>{busy ? "Creating…" : "Create token"}</button>
          </>}
    >
      {!result ? (
        <>
          <label className="field">
            <span>Groups <em className="muted">comma-separated</em></span>
            <input value={groups} onChange={(e) => setGroups(e.target.value)} placeholder="pilot, workstations" autoFocus />
          </label>
          <label className="field">
            <span>Site</span>
            <input value={site} onChange={(e) => setSite(e.target.value)} />
          </label>
          <label className="field">
            <span>Expires in (hours)</span>
            <input type="number" min={1} value={hours} onChange={(e) => setHours(e.target.value)} />
            {u > 1 && h > 336 && <small className="hint text-red">Multi-use tokens may last at most 336 hours (14 days).</small>}
          </label>
          <label className="field">
            <span>Devices this token can enroll</span>
            <input type="number" min={1} max={10000} step={1} value={uses} onChange={(e) => setUses(e.target.value)} />
            {!usesOk
              ? <small className="hint text-red">Enter a whole number from 1 to 10000.</small>
              : <small className="hint">Use &gt;1 only for GPO/SCCM/Intune mass rollout; keep the expiry short.</small>}
          </label>
          <ErrorBanner error={error} />
        </>
      ) : (
        <>
          <div className="token-result">
            <div className="banner banner-warn">
              Copy this token now. <b>It will not be shown again.</b> It enrolls {(result.max_uses ?? 1) > 1 ? <>up to <b>{result.max_uses}</b> devices</> : "one device"} and expires <Time value={result.expires_at} />.
              It is already filled into the commands below.
            </div>
            <CopyBox value={result.token} />
          </div>
          <AgentSetupGuide token={result.token} groups={splitList(groups)} site={site.trim()} />
        </>
      )}
    </Modal>
  );
}

// Free space on the endpoint's fullest disk, coloured when it runs low
// (patches need room to download and install).
function DiskFree({ e }: { e: Endpoint }) {
  const disks = e.hardware?.disks ?? [];
  if (!disks.length) return <span className="muted">—</span>;
  const d = disks.reduce((a, b) => (usedPct(b) > usedPct(a) ? b : a));
  const pct = usedPct(d);
  return (
    <span className={pct >= 90 ? "text-red" : pct >= 75 ? "text-amber" : ""} title={`${d.mount}: ${fmtBytes(d.free_bytes)} free of ${fmtBytes(d.total_bytes)} (${pct}% used)`}>
      {fmtBytes(d.free_bytes)}
      <div className="cell-sub">of {fmtBytes(d.total_bytes)}</div>
    </span>
  );
}

function missingTotal(e: Endpoint): number {
  return e.missing ? (e.missing.os ?? 0) + (e.missing.apps ?? 0) : 0;
}

// "3" with "OS 1 · apps 2 · 2 ready": compliant only means no open deployment
// problem; this column says what inventory shows is still missing.
function OutdatedCell({ e }: { e: Endpoint }) {
  const m = e.missing;
  if (!m) return <span className="muted" title="No update intelligence for this endpoint yet">unknown</span>;
  const total = missingTotal(e);
  const unsupported = m.os_support === "out_of_support"
    ? <div className="cell-sub"><Pill state="failed" label="Windows no longer updated" /> <span className="muted" title="Microsoft stopped shipping updates for this Windows version; upgrade Windows to keep it secure">last update {m.os_last_update}</span></div>
    : null;
  if (total === 0) return <>
    <Pill state="verified" label="up to date" />
    {unsupported}
  </>;
  return (
    <span title={`${m.os} Windows update(s), ${m.apps} application update(s) missing; ${m.ready} approved package(s) ready to deploy`}>
      <b className="text-amber">{total}</b> <span className="muted">missing</span>
      <div className="cell-sub">OS {m.os} · apps {m.apps}{m.ready ? <> · <b>{m.ready} ready</b></> : null}</div>
      {unsupported}
    </span>
  );
}
