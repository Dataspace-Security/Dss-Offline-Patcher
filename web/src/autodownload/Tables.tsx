import { useState } from "react";
import { api, qs } from "../api";
import { ImportableBadge, useDebounced } from "../components/libraryParts";
import { Empty, Mono, Pill } from "../components/ui";
import type { LibraryPage } from "../types";
import { useLoad } from "../util";
import {
  ARCHES, RESULT_LABELS, RESULT_TONE, SOURCE_LABELS, WINGET_ID, sourceSummary, windowsKey,
  type AppEntry, type Arch, type Classification, type KnownWindows, type SourceEntry, type SourceResult, type WindowsEntry,
} from "./types";

/** Last run's result for one entry ("—" if the downloader did not report it). */
export function LastResult({ r }: { r: SourceResult | undefined }) {
  if (!r) return <span className="muted">—</span>;
  return (
    <span title={r.detail}>
      <Pill state={RESULT_TONE[r.result] ?? "pending"} label={RESULT_LABELS[r.result] ?? r.result} />
      {r.detail && <div className="cell-sub">{r.detail}</div>}
    </span>
  );
}

function replaceAt<T>(xs: T[], i: number, v: T): T[] {
  return xs.map((x, j) => (j === i ? v : x));
}

interface WindowsTableProps {
  rows: WindowsEntry[];
  choices: KnownWindows[];
  results: Map<string, SourceResult>;
  onChange: (rows: WindowsEntry[]) => void;
}

export function WindowsTable({ rows, choices, results, onChange }: WindowsTableProps) {
  const free = choices.filter((c) => !rows.some((r) => windowsKey(r) === windowsKey(c)));
  const [pick, setPick] = useState("");
  const [cls, setCls] = useState<Classification>("security");
  const add = () => {
    const c = free.find((x) => windowsKey(x) === pick);
    if (!c) return;
    onChange([...rows, { product: c.product, build: c.build, arch: c.arch, classification: cls, enabled: true }]);
    setPick("");
  };
  return (
    <>
      {rows.length === 0 ? <Empty>No Windows releases. Add the ones your machines run.</Empty> : (
        <table className="table table-compact">
          <thead><tr><th>Windows release</th><th>Build</th><th>Arch</th><th>Updates</th><th>Download</th><th>Last run</th><th /></tr></thead>
          <tbody>
            {rows.map((w, i) => (
              <tr key={windowsKey(w)}>
                <td>{w.product}</td>
                <td><Mono>{w.build}</Mono></td>
                <td>{w.arch}</td>
                <td>
                  <select value={w.classification} onChange={(e) => onChange(replaceAt(rows, i, { ...w, classification: e.target.value as Classification }))}>
                    <option value="security">Security updates</option>
                    <option value="all">All severities</option>
                  </select>
                </td>
                <td><label className="check"><input type="checkbox" checked={w.enabled} onChange={(e) => onChange(replaceAt(rows, i, { ...w, enabled: e.target.checked }))} /> {w.enabled ? "On" : "Off"}</label></td>
                <td><LastResult r={results.get(`windows:${windowsKey(w)}`)} /></td>
                <td className="right"><button className="btn btn-sm btn-danger-ghost" onClick={() => onChange(rows.filter((_, j) => j !== i))}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="form-actions" style={{ justifyContent: "flex-start", marginTop: 8 }}>
        <select value={pick} style={{ width: "auto" }} onChange={(e) => setPick(e.target.value)} aria-label="Windows release to add">
          <option value="">Choose a Windows release…</option>
          {free.map((c) => <option key={windowsKey(c)} value={windowsKey(c)}>{c.product} · {c.build} · {c.arch}</option>)}
        </select>
        <select value={cls} style={{ width: "auto" }} onChange={(e) => setCls(e.target.value as Classification)} aria-label="Which updates">
          <option value="security">Security updates</option>
          <option value="all">All severities</option>
        </select>
        <button className="btn btn-sm" disabled={!pick} onClick={add}>Add</button>
      </div>
      <p className="hint">Off removes the release even if the installer's settings (acquire.json) list it. "Security updates" uses the minimum severity in acquire.json (critical after a standard install).</p>
    </>
  );
}

interface AppsTableProps {
  rows: AppEntry[];
  results: Map<string, SourceResult>;
  onChange: (rows: AppEntry[]) => void;
}

export function AppsTable({ rows, results, onChange }: AppsTableProps) {
  const toggleArch = (a: AppEntry, arch: Arch): AppEntry => {
    const has = a.arch.includes(arch);
    const next = has ? a.arch.filter((x) => x !== arch) : [...a.arch, arch];
    return { ...a, arch: next.length ? next : a.arch };
  };
  return (
    <>
      {rows.length === 0 ? <Empty>No apps yet. Search the Library below to add one.</Empty> : (
        <table className="table table-compact">
          <thead><tr><th>App (winget id)</th><th>Architectures</th><th>Version</th><th>Download</th><th>Note</th><th>Last run</th><th /></tr></thead>
          <tbody>
            {rows.map((a, i) => (
              <tr key={a.id}>
                <td><Mono>{a.id}</Mono></td>
                <td className="nowrap">
                  {ARCHES.map((ar) => (
                    <label key={ar} className="check" style={{ display: "inline-flex", marginRight: 8 }}>
                      <input type="checkbox" checked={a.arch.includes(ar)} onChange={() => onChange(replaceAt(rows, i, toggleArch(a, ar)))} /> {ar}
                    </label>
                  ))}
                </td>
                <td className="muted">Newest</td>
                <td><label className="check"><input type="checkbox" checked={a.enabled} onChange={(e) => onChange(replaceAt(rows, i, { ...a, enabled: e.target.checked }))} /> {a.enabled ? "On" : "Off"}</label></td>
                <td><input value={a.note} maxLength={256} placeholder="optional" onChange={(e) => onChange(replaceAt(rows, i, { ...a, note: e.target.value }))} /></td>
                <td><LastResult r={results.get(`app:${a.id.toLowerCase()}`)} /></td>
                <td className="right"><button className="btn btn-sm btn-danger-ghost" onClick={() => onChange(rows.filter((_, j) => j !== i))}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <AppSearch existing={rows} onAdd={(id) => onChange([...rows, { source: "winget", id, arch: ["x64"], channel: "latest", enabled: true, note: "" }])} />
    </>
  );
}

/** Search the Library (update intelligence) and add an app by its winget id. */
function AppSearch({ existing, onAdd }: { existing: AppEntry[]; onAdd: (id: string) => void }) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q.trim(), 250);
  const res = useLoad(
    () => (dq.length < 2 ? Promise.resolve(null) : api.get<LibraryPage>(`/api/library${qs({ q: dq, kind: "app", view: "all", sort: "installed", per_page: 8 })}`)),
    [dq],
  );
  const have = (id: string) => existing.some((a) => a.id.toLowerCase() === id.toLowerCase());
  const exact = WINGET_ID.test(q.trim()) && !have(q.trim()) && !(res.data?.items ?? []).some((it) => it.id.toLowerCase() === q.trim().toLowerCase());
  return (
    <div style={{ marginTop: 10 }}>
      <label className="field">
        <span>Add an app</span>
        <input value={q} placeholder="Search by name or winget id, e.g. Chrome or 7zip.7zip" onChange={(e) => setQ(e.target.value)} />
      </label>
      {res.error && <p className="text-red small">Library search failed: {res.error}</p>}
      {res.data && res.data.items.length === 0 && dq.length >= 2 && <p className="muted small">Nothing in the Library matches "{dq}".</p>}
      {res.data && res.data.items.length > 0 && (
        <table className="table table-compact">
          <tbody>
            {res.data.items.map((it) => (
              <tr key={it.id}>
                <td><div className="cell-title">{it.name || it.id}</div><div className="cell-sub"><Mono>{it.id}</Mono> · {it.publisher} · {it.latest_version}</div></td>
                <td><ImportableBadge item={it} /></td>
                <td className="right">
                  {have(it.id) ? <span className="muted small">Added</span> : <button className="btn btn-sm" onClick={() => { onAdd(it.id); setQ(""); }}>Add</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {exact && (
        <p className="small">Not in the Library yet? <button className="btn btn-sm" onClick={() => { onAdd(q.trim()); setQ(""); }}>Add {q.trim()} by its winget id</button></p>
      )}
      <p className="hint">Apps are kept at their newest version. Only apps with an MSI installer can be downloaded ("can import").</p>
    </div>
  );
}

interface SourcesTableProps {
  rows: SourceEntry[];
  results: Map<string, SourceResult>;
  onChange: (rows: SourceEntry[]) => void;
  onEdit: (index: number | null) => void;
}

export function SourcesTable({ rows, results, onChange, onEdit }: SourcesTableProps) {
  return (
    <>
      {rows.length === 0 ? <Empty>No sources listed: the public winget, Microsoft Update Catalog and MSRC addresses are used.</Empty> : (
        <table className="table table-compact">
          <thead><tr><th>Source</th><th>Type</th><th>Details</th><th>Use</th><th>Added by</th><th>Last run</th><th /></tr></thead>
          <tbody>
            {rows.map((s, i) => (
              <tr key={s.id}>
                <td><Mono>{s.id}</Mono>{s.note && <div className="cell-sub">{s.note}</div>}</td>
                <td>{SOURCE_LABELS[s.type] ?? s.type}</td>
                <td className="small">{sourceSummary(s)}</td>
                <td><label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => onChange(replaceAt(rows, i, { ...s, enabled: e.target.checked }))} /> {s.enabled ? "On" : "Off"}</label></td>
                <td className="small">{s.added_by ? s.added_by.replace(/^user:/, "") : <span className="muted">you (on save)</span>}</td>
                <td><LastResult r={results.get(`source:${s.id}`)} /></td>
                <td className="right nowrap">
                  <button className="btn btn-sm" onClick={() => onEdit(i)}>Edit</button>{" "}
                  <button className="btn btn-sm btn-danger-ghost" onClick={() => onChange(rows.filter((_, j) => j !== i))}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="form-actions" style={{ justifyContent: "flex-start", marginTop: 8 }}>
        <button className="btn btn-sm" onClick={() => onEdit(null)}>Add a source</button>
      </div>
    </>
  );
}
