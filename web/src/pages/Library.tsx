import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, qs } from "../api";
import { RequestedPill } from "../components/AcqRequestStatus";
import { IntelStaleBanner } from "../components/IntelStaleBanner";
import { LibraryDrawer } from "../components/LibraryDrawer";
import { ImportableBadge, InstalledCount, useDebounced } from "../components/libraryParts";
import { RequestResultBanner } from "../components/RequestResultBanner";
import { CatalogState } from "../components/UpdatesAvailable";
import { useImportRequest } from "../components/useImportRequest";
import { Empty, ErrorBanner, Mono, PageHeader, RelTime, expandRowProps } from "../components/ui";
import type { LibraryItem, LibraryKind, LibraryPage, LibrarySort, LibraryView } from "../types";
import { useLoad } from "../util";
import "../patch.css";

const PER_PAGE = 50;
const DEBOUNCE_MS = 250;

/** The chips: four views over applications, and Windows updates. */
type Chip = LibraryView | "windows";
const CHIPS: { value: Chip; label: string; help: string }[] = [
  { value: "available", label: "Available", help: "Apps DSS Patcher can import, and apps already on your machines" },
  { value: "installed", label: "Installed in fleet", help: "Apps on at least one of your machines" },
  { value: "catalog", label: "In catalog", help: "Apps that already have a package in the Catalog" },
  { value: "all", label: "All", help: "Every app the update information knows about" },
  { value: "windows", label: "Windows", help: "Windows cumulative updates" },
];
const SORTS: { value: LibrarySort; label: string }[] = [
  { value: "installed", label: "Most installed" },
  { value: "name", label: "Name" },
  { value: "date", label: "Newest" },
];

const itemKey = (it: Pick<LibraryItem, "kind" | "id">) => `${it.kind}:${it.id}`;

function parseChip(v: string | null): Chip {
  return CHIPS.some((c) => c.value === v) ? (v as Chip) : "available";
}
function parseSort(v: string | null): LibrarySort {
  return SORTS.some((s) => s.value === v) ? (v as LibrarySort) : "installed";
}

/**
 * Patches → Library: everything that could be imported, from the update
 * information (an untrusted index; the content comes from the winget
 * community). Search, filter, open a row for details, and Import. Nothing
 * here installs anything: imports arrive in the Catalog for approval.
 */
export default function Library() {
  const [sp, setSp] = useSearchParams();
  const chip = parseChip(sp.get("view"));
  const sort = parseSort(sp.get("sort"));
  const page = Math.max(1, Number(sp.get("page")) || 1);
  const openKey = sp.get("open") ?? "";

  // The search and publisher boxes update the address only after typing stops.
  const [q, setQ] = useState(sp.get("q") ?? "");
  const [publisher, setPublisher] = useState(sp.get("publisher") ?? "");
  const dq = useDebounced(q.trim(), DEBOUNCE_MS);
  const dpub = useDebounced(publisher.trim(), DEBOUNCE_MS);

  const update = (changes: Record<string, string>, resetPage = true) => {
    const n = new URLSearchParams(sp);
    for (const [k, v] of Object.entries(changes)) {
      if (v) n.set(k, v); else n.delete(k);
    }
    if (resetPage) n.delete("page");
    setSp(n, { replace: true });
  };
  useEffect(() => {
    if ((sp.get("q") ?? "") !== dq || (sp.get("publisher") ?? "") !== dpub) update({ q: dq, publisher: dpub });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq, dpub]);

  const kind: LibraryKind = chip === "windows" ? "os" : "app";
  const view: LibraryView = chip === "windows" ? "all" : chip;
  const query = qs({ q: dq, kind, view, publisher: dpub, sort, page, per_page: PER_PAGE });
  const list = useLoad(() => api.get<LibraryPage>(`/api/library${query}`), [query], 60000);
  const imp = useImportRequest(() => void list.reload());

  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / (list.data?.per_page || PER_PAGE)));
  const publishers = useMemo(
    () => [...new Set(items.map((i) => i.publisher).filter(Boolean))].sort((a, b) => a.localeCompare(b)), [items]);

  const [openKind, ...rest] = openKey.split(":");
  const openId = rest.join(":");
  const setOpen = (it: LibraryItem | null) => update({ open: it && itemKey(it) !== openKey ? itemKey(it) : "" }, false);

  return (
    <>
      <PageHeader
        title="Library"
        sub={<>Software you can import, from the update information
          {list.data?.generated_at && <> (made <RelTime value={list.data.generated_at} />)</>}. Names, descriptions and links come from the
          winget community and are <b>not verified</b>; only packages you approve in the Catalog are ever installed.</>}
      >
        <input className="search" placeholder="Search name, id, publisher or product code…" value={q}
               onChange={(e) => setQ(e.target.value)} aria-label="Search the library" />
      </PageHeader>
      <IntelStaleBanner />
      <ErrorBanner error={list.error} />
      {imp.error && <div className="banner banner-error">Import failed: {imp.error}</div>}
      {imp.result && <RequestResultBanner req={imp.result} onDismiss={imp.dismiss} />}

      <div className="section-head">
        <div className="chips">
          {CHIPS.map((c) => (
            <button key={c.value} className={`chip ${chip === c.value ? "chip-on" : ""}`} title={c.help}
                    onClick={() => update({ view: c.value === "available" ? "" : c.value, open: "" })}>
              {c.label}{chip === c.value && list.data && <b>{total.toLocaleString()}</b>}
            </button>
          ))}
        </div>
        <div className="cat-filters">
          {chip !== "windows" && (
            <label className="inline-field">
              Publisher
              <input list="lib-publishers" value={publisher} onChange={(e) => setPublisher(e.target.value)} placeholder="any" />
              <datalist id="lib-publishers">{publishers.map((p) => <option key={p} value={p} />)}</datalist>
            </label>
          )}
          <label className="inline-field">
            Sort
            <select value={sort} onChange={(e) => update({ sort: e.target.value === "installed" ? "" : e.target.value })}>
              {SORTS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
            </select>
          </label>
        </div>
      </div>

      <div className={openKey ? "split" : ""}>
        <div className="split-main">
          {list.data && items.length === 0 && (
            <Empty>
              {dq || dpub ? "Nothing matches the search." : chip === "available"
                ? "Nothing to show yet. The library fills in when update information arrives from the acquisition team."
                : "Nothing in this view."}
            </Empty>
          )}
          {!list.data && !list.error && <div className="muted small">Loading…</div>}
          {items.length > 0 && (
            <table className="table">
              <thead>
                <tr>
                  <th>{chip === "windows" ? "Update" : "Software"}</th>
                  {!openKey && <th>Publisher</th>}
                  <th>Latest</th><th>On your machines</th><th>Import</th>{!openKey && <th>Catalog / request</th>}
                </tr>
              </thead>
              <tbody>
                {items.map((it) => (
                  <tr key={itemKey(it)} {...expandRowProps(openKey === itemKey(it), () => setOpen(it))}>
                    <td>
                      <div className="cell-title">{it.name || it.id}</div>
                      <div className="cell-sub"><Mono>{it.id}</Mono>{openKey && it.publisher && <> · {it.publisher}</>}</div>
                    </td>
                    {!openKey && <td>{it.publisher || <span className="muted">—</span>}</td>}
                    <td><Mono>{it.latest_version || "—"}</Mono></td>
                    <td className="nowrap"><InstalledCount installed={it.installed} /></td>
                    <td><ImportableBadge item={it} /></td>
                    {!openKey && (
                      <td>
                        {it.catalog ? <CatalogState link={it.catalog} latest={it.kind === "app" ? it.latest_version : undefined} /> : !it.requested && <span className="muted small">not imported</span>}
                        {it.requested && <div><RequestedPill r={it.requested} /></div>}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {list.data && total > 0 && (
            <div className="lib-pager">
              <button className="btn btn-sm" disabled={page <= 1} onClick={() => update({ page: String(page - 1) }, false)}>← Previous</button>
              <span className="muted">Page {page} of {pages} · {total.toLocaleString()} entries</span>
              <button className="btn btn-sm" disabled={page >= pages} onClick={() => update({ page: String(page + 1) }, false)}>Next →</button>
            </div>
          )}
        </div>
        {openKey && (openKind === "app" || openKind === "os") && openId && (
          <LibraryDrawer key={`${openKey}:${imp.result?.request_id ?? ""}`} kind={openKind} id={openId} onClose={() => update({ open: "" }, false)}
                         onImport={(items, key) => void imp.send(items, key)} busy={imp.busy} />
        )}
      </div>
    </>
  );
}
