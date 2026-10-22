import { useState } from "react";
import { Link } from "react-router-dom";
import { api, enc } from "../api";
import { useCan } from "../auth";
import { paths } from "../paths";
import type { LibraryItem, LibraryItemDetail, LibraryKind } from "../types";
import { useLoad } from "../util";
import { RequestedPill } from "./AcqRequestStatus";
import { isRequestable } from "./PipelineAction";
import { CatalogState } from "./UpdatesAvailable";
import { ImportableBadge, InstalledCount, UnverifiedLink, safeHttpsUrl } from "./libraryParts";
import type { ImportItems } from "./useImportRequest";
import { Empty, ErrorBanner, KV, Mono, Pill, RelTime } from "./ui";

const DEFAULT_ARCH = "x64";

type Props = {
  kind: LibraryKind;
  id: string;
  onClose: () => void;
  /** Send the Import (the page owns the request state and result banner). */
  onImport: (items: ImportItems, busyKey: string) => void;
  busy: string | null;
};

/** Why Import is not offered for this entry ("" = it can be imported). */
function blockedReason(it: LibraryItem): string {
  if (it.importable === "no") return `Can't import: ${it.importable_reason || "no supported installer"}`;
  if (it.requested?.status === "unsupported") return `Can't import: ${it.requested.reason || "the acquisition team cannot fetch it this way"}`;
  if (!isRequestable(it.catalog, it.requested)) {
    return it.catalog?.state === "revoked" ? "Revoked in the catalog: it cannot be imported again" : "Already in the catalog";
  }
  return "";
}

/** Architectures the resolved installers offer (x64 first). */
function archesOf(it: LibraryItem): string[] {
  const set = new Set((it.installers ?? []).map((i) => i.arch).filter(Boolean));
  const list = [...set].sort((a, b) => (a === DEFAULT_ARCH ? -1 : b === DEFAULT_ARCH ? 1 : a.localeCompare(b)));
  return list.length ? list : [DEFAULT_ARCH];
}

/** Row drawer of the Library: details, links (unverified), installers, machines that have it, and Import. */
export function LibraryDrawer({ kind, id, onClose, onImport, busy }: Props) {
  const { data: it, error } = useLoad(
    () => api.get<LibraryItemDetail>(`/api/library/${enc(kind)}/${enc(id)}`), [kind, id], 60000);
  const canImport = useCan("user");
  const [arch, setArch] = useState<string>("");
  const busyKey = `lib:${kind}:${id}`;

  return (
    <aside className="panel">
      <div className="panel-head">
        <div>
          <div className="panel-title">{it?.name || id}</div>
          <Mono>{id}</Mono>
        </div>
        <button className="btn-icon" onClick={onClose} aria-label="Close">×</button>
      </div>
      <ErrorBanner error={error} />
      {!it && !error && <div className="muted small">Loading…</div>}
      {it && <DrawerBody it={it} canImport={canImport} arch={arch} setArch={setArch}
                         onImport={onImport} busy={busy} busyKey={busyKey} />}
    </aside>
  );
}

function DrawerBody({ it, canImport, arch, setArch, onImport, busy, busyKey }: {
  it: LibraryItemDetail; canImport: boolean; arch: string; setArch: (a: string) => void;
  onImport: Props["onImport"]; busy: string | null; busyKey: string;
}) {
  const blocked = blockedReason(it);
  const installedNowhere = !it.installed?.endpoints;
  const arches = archesOf(it);
  const chosenArch = arch || arches[0];
  const doImport = () => {
    if (it.kind === "os") { onImport({ apps: [], kbs: [it.id] }, busyKey); return; }
    onImport({ apps: [it.id], kbs: [], ...(installedNowhere ? { app_archs: { [it.id]: chosenArch } } : {}) }, busyKey);
  };
  const askAgain = !!it.requested && it.requested.status !== "fulfilled";
  const links = it.links ?? {};

  return (
    <>
      <div className="panel-actions">
        <ImportableBadge item={it} />
        <span className="spacer" />
        {canImport && !blocked && (
          <>
            {it.kind === "app" && installedNowhere && arches.length > 1 && (
              <label className="inline-field" title="No machine has this yet, so choose which version to download">
                for
                <select value={chosenArch} onChange={(e) => setArch(e.target.value)}>
                  {arches.map((a) => <option key={a} value={a}>{a}</option>)}
                </select>
              </label>
            )}
            <button className="btn btn-primary" disabled={busy !== null} onClick={doImport}
                    title="Ask the acquisition zone to download it; it is checked, signed and comes back to the Catalog for approval">
              {busy === busyKey ? "Sending…" : askAgain ? "Ask again" : "Import"}
            </button>
          </>
        )}
        {canImport && blocked && <button className="btn" disabled title={blocked}>Import</button>}
      </div>
      {canImport && blocked && <div className="hint">{blocked}</div>}
      {!canImport && <div className="hint">Viewers can look but not import.</div>}
      {it.importable === "unknown" && !blocked && (
        <div className="hint">The installer has not been checked yet. If it turns out not to be an MSI or a silent machine-wide EXE installer, the import will show “Can't import” with the reason.</div>
      )}

      <KV rows={[
        ["Publisher", it.publisher || <span className="muted">—</span>],
        ["Latest version", it.latest_version ? <Mono>{it.latest_version}</Mono> : <span className="muted">—</span>],
        ["On your machines", <InstalledCount installed={it.installed} />],
        ["Catalog", <CatalogState link={it.catalog} latest={it.kind === "app" ? it.latest_version : undefined} />],
        ["Import request", it.requested ? <RequestedPill r={it.requested} /> : <span className="muted">not requested</span>],
        ["Details checked", it.resolved_at ? <RelTime value={it.resolved_at} /> : <span className="muted">not yet</span>],
      ]} />

      {it.description && (
        <>
          <h3>Description <span className="muted small">· from the winget community</span></h3>
          <p className="lib-desc">{it.description}</p>
        </>
      )}

      {(links.homepage || links.publisher_url || links.manifest) && (
        <>
          <h3>Links</h3>
          <div className="hint">For reading only. DSS Patcher never downloads from these; it installs only signed packages from the Catalog.</div>
          <UnverifiedLink label={it.kind === "os" ? "Microsoft Update Catalog" : "Homepage"} url={links.homepage} />
          <UnverifiedLink label="Publisher" url={links.publisher_url} />
          <UnverifiedLink label="winget manifest" url={links.manifest} />
        </>
      )}

      {it.kind === "app" && (
        <>
          <h3>Installers</h3>
          {!it.installers || it.installers.length === 0 ? (
            <div className="muted small">Not checked yet.</div>
          ) : (
            <table className="table table-compact">
              <thead><tr><th>Arch</th><th>Type</th><th>Scope</th><th>SHA-256</th></tr></thead>
              <tbody>
                {it.installers.map((ins, n) => (
                  <tr key={`${ins.arch}-${ins.type}-${n}`}>
                    <td>{ins.arch || "—"}</td>
                    <td><span className="tag">{ins.type || "?"}</span></td>
                    <td>{ins.scope || <span className="muted">—</span>}</td>
                    <td className="break">
                      <Mono>{ins.sha256 || "—"}</Mono>
                      {safeHttpsUrl(ins.url) && <div className="cell-sub" title="Download address (unverified · winget community)">{safeHttpsUrl(ins.url)}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      <h3>Machines that have it <span className="muted">· {(it.endpoints ?? []).length}</span></h3>
      {(it.endpoints ?? []).length === 0 ? <Empty>No machine has it installed.</Empty> : (
        <table className="table table-compact">
          <thead><tr><th>Machine</th><th>Installed</th><th /></tr></thead>
          <tbody>
            {it.endpoints.map((e) => (
              <tr key={e.endpoint_id}>
                <td><Link to={paths.endpoint(e.endpoint_id)}>{e.hostname || e.endpoint_id}</Link></td>
                <td><Mono>{e.installed_version || "—"}</Mono></td>
                <td>{e.outdated ? <Pill state="pending" label="outdated" /> : <Pill state="verified" label="up to date" />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
