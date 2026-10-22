import { api } from "../api";
import type { AcquisitionRequestRef, Importable, LibraryPage } from "../types";
import { useLoad } from "../util";

/** The Library's verdict for one update row ("no" = Import is not offered). */
export type ImportInfo = { importable?: Importable; importable_reason?: string };

const LIB_PER_PAGE = 100; // server maximum (libMaxPerPage)
const LIB_MAX_PAGES = 20; // 2,000 installed apps is far more than a bank fleet has
const LIB_POLL_MS = 5 * 60_000;

/**
 * Why an update cannot be imported, or null when Import may be offered.
 * The Library ("importable: no") and the downloader ("unsupported") both
 * block it; the reason is shown as "Can't import: <reason>".
 */
export function cantImportReason(info: ImportInfo | null | undefined, requested?: AcquisitionRequestRef | null): string | null {
  if (info?.importable === "no") return info.importable_reason?.trim() || "no supported installer";
  const req = liveRequested(requested, info);
  if (req?.status === "unsupported") return req.reason?.trim() || "the acquisition team cannot fetch it this way";
  return null;
}

/**
 * An old "can't import" (unsupported) result that no longer holds is
 * ignored, so Import is offered again: the Library now says the app can be
 * imported, or the result came from a downloader that only took MSI
 * installers ("no MSI installer for x64 …"; it now tries EXE, MSIX,
 * per-user and portable installers too). Same rule as the server (liveRef).
 */
export function liveRequested<T extends AcquisitionRequestRef>(requested: T | null | undefined, info?: ImportInfo | null): T | undefined {
  if (!requested) return undefined;
  if (requested.status === "unsupported" && (info?.importable === "yes" || /no MSI installer for/.test(requested.reason ?? ""))) return undefined;
  return requested;
}

/** Map key for an app (winget ids are case-insensitive). */
export const appInfoKey = (wingetId: string): string => wingetId.trim().toLowerCase();

async function fetchInstalledLibrary(): Promise<Map<string, ImportInfo>> {
  const m = new Map<string, ImportInfo>();
  for (let page = 1; page <= LIB_MAX_PAGES; page++) {
    const p = await api.get<LibraryPage>(`/api/library?kind=app&view=installed&per_page=${LIB_PER_PAGE}&page=${page}`);
    for (const it of p.items ?? []) m.set(appInfoKey(it.id), { importable: it.importable, importable_reason: it.importable_reason });
    if (page * p.per_page >= p.total || (p.items ?? []).length === 0) break;
  }
  return m;
}

/**
 * Library verdicts of the installed apps, keyed by appInfoKey. Only for the
 * super admin (the Library API is theirs); for everyone else the update rows
 * carry `importable` themselves (assumed server field) and this map is empty.
 * A failed load is not an error for the page: rows then fall back to the
 * row fields and the request status.
 */
export function useLibraryImportability(enabled: boolean): Map<string, ImportInfo> {
  const lib = useLoad(() => (enabled ? fetchInstalledLibrary() : Promise.resolve(null)), [enabled], enabled ? LIB_POLL_MS : undefined);
  return lib.data ?? EMPTY;
}
const EMPTY = new Map<string, ImportInfo>();

/** The row's own fields win; otherwise the Library verdict for apps. */
export function importInfoOf(row: ImportInfo & { kind: string; key: string }, lib: Map<string, ImportInfo>): ImportInfo {
  if (row.importable) return { importable: row.importable, importable_reason: row.importable_reason };
  return row.kind === "app" ? lib.get(appInfoKey(row.key)) ?? {} : {};
}
