import { useEffect, useState } from "react";
import type { LibraryItem } from "../types";
import { CopyBox, Pill } from "./ui";

/** A value that follows `value` once it has stopped changing for `ms`. */
export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

const MAX_LINK = 2048;

/**
 * Only plain https URLs up to 2 KB are ever rendered as links (community data:
 * no javascript:, data:, http: or credentials in the URL). Returns the
 * normalised URL or null.
 */
export function safeHttpsUrl(raw: string | undefined | null): string | null {
  if (!raw || raw.length > MAX_LINK) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:" || u.username || u.password) return null;
    return u.toString();
  } catch {
    return null;
  }
}

/**
 * An untrusted community link: copyable text (the isolated console usually
 * has no internet) and, when it is a safe https URL, a link that opens in a
 * new tab without referrer or opener.
 */
export function UnverifiedLink({ label, url }: { label: string; url: string | undefined | null }) {
  const safe = safeHttpsUrl(url);
  if (!safe) return null;
  return (
    <div className="lib-link">
      <div className="lib-link-head">
        <b>{label}</b>{" "}
        <a href={safe} target="_blank" rel="noopener noreferrer">open</a>{" "}
        <span className="muted small">unverified · winget community</span>
      </div>
      <CopyBox value={safe} />
    </div>
  );
}

/** "can import" / "Can't import: reason" / "Not checked yet". */
export function ImportableBadge({ item }: { item: Pick<LibraryItem, "importable" | "importable_reason"> }) {
  if (item.importable === "yes") {
    return <span title="offpatch can download and install this (MSI installer)"><Pill state="verified" label="can import" /></span>;
  }
  if (item.importable === "no") {
    return <span className="text-red small">Can't import{item.importable_reason ? `: ${item.importable_reason}` : ""}</span>;
  }
  return (
    <span className="muted small" title="The installer has not been looked at yet. The acquisition team checks it when it downloads.">
      Not checked yet
    </span>
  );
}

/** "3 machines (1 outdated)" / "none". */
export function InstalledCount({ installed }: { installed: LibraryItem["installed"] }) {
  if (!installed?.endpoints) return <span className="muted">none</span>;
  return (
    <span>
      <b>{installed.endpoints}</b> machine{installed.endpoints === 1 ? "" : "s"}
      {installed.outdated > 0 && <span className="text-amber"> ({installed.outdated} outdated)</span>}
    </span>
  );
}
