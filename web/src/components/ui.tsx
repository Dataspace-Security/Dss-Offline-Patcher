import { createContext, useContext, useEffect, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import { fmtTime, relTime, useNow } from "../util";

const GREEN = ["verified", "compliant", "approved", "validated", "completed", "installed", "downloaded", "success", "active-ok"];
const AMBER = ["pending_reboot", "paused", "quarantined", "noncompliant", "pending", "downloading", "installing", "received", "deferred"];
const RED = ["failed", "rejected", "revoked", "offline", "cancelled", "failure", "expired", "lost_after_install"];
const MUTED = ["stale", "exception", "not_applicable", "rolled_back"];
const BLUE = ["active"];

export function pillTone(state: string): string {
  if (GREEN.includes(state)) return "green";
  if (AMBER.includes(state)) return "amber";
  if (RED.includes(state)) return "red";
  if (MUTED.includes(state)) return "purple";
  if (BLUE.includes(state)) return "blue";
  return "grey";
}

export function Pill({ state, label }: { state: string; label?: string }) {
  return <span className={`pill pill-${pillTone(state)}`}>{(label ?? state).replace(/_/g, " ")}</span>;
}

export function Time({ value, hideRel }: { value: string | undefined | null; hideRel?: boolean }) {
  const now = useNow();
  const abs = fmtTime(value);
  if (abs === "—") return <span className="muted">—</span>;
  return (
    <span className="time" title={value ?? ""}>
      {abs}
      {!hideRel && <span className="rel"> · {relTime(value, now)}</span>}
    </span>
  );
}

export function RelTime({ value }: { value: string | undefined | null }) {
  const now = useNow();
  return <span title={fmtTime(value)}>{relTime(value, now)}</span>;
}

export function ErrorBanner({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return <div className="banner banner-error">{error}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/**
 * Set by a tabbed area (Patches) whose pages are shown inside one shared
 * header: PageHeader then keeps the page's description and controls but
 * drops its own title.
 */
export const EmbeddedHeader = createContext(false);

export function PageHeader({ title, sub, children }: { title: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  const embedded = useContext(EmbeddedHeader);
  if (embedded) {
    if (!sub && !children) return null;
    return (
      <div className="page-header page-header-embedded">
        <div>{sub && <div className="sub">{sub}</div>}</div>
        <div className="actions">{children}</div>
      </div>
    );
  }
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      <div className="actions">{children}</div>
    </div>
  );
}

/**
 * Props for a table row that expands/collapses on click: also focusable and
 * operable with Enter / Space, and announces its state to assistive tech.
 */
export function expandRowProps(isOpen: boolean, toggle: () => void, className = "") {
  return {
    className: `clickable ${isOpen ? "selected" : ""} ${className}`.trim(),
    onClick: toggle,
    tabIndex: 0,
    "aria-expanded": isOpen,
    onKeyDown: (e: ReactKeyboardEvent<HTMLElement>) => {
      if (e.target !== e.currentTarget) return; // keys inside buttons/links/inputs keep their meaning
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
    },
  };
}

/** Accessible meter for a 0–100 share (score bars). */
export function Meter({ pct, tone, label }: { pct: number; tone: string; label: string }) {
  return (
    <div className="score-meter" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
      <span className={`bg-${tone}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k} className="kv-row">
          <dt>{k}</dt>
          <dd>{v === "" || v === null || v === undefined ? <span className="muted">—</span> : v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Mono({ children, title }: { children: ReactNode; title?: string }) {
  return <code className="mono" title={title}>{children}</code>;
}

export function Modal({ title, onClose, children, footer, wide, xwide }: {
  title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean; xwide?: boolean;
}) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${wide ? "modal-wide" : ""} ${xwide ? "modal-xwide" : ""}`} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="btn-icon" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

/** Confirmation modal with a reason field. `required` enforces a non-empty reason. */
export function ReasonModal({ title, description, confirmLabel, danger, required = true, onClose, onSubmit }: {
  title: string; description?: ReactNode; confirmLabel: string; danger?: boolean; required?: boolean;
  onClose: () => void; onSubmit: (reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ok = !required || reason.trim().length > 0;
  const submit = async () => {
    if (!ok || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onSubmit(reason.trim());
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          {!ok && <span className="reason-hint">Type a reason to enable {confirmLabel}</span>}
          <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
          <button className={`btn ${danger ? "btn-danger" : "btn-primary"}`} onClick={submit} disabled={!ok || busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </>
      }
    >
      {description && <div className="modal-desc">{description}</div>}
      <label className="field">
        <span>Reason {required ? <em className="req">required</em> : <em className="muted">optional</em>}</span>
        <textarea
          autoFocus
          rows={3}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={required ? "Recorded in the audit log" : "Optional; recorded in the audit log"}
          onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) void submit(); }}
        />
      </label>
      <ErrorBanner error={error} />
    </Modal>
  );
}

export function CopyBox({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable over plain http; text is selectable */
    }
  };
  return (
    <div className="copybox">
      <input readOnly value={value} onFocus={(e) => e.currentTarget.select()} className="mono" />
      <button className="btn" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
    </div>
  );
}

const TARGET_ORDER = [
  "verified", "installed", "pending_reboot", "installing", "downloaded", "downloading",
  "pending", "deferred", "failed", "lost_after_install", "exception", "not_applicable", "rolled_back",
];

/** Target state as shown to people: rollback deployments uninstall, so their
 * in-flight and done states read as such. */
export function targetLabel(state: string, operation?: string): string {
  if (operation === "rollback") {
    const l: Record<string, string> = { installing: "uninstalling", installed: "uninstalled", verified: "verified removed", pending_reboot: "pending reboot" };
    if (l[state]) return l[state];
  }
  return state.replace(/_/g, " ");
}

export const TARGET_HELP: Record<string, string> = {
  deferred: "Pre-install check not met (free disk space or battery). Retried at every check-in; not a failure.",
  lost_after_install: "The endpoint stopped checking in after installing. Counts as a failure towards auto-pause; recovers when it checks in again.",
  rolled_back: "Removed by a rollback deployment; no longer counted as patched.",
};

export function TargetPill({ state, operation }: { state: string; operation?: string }) {
  return <span title={TARGET_HELP[state]}><Pill state={state} label={targetLabel(state, operation)} /></span>;
}

export function CountsBar({ counts, compact, rollback }: { counts: Partial<Record<string, number>>; compact?: boolean; rollback?: boolean }) {
  const entries = TARGET_ORDER
    .map((k) => [k, counts[k] ?? 0] as [string, number])
    .concat(Object.entries(counts).filter(([k]) => !TARGET_ORDER.includes(k)).map(([k, v]) => [k, v ?? 0] as [string, number]))
    .filter(([, v]) => v > 0);
  const total = entries.reduce((a, [, v]) => a + v, 0);
  if (total === 0) return <span className="muted">no targets</span>;
  return (
    <div className={`counts ${compact ? "counts-compact" : ""}`}>
      {!compact && <PatchScore counts={counts} rollback={rollback} />}
      <div className="countbar" title={entries.map(([k, v]) => `${k}: ${v}`).join(", ")}
           role="progressbar" aria-label={rollback ? "Removed" : "Patched"} aria-valuemin={0} aria-valuemax={100}
           aria-valuenow={patchScore(counts).pct} aria-valuetext={entries.map(([k, v]) => `${targetLabel(k, rollback ? "rollback" : undefined)} ${v}`).join(", ")}>
        {entries.map(([k, v]) => (
          <span key={k} className={`seg seg-${pillTone(k)} seg-${k}`} style={{ width: `${(v / total) * 100}%` }} />
        ))}
      </div>
      {!compact && (
        <div className="legend">
          {entries.map(([k, v]) => (
            <span key={k} className="legend-item">
              <span className={`dot seg-${pillTone(k)} seg-${k}`} />
              {targetLabel(k, rollback ? "rollback" : undefined)} <b>{v}</b>
            </span>
          ))}
          <span className="legend-item muted">total <b>{total}</b></span>
        </div>
      )}
    </div>
  );
}

/**
 * Patch score: share of applicable targets that are verified (installed AND
 * confirmed by fresh inventory). Not-applicable and excepted targets are
 * left out; failed, pending and silent endpoints count against the score.
 */
export function patchScore(counts: Partial<Record<string, number>>) {
  const total = Object.values(counts).reduce<number>((a, v) => a + (v ?? 0), 0);
  const applicable = total - (counts.not_applicable ?? 0) - (counts.exception ?? 0);
  const patched = counts.verified ?? 0;
  const pct = applicable > 0 ? Math.floor((patched / applicable) * 100) : total > 0 ? 100 : 0;
  return { pct, patched, applicable, total };
}

export function scoreTone(pct: number): "green" | "amber" | "red" {
  return pct >= 95 ? "green" : pct >= 70 ? "amber" : "red";
}

export function PatchScore({ counts, rollback }: { counts: Partial<Record<string, number>>; rollback?: boolean }) {
  const s = patchScore(counts);
  if (s.total === 0) return null;
  return (
    <div className="patch-score">
      <span className={`patch-score-pct text-${scoreTone(s.pct)}`}>{s.pct}%</span>
      <span className="patch-score-label">
        {rollback ? "removed" : "patched"} — <b>{s.patched}</b> of <b>{s.applicable}</b> endpoint{s.applicable === 1 ? "" : "s"} verified{rollback ? " without the package" : ""}
        {s.total !== s.applicable && <span className="muted"> ({s.total - s.applicable} not applicable / excepted)</span>}
      </span>
    </div>
  );
}
