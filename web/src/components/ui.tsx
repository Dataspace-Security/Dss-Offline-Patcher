import { createContext, useContext, useEffect, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { fmtTime, relTime, useNow } from "../util";
import { normalizeRole, ROLE_HELP, roleLabel } from "../auth";

const GREEN = ["verified", "compliant", "approved", "validated", "completed", "success", "active-ok"];
const AMBER = ["pending_approval", "pending_reboot", "paused", "quarantined", "noncompliant", "pending", "received", "deferred", "updates_available"];
const RED = ["failed", "rejected", "revoked", "offline", "cancelled", "failure", "expired", "lost_after_install", "out_of_support"];
const MUTED = ["stale", "exception", "not_applicable", "rolled_back"];
// Work in progress is blue: green only once confirmed, red only for real failures.
const BLUE = ["active", "downloading", "downloaded", "installing", "installed"];

export function pillTone(state: string): string {
  if (GREEN.includes(state)) return "green";
  if (AMBER.includes(state)) return "amber";
  if (RED.includes(state)) return "red";
  if (MUTED.includes(state)) return "purple";
  if (BLUE.includes(state)) return "blue";
  return "grey"; // includes awaiting_checkin
}

/** Plain words for states whose stored name reads badly. */
const STATE_LABELS: Record<string, string> = {
  pending_reboot: "Restart needed",
  updates_available: "Updates available",
  out_of_support: "Windows no longer updated",
  awaiting_checkin: "Waiting for first check-in",
  pending_approval: "Waiting for approval",
};

/** Help text (tooltips) for endpoint statuses. */
export const STATUS_HELP: Record<string, string> = {
  pending_reboot: "Installed; the machine has to restart to finish. It stays like this until it is restarted.",
  updates_available: "Checking in and no deployment problem, but Windows or application updates are missing.",
  out_of_support: "This Windows version no longer receives security updates from Microsoft: upgrade it.",
  awaiting_checkin: "Enrolled, but the agent has not sent its first inventory yet.",
};

/** Display name of a state: plain words where defined, else the state with spaces. */
export function stateLabel(state: string): string {
  return STATE_LABELS[state] ?? state.replace(/_/g, " ");
}

export function Pill({ state, label }: { state: string; label?: string }) {
  return (
    <span className={`pill pill-${pillTone(state)}`} title={label === undefined ? STATUS_HELP[state] : undefined}>
      {label !== undefined ? label.replace(/_/g, " ") : stateLabel(state)}
    </span>
  );
}

/** Role as shown to people: Super admin (vendor), Admin, User, Viewer (old names map to User). */
export function RoleBadge({ role }: { role: string }) {
  const r = normalizeRole(role);
  return <span className={`role role-${r}`} title={ROLE_HELP[r]}>{roleLabel(r)}</span>;
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
  return <div className="banner banner-error" role="alert">{error}</div>;
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

// Open dialogs (nested ones too): the page behind stays still while any is open.
let openModals = 0;
function lockBodyScroll(): () => void {
  openModals += 1;
  document.body.classList.add("modal-open");
  return () => {
    openModals = Math.max(0, openModals - 1);
    if (openModals === 0) document.body.classList.remove("modal-open");
  };
}

/**
 * A dialog. It is rendered at <body> (a portal), so no sticky or transformed
 * ancestor (side panel, sticky table header) can paint over it; the page
 * behind does not scroll while it is open.
 */
export function Modal({ title, onClose, children, footer, wide, xwide }: {
  title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean; xwide?: boolean;
}) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  useEffect(() => lockBodyScroll(), []);
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${wide ? "modal-wide" : ""} ${xwide ? "modal-xwide" : ""}`} role="dialog" aria-modal="true">
        <div className="modal-head">
          <h2>{title}</h2>
          <button className="btn-icon" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>,
    document.body,
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
    const l: Record<string, string> = { installing: "uninstalling", installed: "uninstalled", verified: "verified removed" };
    if (l[state]) return l[state];
  }
  return stateLabel(state);
}

export const TARGET_HELP: Record<string, string> = {
  pending_reboot: "Installed; the machine has to restart to finish. See the detail for why it has not restarted yet.",
  deferred: "Pre-install check not met (free disk space or battery). Retried at every check-in; not a failure.",
  lost_after_install: "The endpoint stopped checking in after installing. Counts as a failure towards auto-pause; recovers when it checks in again.",
  rolled_back: "Removed by a rollback deployment; no longer counted as patched.",
};

export function TargetPill({ state, operation }: { state: string; operation?: string }) {
  return <span title={TARGET_HELP[state]}><Pill state={state} label={targetLabel(state, operation)} /></span>;
}

export function CountsBar({ counts, compact, rollback, running }: { counts: Partial<Record<string, number>>; compact?: boolean; rollback?: boolean; running?: boolean }) {
  const entries = TARGET_ORDER
    .map((k) => [k, counts[k] ?? 0] as [string, number])
    .concat(Object.entries(counts).filter(([k]) => !TARGET_ORDER.includes(k)).map(([k, v]) => [k, v ?? 0] as [string, number]))
    .filter(([, v]) => v > 0);
  const total = entries.reduce((a, [, v]) => a + v, 0);
  if (total === 0) return <span className="muted">no targets</span>;
  return (
    <div className={`counts ${compact ? "counts-compact" : ""}`}>
      {!compact && <PatchScore counts={counts} rollback={rollback} running={running} />}
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

/**
 * While a deployment is still running the share is progress, not a grade:
 * blue until it finishes (then the green / amber / red score applies), and
 * red at once only if something failed.
 */
export function PatchScore({ counts, rollback, running }: { counts: Partial<Record<string, number>>; rollback?: boolean; running?: boolean }) {
  const s = patchScore(counts);
  if (s.total === 0) return null;
  const failed = (counts.failed ?? 0) + (counts.lost_after_install ?? 0);
  const tone = running && failed === 0 && s.pct < 100 ? "blue" : scoreTone(s.pct);
  return (
    <div className="patch-score">
      <span className={`patch-score-pct text-${tone}`}>{s.pct}%</span>
      <span className="patch-score-label">
        {rollback ? "removed" : "patched"} — <b>{s.patched}</b> of <b>{s.applicable}</b> endpoint{s.applicable === 1 ? "" : "s"} verified{rollback ? " without the package" : ""}
        {s.total !== s.applicable && <span className="muted"> ({s.total - s.applicable} not applicable / excepted)</span>}
      </span>
    </div>
  );
}
