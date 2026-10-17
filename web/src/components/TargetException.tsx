import { useState } from "react";
import { api, errMsg } from "../api";
import type { Deployment, Exception, NewException, Target } from "../types";
import { toRFC3339 } from "../util";
import { ErrorBanner, Modal, Mono } from "./ui";

const DEFAULT_EXCEPTION_DAYS = 30;

function localInputValue(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function failureText(t: Target): string {
  return [
    t.state.replace(/_/g, " "),
    t.exit_code ? `exit code ${t.exit_code}` : "",
    `${t.attempts} attempt${t.attempts === 1 ? "" : "s"}`,
    t.detail ? `detail: ${t.detail}` : "",
    t.health === "failed" && t.health_detail ? `health check: ${t.health_detail}` : "",
  ].filter(Boolean).join("; ");
}

/** Approver: create an exception for one failed target (POST /api/exceptions). */
export function RaiseExceptionModal({ target, deployment, onClose, onDone }: {
  target: Target; deployment: Deployment; onClose: () => void; onDone: () => void;
}) {
  const [owner, setOwner] = useState("");
  const [reason, setReason] = useState(`Install failed in deployment ${deployment.name || deployment.deployment_id}: ${failureText(target)}`);
  const [controls, setControls] = useState("");
  const [expires, setExpires] = useState(() => localInputValue(new Date(Date.now() + DEFAULT_EXCEPTION_DAYS * 86400_000)));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const expDate = expires ? new Date(expires) : null;
  const expValid = !!expDate && !isNaN(expDate.getTime()) && expDate.getTime() > Date.now();
  const valid = owner.trim() !== "" && reason.trim() !== "" && expValid;

  const submit = async () => {
    if (!valid || busy) return;
    setBusy(true);
    setError(null);
    const body: NewException = {
      endpoint_id: target.endpoint_id, package_id: target.package_id, owner: owner.trim(), reason: reason.trim(),
      compensating_controls: controls.trim(), expires_at: toRFC3339(expires),
    };
    try {
      await api.post<Exception>("/api/exceptions", body);
      onDone();
      onClose();
    } catch (e) {
      setError(errMsg(e));
      setBusy(false);
    }
  };

  return (
    <Modal title={`Raise exception · ${target.hostname || target.endpoint_id}`} onClose={onClose} wide footer={
      <>
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="btn btn-primary" disabled={!valid || busy} onClick={() => void submit()}>{busy ? "Creating…" : "Create exception"}</button>
      </>
    }>
      <div className="modal-desc">
        Accept the risk for <b>{target.hostname || target.endpoint_id}</b> and package <Mono>{target.package_id}</Mono> until the expiry.
        The target then counts as an exception, not a failure. Recorded in the audit log.
      </div>
      <div className="form-grid">
        <label className="field">
          <span>Owner <em className="req">required</em></span>
          <input autoFocus value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Accountable person or team" />
        </label>
        <label className="field">
          <span>Expires at <em className="req">required, local time</em></span>
          <input type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
          {expires && !expValid && <small className="text-red">Must be in the future.</small>}
        </label>
      </div>
      <label className="field">
        <span>Reason <em className="req">required</em></span>
        <textarea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
      </label>
      <label className="field">
        <span>Compensating controls</span>
        <textarea rows={2} value={controls} onChange={(e) => setControls(e.target.value)} placeholder="e.g. host isolated in VLAN, EDR in block mode" />
      </label>
      <ErrorBanner error={error} />
    </Modal>
  );
}

/** Operators and viewers cannot create exceptions: give them text to send to an approver. */
export function AskApproverModal({ target, deployment, onClose }: { target: Target; deployment: Deployment; onClose: () => void }) {
  const link = `${window.location.origin}/deployments/${encodeURIComponent(deployment.deployment_id)}`;
  const text = [
    "Exception request (offpatch)",
    `Endpoint: ${target.hostname || target.endpoint_id} (${target.endpoint_id})`,
    `Package: ${target.package_id}`,
    `Deployment: ${deployment.name || deployment.deployment_id} (${deployment.deployment_id})`,
    `Failure: ${failureText(target)}`,
    `Link: ${link}`,
    "Please review and raise an exception (Exceptions page, or \"Raise exception…\" on the target row) if the risk is accepted.",
  ].join("\n");
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable over plain http: the text stays selectable */
    }
  };
  return (
    <Modal title="Ask an approver for an exception" onClose={onClose} wide footer={
      <>
        <button className="btn" onClick={onClose}>Close</button>
        <button className="btn btn-primary" onClick={() => void copy()}>{copied ? "Copied" : "Copy text"}</button>
      </>
    }>
      <div className="modal-desc">Only approvers can create exceptions. Send this to an approver:</div>
      <textarea className="mono copy-area" readOnly rows={8} value={text} onFocus={(e) => e.currentTarget.select()} />
    </Modal>
  );
}
