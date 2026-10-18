import { useState } from "react";
import { errMsg } from "../api";
import { useMe } from "../auth";
import { fetchMe } from "../components/SignIn";
import { ErrorBanner, Modal, Pill } from "../components/ui";
import { useLoad } from "../util";
import { CodeInput } from "./CodeInput";
import { MfaSetupFlow } from "./MfaScreens";
import { disableMfa } from "./mfaApi";

/**
 * Settings → Users, super admin only: their own optional two-step sign-in.
 * (Bank roles must use it and set it up at sign-in.)
 */
export function TwoStepSection() {
  const me = useMe();
  const live = useLoad(fetchMe, []);
  const current = live.data ?? me;
  const [dialog, setDialog] = useState<"on" | "off" | null>(null);
  if (!current || current.role !== "super_admin" || current.auth !== "password") return null;
  const on = !!(current.mfa_enrolled ?? current.mfa);
  /** require_mfa in the server settings makes it mandatory for the super admin too (disable answers 409). */
  const required = !!current.mfa_required;
  const close = () => setDialog(null);

  return (
    <section className="card two-step">
      <div className="section-head">
        <div>
          <h2>Two-step sign-in <span className="muted small">· your account</span></h2>
          <div className="hint">
            Optional for the super admin: after your password, also ask for a code from an authenticator app.
            Bank users (Viewer, User, Admin) always need it.
          </div>
        </div>
        <div className="actions-inline">
          {on ? <Pill state="compliant" label="On" /> : <Pill state="stale" label="Off" />}
          {on && required && <span className="muted small">Required by the server settings</span>}
          {on && !required && <button className="btn btn-danger-ghost" onClick={() => setDialog("off")}>Turn off…</button>}
          {!on && <button className="btn btn-primary" onClick={() => setDialog("on")}>Turn on…</button>}
        </div>
      </div>
      <ErrorBanner error={live.error} />
      {dialog === "on" && (
        <Modal title="Turn on two-step sign-in" onClose={close}>
          <MfaSetupFlow account={current.email || current.user} onCancel={close}
            onFinished={async () => { await live.reload(); close(); }} />
        </Modal>
      )}
      {dialog === "off" && <TurnOffModal onClose={close} onDone={async () => { await live.reload(); close(); }} />}
    </section>
  );
}

function TurnOffModal({ onClose, onDone }: { onClose: () => void; onDone: () => Promise<void> }) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (c: string) => {
    if (busy || c.length !== 6) return;
    setBusy(true);
    setError(null);
    try {
      await disableMfa(c);
      await onDone();
    } catch (e) {
      setError(errMsg(e));
      setCode("");
      setBusy(false);
    }
  };
  return (
    <Modal title="Turn off two-step sign-in" onClose={onClose} footer={
      <>
        <button className="btn" onClick={onClose} disabled={busy}>Cancel</button>
        <button className="btn btn-danger" onClick={() => void submit(code)} disabled={busy || code.length !== 6}>{busy ? "Turning off…" : "Turn off"}</button>
      </>
    }>
      <div className="modal-desc">Enter the current code from your authenticator app. Your recovery codes stop working too.</div>
      <CodeInput value={code} onChange={setCode} disabled={busy} autoFocus invalid={!!error} />
      <ErrorBanner error={error} />
    </Modal>
  );
}
