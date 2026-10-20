// Two-step sign-in screens: the code step after the password, first-time
// set-up (QR code, key, confirm, recovery codes) and the recovery-code list.
import { useEffect, useRef, useState, type FormEvent } from "react";
import { ApiError, errMsg, saveBlob } from "../api";
import { ErrorBanner } from "../components/ui";
import { CodeInput } from "./CodeInput";
import "./mfa.css";
import { QrCode } from "./QrCode";
import { confirmEnroll, groupSecret, isOtpauthUri, startEnroll, verifyCode, verifyRecoveryCode, type EnrollStart } from "./mfaApi";

function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

/** Server: 401/400 "wrong or expired code"; 401 "sign-in expired; …"; 403 disabled; 429 rate limit. */
function codeError(e: unknown): string {
  if (e instanceof ApiError && e.status === 429) {
    return /two-step sign-in is locked/i.test(e.message)
      ? "Too many wrong codes: two-step sign-in is locked for a while (15 minutes, longer if it happens again). Try later or ask an administrator to unlock your account."
      : "Too many attempts. Wait a few minutes and try again.";
  }
  if (e instanceof ApiError && /wrong or expired code/i.test(e.message)) {
    return "That code is not right. Use the newest code (each code works once). After 3 wrong codes you sign in again with your password; after 5 in a row two-step sign-in is locked for 15 minutes.";
  }
  return errMsg(e);
}

/** 401 "sign-in expired; enter your email and password again": the pre-auth step timed out. */
function signInExpired(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401 && /sign-in expired/i.test(e.message);
}

/** After the password: "Enter the 6-digit code from your authenticator app" (or a recovery code). */
/** `onCancel(reason)`: back to e-mail and password (reason shown there, e.g. the step expired). */
export function MfaChallenge({ onDone, onCancel }: { onDone: () => Promise<void>; onCancel: (reason?: string) => void }) {
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submitCode = async (c: string) => {
    if (busy || c.length !== 6) return;
    setBusy(true);
    setError(null);
    try {
      await verifyCode(c);
      await onDone();
    } catch (e) {
      if (signInExpired(e)) { onCancel(errMsg(e)); return; }
      setError(codeError(e));
      setCode("");
      setBusy(false);
    }
  };

  const submitRecovery = async (e: FormEvent) => {
    e.preventDefault();
    const r = recovery.trim();
    if (!r || busy) return;
    setBusy(true);
    setError(null);
    try {
      await verifyRecoveryCode(r);
      await onDone();
    } catch (err) {
      if (signInExpired(err)) { onCancel(errMsg(err)); return; }
      setError(err instanceof ApiError && err.status === 401 ? "That recovery code is not valid or was already used." : codeError(err));
      setBusy(false);
    }
  };

  if (useRecovery) {
    return (
      <form className="login-token" onSubmit={submitRecovery} aria-busy={busy}>
        <label className="field">
          <span>Recovery code</span>
          <input className="mono" autoFocus autoComplete="off" spellCheck={false} value={recovery} onChange={(e) => setRecovery(e.target.value)} />
          <small className="hint">Each recovery code works once. Afterwards, ask an Admin to reset two-step sign-in if you lost your phone.</small>
        </label>
        <ErrorBanner error={error} />
        <button className="btn btn-primary btn-block btn-lg" disabled={busy || !recovery.trim()}>{busy ? <><Spinner /> Checking…</> : "Sign in"}</button>
        <p className="login-alt">
          <button type="button" className="btn-link" onClick={() => { setUseRecovery(false); setError(null); }}>Use the authenticator app instead</button>
          {" · "}<button type="button" className="btn-link" onClick={() => onCancel()}>Back</button>
        </p>
      </form>
    );
  }
  return (
    <form className="login-token" onSubmit={(e) => { e.preventDefault(); void submitCode(code); }} aria-busy={busy}>
      <CodeInput value={code} onChange={setCode} onComplete={(c) => void submitCode(c)} disabled={busy} autoFocus invalid={!!error} />
      <ErrorBanner error={error} />
      <button className="btn btn-primary btn-block btn-lg" disabled={busy || code.length !== 6}>{busy ? <><Spinner /> Checking…</> : "Verify"}</button>
      <p className="login-alt">
        <button type="button" className="btn-link" onClick={() => { setUseRecovery(true); setError(null); }}>Use a recovery code instead</button>
        {" · "}<button type="button" className="btn-link" onClick={() => onCancel()}>Back</button>
      </p>
    </form>
  );
}

/** Recovery codes, shown once: copy, download .txt, and "I saved them" before continuing. */
export function RecoveryCodes({ codes, account, onContinue, continueLabel = "Continue" }: {
  codes: string[]; account: string; onContinue: () => void; continueLabel?: string;
}) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const text = `DSS Patcher recovery codes for ${account}\nEach code works once. Keep them somewhere safe, away from your phone.\n\n${codes.join("\n")}\n`;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked (plain http): the codes are selectable */
    }
  };
  const download = () => saveBlob(new Blob([text], { type: "text/plain;charset=utf-8" }), "dss-patcher-recovery-codes.txt");
  return (
    <div className="mfa-recovery">
      <p className="login-sub">
        If you lose your phone, each of these codes lets you sign in once. <b>They are shown only now.</b> Print them or keep them in a password manager.
      </p>
      {codes.length === 0 ? <div className="banner banner-warn">The server returned no recovery codes. Ask an Admin to reset two-step sign-in if you lose your phone.</div> : (
        <ol className="mfa-codes">{codes.map((c) => <li key={c}><code>{c}</code></li>)}</ol>
      )}
      <div className="mfa-actions">
        <button type="button" className="btn" onClick={() => void copy()} disabled={codes.length === 0}>{copied ? "Copied" : "Copy"}</button>
        <button type="button" className="btn" onClick={download} disabled={codes.length === 0}>Download .txt</button>
      </div>
      <label className="check mfa-saved">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> I saved my recovery codes
      </label>
      <button type="button" className="btn btn-primary btn-block btn-lg" disabled={!saved} onClick={onContinue}>{continueLabel}</button>
    </div>
  );
}

/** First-time set-up: scan the QR code (or type the key), confirm a code, then save the recovery codes. */
export function MfaSetupFlow({ account, onFinished, onCancel }: { account: string; onFinished: () => void | Promise<void>; onCancel?: () => void }) {
  const [enroll, setEnroll] = useState<EnrollStart | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  const start = async () => {
    setError(null);
    try {
      setEnroll(await startEnroll());
    } catch (e) {
      setError(`Could not start set-up: ${errMsg(e)}`);
    }
  };
  useEffect(() => {
    if (started.current) return; // StrictMode / re-render: one secret per visit
    started.current = true;
    void start();
  }, []);

  const confirm = async (c: string) => {
    if (busy || c.length !== 6) return;
    setBusy(true);
    setError(null);
    try {
      const r = await confirmEnroll(c);
      setCodes(r.recovery_codes);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        // The pending key expired (15 min) or was never started: begin again with a new key.
        setEnroll(null);
        setError(`${errMsg(e)}. Press Try again for a new key, then scan it again.`);
      } else {
        setError(codeError(e));
      }
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  if (codes) return <RecoveryCodes codes={codes} account={account} onContinue={() => void onFinished()} />;
  return (
    <div className="mfa-setup">
      <ol className="mfa-steps">
        <li>Open an authenticator app on your phone (for example Microsoft Authenticator, Google Authenticator or FreeOTP).</li>
        <li>Add an account and scan this QR code.</li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      {!enroll && !error && <div className="muted" role="status"><Spinner /> Preparing…</div>}
      {enroll && (
        <>
          <div className="mfa-qr">
            {isOtpauthUri(enroll.otpauth_uri)
              ? <QrCode text={enroll.otpauth_uri} size={196} label="QR code for your authenticator app" />
              : <div className="banner banner-warn">The server sent an unexpected set-up link; type the key by hand.</div>}
          </div>
          <div className="field">
            <span>Can't scan? Type this key</span>
            <code className="mfa-secret" aria-label="Set-up key">{groupSecret(enroll.secret_base32)}</code>
            <small className="hint">Time-based, 6 digits, every 30 seconds.</small>
          </div>
          <form className="login-token" onSubmit={(e) => { e.preventDefault(); void confirm(code); }} aria-busy={busy}>
            <div className="field"><span>Code from the app</span></div>
            <CodeInput value={code} onChange={setCode} onComplete={(c) => void confirm(c)} disabled={busy} invalid={!!error} />
            <ErrorBanner error={error} />
            <button className="btn btn-primary btn-block btn-lg" disabled={busy || code.length !== 6}>{busy ? <><Spinner /> Checking…</> : "Turn on two-step sign-in"}</button>
          </form>
        </>
      )}
      {!enroll && error && (
        <>
          <ErrorBanner error={error} />
          <button type="button" className="btn btn-block" onClick={() => void start()}>Try again</button>
        </>
      )}
      {onCancel && <p className="login-alt"><button type="button" className="btn-link" onClick={onCancel}>Cancel</button></p>}
    </div>
  );
}
