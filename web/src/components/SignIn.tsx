import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useLocation } from "react-router-dom";
import { api, ApiError, errMsg } from "../api";
import { normalizeMe } from "../auth";
import { normalizeEmail, passwordProblems } from "../passwords";
import type { AuthConfig, Me } from "../types";
import { ErrorBanner } from "./ui";
import { BrandLogo, IconOffline, IconShieldCheck, IconUsers } from "./icons";
import { PasswordInput } from "./PasswordInput";
import { ThemeSwitcher } from "./ThemeSwitcher";
import { MfaChallenge } from "../mfa/MfaScreens";
import type { LoginResponse } from "../mfa/mfaApi";

/** Ask the server who is signed in (password or SSO session cookie). */
export async function fetchMe(): Promise<Me> {
  return normalizeMe(await api.get<Me>("/api/me"));
}

/** Sign-in page: e-mail + password, and "Use SSO" when the server has single sign-on. */
export function SignIn({ onLogin, ssoError }: { onLogin: (me: Me) => void; ssoError: string | null }) {
  const location = useLocation();
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const [mfaStep, setMfaStep] = useState(false);
  const [stepError, setStepError] = useState<string | null>(null);

  useEffect(() => {
    api.get<AuthConfig>("/auth/config")
      .then(setCfg)
      .catch(() => setCfg({ sso: false, require_mfa: false }));
  }, []);

  const returnPath = (() => {
    if (location.pathname === "/login") return "/";
    const sp = new URLSearchParams(location.search);
    sp.delete("login_error");
    const q = sp.toString();
    return `${location.pathname}${q ? `?${q}` : ""}`;
  })();
  const sso = () => window.location.assign(`/auth/login?return=${encodeURIComponent(returnPath)}`);

  if (mfaStep) {
    return (
      <AuthLayout version={cfg?.version} title="Two-step sign-in" sub="Enter the 6-digit code from your authenticator app.">
        <MfaChallenge onDone={async () => onLogin(await fetchMe())} onCancel={(reason) => { setStepError(reason ?? null); setMfaStep(false); }} />
      </AuthLayout>
    );
  }

  return (
    <AuthLayout version={cfg?.version}
                title="Sign in to DSS Patcher"
                sub="Use your work e-mail and password.">
      {ssoError && <div className="banner banner-error" role="alert"><b>Sign-in failed:</b> {ssoError}</div>}
      {stepError && <div className="banner banner-warn" role="alert">{stepError}</div>}
      <PasswordForm onLogin={onLogin} onMfa={() => { setStepError(null); setMfaStep(true); }} />
      {cfg?.sso && (
        <>
          <div className="login-divider"><span>or</span></div>
          <button className="btn btn-block btn-lg" onClick={sso}>Use SSO</button>
          {cfg.require_mfa && <p className="hint">Single sign-on asks for multi-factor authentication.</p>}
        </>
      )}
    </AuthLayout>
  );
}

const TRUST_POINTS: { icon: ReactNode; title: string; text: string }[] = [
  { icon: <IconShieldCheck size={20} />, title: "Signed, verified patches", text: "Only packages that pass signature and hash checks reach your machines." },
  { icon: <IconUsers size={20} />, title: "2-person approval for every rollout", text: "One person prepares a deployment or rollback; two other people approve it before anything installs." },
  { icon: <IconOffline size={20} />, title: "Works fully offline", text: "Endpoints talk only to this server. No internet, no Windows Update fallback." },
];

/** Split sign-in layout: brand panel on the left, the form card on the right. */
export function AuthLayout({ title, sub, version, children }: { title: string; sub?: ReactNode; version?: string; children: ReactNode }) {
  return (
    <div className="login">
      <aside className="login-brand">
        <div className="login-brand-bg" aria-hidden="true" />
        <div className="login-brand-inner">
          <BrandLogo size={40} />
          <p className="login-tagline">Offline patch management for regulated networks</p>
          <ul className="login-points">
            {TRUST_POINTS.map((t) => (
              <li key={t.title}>
                <span className="login-point-icon">{t.icon}</span>
                <span><b>{t.title}</b><span className="login-point-text">{t.text}</span></span>
              </li>
            ))}
          </ul>
        </div>
      </aside>
      <main className="login-main">
        <div className="login-top"><ThemeSwitcher /></div>
        <div className="login-card">
          <div className="login-head">
            <h1 className="login-title">{title}</h1>
            {sub && <p className="login-sub">{sub}</p>}
          </div>
          {children}
        </div>
        <footer className="login-foot">
          <span className="login-zone">Isolated management zone</span>
          <span>DSS Patcher{version ? ` · version ${version}` : ""}</span>
        </footer>
      </main>
    </div>
  );
}

function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

/**
 * The built-in super admin (the vendor account the installer creates with the
 * fixed default password). While it still has that password the server also
 * wants the one-time setup code the installer printed (`pmserver setup-code`
 * on the server; security review S-1).
 *
 * No password oracle: the field is offered whenever this e-mail is typed,
 * whatever the account's state (nothing is asked of the server to decide),
 * and the server answers a missing or wrong code exactly like a wrong
 * password, so nobody learns whether the default password alone was right.
 * After the password has been changed the code is not needed and ignored.
 * An install whose built-in account has another e-mail (--admin-email)
 * opens the field with "I have a setup code"; a typed code is always sent
 * (the server ignores it for other accounts).
 */
const BUILTIN_SUPER_ADMIN_EMAIL = "superadmin@dataspacesecurity.com";

function PasswordForm({ onLogin, onMfa }: { onLogin: (me: Me) => void; onMfa: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [setupCode, setSetupCode] = useState("");
  const [wantCode, setWantCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const id = normalizeEmail(email);
    if (!id || !password || busy) return;
    setBusy(true);
    setError(null);
    const body = setupCode.trim()
      ? { email: id, password, setup_code: setupCode.trim() }
      : { email: id, password };
    try {
      const res = await api.signIn<LoginResponse>("/api/auth/login", body);
      setPassword("");
      setSetupCode("");
      if (res?.mfa_required) { onMfa(); return; }
      // Set-up still needed (mfa_enrollment_required): the session only allows enrolment; App shows the set-up screen.
      onLogin(await fetchMe());
    } catch (err) {
      setPassword("");
      if (err instanceof ApiError && err.status === 404) setError("This server does not offer e-mail and password sign-in yet.");
      else if (err instanceof ApiError && err.status === 429) setError("Too many sign-in attempts. Wait a few minutes and try again.");
      else setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <form className="login-token" onSubmit={submit} aria-busy={busy}>
      <label className="field">
        <span>E-mail</span>
        <input type="email" name="email" autoFocus autoComplete="username" autoCapitalize="none" spellCheck={false}
               inputMode="email" aria-invalid={error ? true : undefined}
               value={email} onChange={(e) => setEmail(e.target.value)} />
      </label>
      <label className="field">
        <span>Password</span>
        <PasswordInput name="password" autoComplete="current-password" aria-invalid={error ? true : undefined}
                       value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      {normalizeEmail(email) !== BUILTIN_SUPER_ADMIN_EMAIL && !wantCode && (
        <button type="button" className="btn-link small" onClick={() => setWantCode(true)}>I have a setup code (first sign-in)</button>
      )}
      {(normalizeEmail(email) === BUILTIN_SUPER_ADMIN_EMAIL || wantCode) && (
        <label className="field">
          <span>Setup code <em className="muted">first sign-in only</em></span>
          <input name="setup_code" autoComplete="one-time-code" autoCapitalize="characters" spellCheck={false}
                 placeholder="XXXX-XXXX-XXXX" maxLength={32} aria-invalid={error ? true : undefined}
                 value={setupCode} onChange={(e) => setSetupCode(e.target.value)} />
          <span className="hint">Printed by the installer (or <code>pmserver setup-code</code> on the server). Leave empty once the default password has been changed.</span>
        </label>
      )}
      <ErrorBanner error={error} />
      <button className="btn btn-primary btn-block btn-lg" disabled={busy || !email.trim() || !password}>
        {busy ? <><Spinner /> Signing in…</> : "Sign in"}
      </button>
    </form>
  );
}

/** Form to replace your own password (POST /api/auth/password). */
export function ChangePasswordForm({ me, onDone, onCancel, forced }: {
  me: Me; onDone: () => void | Promise<void>; onCancel?: () => void; forced?: boolean;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const problems = [
    ...(next ? passwordProblems(next, me.email || me.user) : []),
    ...(next && current && next === current ? ["The new password must be different from the current one."] : []),
  ];
  const mismatch = again !== "" && again !== next;
  const ok = !!current && !!next && problems.length === 0 && again === next;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ok || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/api/auth/password", { current, new: next });
      setCurrent(""); setNext(""); setAgain("");
      await onDone();
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <form className="login-token" onSubmit={submit}>
      <label className="field">
        <span>{forced ? "Temporary password" : "Current password"}</span>
        <PasswordInput autoFocus autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
      </label>
      <label className="field">
        <span>New password <em className="muted">at least 12 characters</em></span>
        <PasswordInput autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
      </label>
      <label className="field">
        <span>New password again</span>
        <PasswordInput autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
      </label>
      {(problems.length > 0 || mismatch) && (
        <ul className="problems">
          {problems.map((p) => <li key={p}>{p}</li>)}
          {mismatch && <li>The two new passwords are not the same.</li>}
        </ul>
      )}
      <ErrorBanner error={error} />
      <div className="form-actions">
        {onCancel && <button type="button" className="btn" onClick={onCancel} disabled={busy}>Cancel</button>}
        <button className="btn btn-primary" disabled={!ok || busy}>{busy ? "Saving…" : "Change password"}</button>
      </div>
    </form>
  );
}

/** Full-screen: the server allows nothing else until the temporary password is replaced. */
export function ForcedPasswordChange({ me, onDone, onSignOut }: { me: Me; onDone: () => Promise<void>; onSignOut: () => void }) {
  return (
    <AuthLayout title="Change your password">
      <p className="login-sub">
        Hello <b>{me.display_name || me.user}</b>. You signed in with a temporary password. Choose your own password to continue.
      </p>
      <ChangePasswordForm me={me} onDone={onDone} forced />
      <p className="login-alt"><button type="button" className="btn-link" onClick={onSignOut}>Sign out</button></p>
    </AuthLayout>
  );
}
