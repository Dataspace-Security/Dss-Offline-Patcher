import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { api, ApiError, clearToken, errMsg, setToken } from "../api";
import { normalizeMe } from "../auth";
import { normalizeEmail, passwordProblems } from "../passwords";
import type { AuthConfig, Me } from "../types";
import { ErrorBanner } from "./ui";
import { BrandLogo, IconOffline, IconShieldCheck, IconUsers } from "./icons";
import { PasswordInput } from "./PasswordInput";
import { ThemeSwitcher } from "./ThemeSwitcher";

/** Ask the server who is signed in (cookie session or the stored token). */
export async function fetchMe(token?: string): Promise<Me> {
  return normalizeMe(await api.get<Me>("/api/me", token));
}

/**
 * Sign-in page: e-mail + password, and "Use SSO" when the server has single
 * sign-on. The break-glass token form is not linked: only /login?token=1
 * shows it.
 */
export function SignIn({ onLogin, ssoError }: { onLogin: (me: Me) => void; ssoError: string | null }) {
  const location = useLocation();
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const tokenMode = new URLSearchParams(location.search).get("token") === "1";

  useEffect(() => {
    api.get<AuthConfig>("/auth/config")
      .then(setCfg)
      .catch(() => setCfg({ sso: false, static_tokens: false, require_mfa: false }));
  }, []);

  const returnPath = (() => {
    if (location.pathname === "/login") return "/";
    const sp = new URLSearchParams(location.search);
    sp.delete("login_error");
    sp.delete("token");
    const q = sp.toString();
    return `${location.pathname}${q ? `?${q}` : ""}`;
  })();
  const sso = () => window.location.assign(`/auth/login?return=${encodeURIComponent(returnPath)}`);

  return (
    <AuthLayout version={cfg?.version}
                title={tokenMode ? "Emergency sign-in" : "Sign in to DSS Patcher"}
                sub={tokenMode ? "Use the break-glass token from the installation." : "Use your work e-mail and password."}>
      {ssoError && <div className="banner banner-error" role="alert"><b>Sign-in failed:</b> {ssoError}</div>}
      {tokenMode ? <TokenForm onLogin={onLogin} /> : (
        <>
          <PasswordForm onLogin={onLogin} />
          {cfg?.sso && (
            <>
              <div className="login-divider"><span>or</span></div>
              <button className="btn btn-block btn-lg" onClick={sso}>Use SSO</button>
              {cfg.require_mfa && <p className="hint">Single sign-on asks for multi-factor authentication.</p>}
            </>
          )}
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
function AuthLayout({ title, sub, version, children }: { title: string; sub?: ReactNode; version?: string; children: ReactNode }) {
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

function PasswordForm({ onLogin }: { onLogin: (me: Me) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const id = normalizeEmail(email);
    if (!id || !password || busy) return;
    setBusy(true);
    setError(null);
    try {
      // A stored token would win over the new session cookie: drop it.
      clearToken();
      await api.signIn("/api/auth/login", { email: id, password });
      setPassword("");
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
      <ErrorBanner error={error} />
      <button className="btn btn-primary btn-block btn-lg" disabled={busy || !email.trim() || !password}>
        {busy ? <><Spinner /> Signing in…</> : "Sign in"}
      </button>
    </form>
  );
}

function TokenForm({ onLogin }: { onLogin: (me: Me) => void }) {
  const [token, setTok] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const t = token.trim();
    if (!t || busy) return;
    setBusy(true);
    setError(null);
    try {
      const me = await fetchMe(t);
      setToken(t);
      onLogin(me);
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <form className="login-token" onSubmit={submit} aria-busy={busy}>
      <label className="field">
        <span>Token</span>
        <PasswordInput what="token" autoFocus autoComplete="off" spellCheck={false} value={token}
                       onChange={(e) => setTok(e.target.value)} className="mono" />
      </label>
      <ErrorBanner error={error} />
      <button className="btn btn-primary btn-block btn-lg" disabled={busy || !token.trim()}>
        {busy ? <><Spinner /> Checking…</> : "Sign in with token"}
      </button>
      <p className="hint">The token is kept in this browser tab only. <Link to="/">Sign in with e-mail instead</Link></p>
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
