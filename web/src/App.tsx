import { useEffect, useState, type FormEvent } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { api, clearToken, errMsg, setToken, UNAUTHORIZED_EVENT } from "./api";
import { AuthContext, hasRole } from "./auth";
import type { Alert, AuthConfig, LogoutResponse, Me } from "./types";
import { useLoad } from "./util";
import Overview from "./pages/Overview";
import { DeploymentList, NewDeploymentPage } from "./pages/Deployments";
import DeploymentDetailPage from "./pages/DeploymentDetail";
import Endpoints from "./pages/Endpoints";
import EndpointDetailPage from "./pages/EndpointDetail";
import Exceptions from "./pages/Exceptions";
import Audit from "./pages/Audit";
import { paths } from "./paths";
import { DeploymentsArea, EndpointsArea, OverviewArea, PatchesArea, ReportsArea, SettingsArea } from "./pages/Areas";
import PatchUpdates from "./pages/PatchUpdates";
import Catalog from "./pages/Catalog";
import Imports from "./pages/Imports";
import Library from "./pages/Library";
import ServerPage from "./pages/Server";
import AgentSetupPage from "./pages/AgentSetup";
import Users from "./pages/Users";
import MaintenanceWindows from "./pages/MaintenanceWindows";
import Alerts, { isOpenAlert } from "./pages/Alerts";
import Reports from "./pages/Reports";
import { AlertsRefreshContext } from "./alertsContext";

export default function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(true);
  // An SSO failure redirects to /?login_error=<message>. Capture it once, then
  // strip it from the URL so a reload doesn't show it again.
  const [loginError, setLoginError] = useState<string | null>(
    () => new URLSearchParams(window.location.search).get("login_error"));

  useEffect(() => {
    const sp = new URLSearchParams(location.search);
    if (sp.has("login_error")) {
      sp.delete("login_error");
      const s = sp.toString();
      navigate({ pathname: location.pathname, search: s ? `?${s}` : "" }, { replace: true });
    }
  }, [location.search]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onUnauth = () => setMe(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauth);
    // Always ask: a stored bearer token or an SSO session cookie may authenticate us.
    api.get<Me>("/api/me")
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecking(false));
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauth);
  }, []);

  if (checking) return <div className="boot">Loading…</div>;
  if (!me) {
    return <Login onLogin={(m) => { setLoginError(null); setMe(m); }} ssoError={loginError} />;
  }

  const signOut = async () => {
    let endSession: string | undefined;
    try {
      const r = await api.post<LogoutResponse>("/auth/logout", {});
      endSession = r?.end_session_url;
    } catch {
      /* the session may already be gone; sign out locally regardless */
    }
    clearToken();
    setMe(null);
    if (endSession) window.location.assign(endSession);
  };

  return (
    <AuthContext.Provider value={me}>
      <Shell me={me} onSignOut={() => void signOut()} />
    </AuthContext.Provider>
  );
}

function Shell({ me, onSignOut }: { me: Me; onSignOut: () => void }) {
  const isAdmin = hasRole(me, "admin");
  const alerts = useLoad(() => api.get<Alert[]>("/api/alerts?open=1"), [], 15000);
  const open = (alerts.data ?? []).filter(isOpenAlert);
  const openAlerts = open.length;
  const critical = open.some((a) => a.severity === "critical");
  const { pathname } = useLocation();

  return (
    <AlertsRefreshContext.Provider value={() => void alerts.reload()}>
      <div className="shell">
        <aside className="nav">
          <div className="brand">
            <span className="brand-mark">◆</span> offpatch
            <div className="brand-sub">offline patch management</div>
          </div>
          <nav aria-label="Main">
            {NAV.map((n) => {
              const active = n.match(pathname);
              return (
                <Link key={n.to} to={n.to} className={active ? "active" : undefined} aria-current={active ? "page" : undefined}>
                  {n.label}
                  {n.to === paths.overview && openAlerts > 0 && (
                    <span className={`nav-badge ${critical ? "" : "nav-badge-warn"}`} title={`${openAlerts} open alert(s)`}>{openAlerts}</span>
                  )}
                </Link>
              );
            })}
          </nav>
        </aside>
        <div className="main">
          <header className="topbar">
            <div className="topbar-zone">Isolated management zone</div>
            <div className="topbar-user">
              <span className="user">{me.user}</span>
              <span className={`role role-${me.role}`}>{me.role}</span>
              {me.source === "sso" ? (
                <span className={`auth-src ${me.mfa ? "auth-src-mfa" : ""}`}
                      title={me.mfa ? "Signed in through the identity provider with MFA" : "Signed in through the identity provider (no MFA asserted)"}>
                  {me.mfa ? "SSO · MFA" : "SSO"}
                </span>
              ) : (
                <span className="auth-src auth-src-token" title="Authenticated with a static break-glass / automation token">token</span>
              )}
              <button className="btn btn-sm" onClick={onSignOut}>Sign out</button>
            </div>
          </header>
          <main className="content">
            <Routes>
              {/* Six areas; each is a layout route whose children are its tabs. */}
              <Route element={<OverviewArea openAlerts={openAlerts} critical={critical} />}>
                <Route path="/" element={<Overview />} />
                <Route path="/alerts" element={<Alerts />} />
              </Route>
              <Route element={<PatchesArea />}>
                <Route path="/patches/needed" element={<PatchUpdates />} />
                <Route path="/patches/library" element={<Library />} />
                <Route path="/patches/catalog" element={<Catalog />} />
                <Route path="/patches/catalog/:packageId" element={<Catalog />} />
                <Route path="/patches/imports" element={<Imports />} />
              </Route>
              <Route element={<DeploymentsArea />}>
                <Route path="/deployments" element={<DeploymentList />} />
                <Route path="/deployments/windows" element={<MaintenanceWindows />} />
              </Route>
              <Route path="/deployments/new" element={<NewDeploymentPage />} />
              <Route path="/deployments/:id" element={<DeploymentDetailPage />} />
              <Route element={<EndpointsArea />}>
                <Route path="/endpoints" element={<Endpoints />} />
                <Route path="/endpoints/add" element={<AgentSetupPage />} />
              </Route>
              <Route path="/endpoints/:id" element={<EndpointDetailPage />} />
              <Route element={<ReportsArea />}>
                <Route path="/reports" element={<Reports />} />
                <Route path="/reports/exceptions" element={<Exceptions />} />
                <Route path="/reports/audit" element={<Audit />} />
              </Route>
              <Route element={<SettingsArea isAdmin={isAdmin} />}>
                <Route path="/settings/server" element={<ServerPage />} />
                <Route path="/settings/agents" element={<Catalog agents key="agents" />} />
                <Route path="/settings/agents/:packageId" element={<Catalog agents key="agents" />} />
                <Route path="/settings/users" element={isAdmin ? <Users /> : <Navigate to={paths.server} replace />} />
              </Route>

              {/* Old addresses (bookmarks, alert e-mails, other links) keep working, query string included. */}
              <Route path="/patches" element={<Moved to={paths.needed()} />} />
              <Route path="/patches/updates" element={<Moved to={paths.needed()} />} />
              <Route path="/patches/transfers" element={<Moved to={paths.imports} />} />
              <Route path="/patches/status" element={<Moved to={paths.needed()} add={{ view: "all" }} />} />
              <Route path="/patches/downloads" element={<Moved to={paths.imports} />} />
              <Route path="/patches/received" element={<Moved to={paths.imports} />} />
              <Route path="/deployments/exceptions" element={<Moved to={paths.exceptions} />} />
              <Route path="/patches/*" element={<Moved to={paths.needed()} />} />
              <Route path="/updates" element={<Moved to={paths.needed()} />} />
              <Route path="/catalog" element={<Moved to={paths.catalog()} />} />
              <Route path="/catalog/:packageId" element={<MovedPackage />} />
              <Route path="/acquisition" element={<Moved to={paths.imports} />} />
              <Route path="/intake" element={<Moved to={paths.imports} />} />
              <Route path="/windows" element={<Moved to={paths.windows} />} />
              <Route path="/exceptions" element={<Moved to={paths.exceptions} />} />
              <Route path="/agent-setup" element={<Moved to={paths.addEndpoints} />} />
              <Route path="/audit" element={<Moved to={paths.audit()} />} />
              <Route path="/settings" element={<Moved to={paths.server} />} />
              <Route path="/server" element={<Moved to={paths.server} />} />
              <Route path="/users" element={<Moved to={paths.users} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </AlertsRefreshContext.Provider>
  );
}

/**
 * Redirect from an old address, keeping its query string (e.g.
 * ?state=quarantined) and hash; `to` may carry its own query and `add`
 * sets further parameters (the old address's own values win).
 */
function Moved({ to, add }: { to: string; add?: Record<string, string> }) {
  const { search, hash } = useLocation();
  const [pathname, toQuery = ""] = to.split("?");
  const merged = new URLSearchParams(toQuery);
  for (const [k, v] of Object.entries(add ?? {})) merged.set(k, v);
  new URLSearchParams(search).forEach((v, k) => merged.set(k, v));
  const q = merged.toString();
  return <Navigate to={{ pathname, search: q ? `?${q}` : "", hash }} replace />;
}

function MovedPackage() {
  const { packageId } = useParams();
  return <Moved to={paths.catalog(packageId)} />;
}

/** Sidebar: one entry per area; active on any of the area's addresses. */
const NAV: { to: string; label: string; match: (p: string) => boolean }[] = [
  { to: paths.overview, label: "Overview", match: (p) => p === "/" || p.startsWith("/alerts") },
  { to: paths.needed(), label: "Patches", match: (p) => p.startsWith("/patches") },
  { to: paths.deployments, label: "Deployments", match: (p) => p.startsWith("/deployments") },
  { to: paths.endpoints, label: "Endpoints", match: (p) => p.startsWith("/endpoints") },
  { to: paths.reports, label: "Reports", match: (p) => p.startsWith("/reports") },
  { to: paths.server, label: "Settings", match: (p) => p.startsWith("/settings") },
];

function Login({ onLogin, ssoError }: { onLogin: (me: Me) => void; ssoError: string | null }) {
  const location = useLocation();
  const [cfg, setCfg] = useState<AuthConfig | null>(null);
  const [cfgError, setCfgError] = useState<string | null>(null);
  const [token, setTok] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.get<AuthConfig>("/auth/config")
      .then(setCfg)
      .catch((e) => {
        // Older servers have no /auth/config: fall back to the token form.
        setCfgError(errMsg(e));
        setCfg({ sso: false, static_tokens: true, require_mfa: false });
      });
  }, []);

  const returnPath = (() => {
    const sp = new URLSearchParams(location.search);
    sp.delete("login_error");
    const s = sp.toString();
    return `${location.pathname}${s ? `?${s}` : ""}`;
  })();

  const sso = () => {
    window.location.assign(`/auth/login?return=${encodeURIComponent(returnPath)}`);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const t = token.trim();
    if (!t) return;
    setBusy(true);
    setError(null);
    try {
      const me = await api.get<Me>("/api/me", t);
      setToken(t);
      onLogin(me);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <div className="login-card">
        <div className="brand brand-login"><span className="brand-mark">◆</span> offpatch</div>
        {ssoError && <div className="banner banner-error"><b>Sign-in failed:</b> {ssoError}</div>}
        {!cfg && !cfgError && <p className="muted">Loading sign-in options…</p>}
        {cfg?.sso && (
          <>
            <p className="muted">
              Sign in to the admin console with your organisation account.
              {cfg.require_mfa && " Multi-factor authentication is required."}
            </p>
            <button className="btn btn-primary btn-block" onClick={sso} autoFocus>Sign in with single sign-on</button>
          </>
        )}
        {cfg && cfg.static_tokens && (
          <form className="login-token" onSubmit={submit}>
            {cfg.sso ? (
              <div className="login-divider"><span>or</span></div>
            ) : (
              <p className="muted">Sign in to the admin console with an admin bearer token.</p>
            )}
            <label className="field">
              <span>Break-glass / automation token</span>
              <input
                type="password"
                autoFocus={!cfg.sso}
                autoComplete="off"
                value={token}
                onChange={(e) => setTok(e.target.value)}
                className="mono"
              />
            </label>
            {error && <div className="banner banner-error">{error}</div>}
            <button className={`btn btn-block ${cfg.sso ? "" : "btn-primary"}`} disabled={busy || !token.trim()}>
              {busy ? "Checking…" : "Sign in with token"}
            </button>
            <p className="hint">The token is kept in this browser tab's session storage only.</p>
          </form>
        )}
        {cfg && !cfg.sso && !cfg.static_tokens && (
          <div className="banner banner-warn">No sign-in method is configured on this server. Ask an administrator.</div>
        )}
      </div>
    </div>
  );
}
