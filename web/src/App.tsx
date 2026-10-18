import { useEffect, useState, type ComponentType } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { api, ApiError, clearToken, PASSWORD_CHANGE_EVENT, UNAUTHORIZED_EVENT } from "./api";
import { AuthContext, hasRole, shouldRecommendPasswordChange } from "./auth";
import type { Alert, LogoutResponse, Me } from "./types";
import { ChangePasswordForm, fetchMe, ForcedPasswordChange, SignIn } from "./components/SignIn";
import { Modal, RoleBadge } from "./components/ui";
import { ThemeSwitcher } from "./components/ThemeSwitcher";
import { useThemePref } from "./theme";
import {
  BrandLogo, BrandMark, IconDeployments, IconEndpoints, IconKey, IconLogout, IconOverview, IconPatches, IconReports, IconSettings,
} from "./components/icons";
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
  useThemePref(); // keep the theme in step with the OS setting and other tabs
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
    // Any call refused with password_change_required: show the change screen.
    const onPwChange = () => setMe((m) => (m ? { ...m, must_change_password: true } : m));
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauth);
    window.addEventListener(PASSWORD_CHANGE_EVENT, onPwChange);
    // Always ask: a stored bearer token or a session cookie (password or SSO) may authenticate us.
    fetchMe()
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecking(false));
    return () => {
      window.removeEventListener(UNAUTHORIZED_EVENT, onUnauth);
      window.removeEventListener(PASSWORD_CHANGE_EVENT, onPwChange);
    };
  }, []);

  const signOut = async () => {
    let endSession: string | undefined;
    try {
      if (me?.auth === "sso") {
        const r = await api.post<LogoutResponse>("/auth/logout", {});
        endSession = r?.end_session_url;
      } else {
        await api.post("/api/auth/logout", {}).catch(async (e) => {
          // Older servers only have the SSO logout, which also ends cookie sessions.
          if (e instanceof ApiError && e.status === 404) await api.post("/auth/logout", {});
          else throw e;
        });
      }
    } catch {
      /* the session may already be gone; sign out locally regardless */
    }
    clearToken();
    setMe(null);
    if (endSession) window.location.assign(endSession);
  };

  if (checking) {
    return (
      <div className="boot" role="status">
        <BrandMark size={40} />
        <span>Loading DSS Patcher…</span>
      </div>
    );
  }
  if (!me) {
    return <SignIn onLogin={(m) => { setLoginError(null); setMe(m); }} ssoError={loginError} />;
  }
  if (me.must_change_password) {
    return <ForcedPasswordChange me={me} onSignOut={() => void signOut()} onDone={async () => setMe(await fetchMe())} />;
  }

  return (
    <AuthContext.Provider value={me}>
      <Shell me={me} onSignOut={() => void signOut()} />
    </AuthContext.Provider>
  );
}

const PW_BANNER_KEY = "offpatch.pw-banner-hidden";

const AUTH_BADGE: Record<Me["auth"], { label: string; title: string; cls: string }> = {
  password: { label: "password", title: "Signed in with username and password", cls: "" },
  sso: { label: "SSO", title: "Signed in through single sign-on", cls: "" },
  token: { label: "token", title: "Signed in with the break-glass / automation token", cls: "auth-src-token" },
};

function Shell({ me, onSignOut }: { me: Me; onSignOut: () => void }) {
  const isAdmin = hasRole(me, "admin");
  const isSuper = hasRole(me, "super_admin");
  // Settings: Admins manage the bank's users; only the vendor (super admin) sees server settings and agent versions.
  const settingsHome = isSuper ? paths.server : paths.users;
  const nav = NAV
    .filter((n) => n.label !== "Settings" || isAdmin)
    .map((n) => (n.label === "Settings" ? { ...n, to: settingsHome } : n));
  const [pwBannerHidden, setPwBannerHidden] = useState(() => sessionStorage.getItem(PW_BANNER_KEY) === "1");
  const [changingPw, setChangingPw] = useState(false);
  const badge = AUTH_BADGE[me.auth];
  const alerts = useLoad(() => api.get<Alert[]>("/api/alerts?open=1"), [], 15000);
  const open = (alerts.data ?? []).filter(isOpenAlert);
  const openAlerts = open.length;
  const critical = open.some((a) => a.severity === "critical");
  const { pathname } = useLocation();
  const activeLabel = nav.find((n) => n.match(pathname))?.label;
  useEffect(() => {
    document.title = activeLabel ? `${activeLabel} · DSS Patcher` : "DSS Patcher";
  }, [activeLabel]);

  return (
    <AlertsRefreshContext.Provider value={() => void alerts.reload()}>
      <div className="shell">
        <aside className="nav">
          <Link to={paths.overview} className="brand" aria-label="DSS Patcher, go to Overview">
            <BrandLogo size={30} sub="Offline patch management" />
          </Link>
          <nav aria-label="Main">
            {nav.map((n) => {
              const active = n.match(pathname);
              return (
                <Link key={n.to} to={n.to} className={active ? "active" : undefined} aria-current={active ? "page" : undefined}>
                  <n.icon size={18} className="nav-icon" />
                  <span className="nav-label">{n.label}</span>
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
              <ThemeSwitcher />
              <span className="topbar-sep" aria-hidden="true" />
              <span className="user" title={me.display_name ? me.user : undefined}>{me.display_name || me.user}</span>
              <RoleBadge role={me.role} />
              <span className={`auth-src ${badge.cls} ${me.auth === "sso" && me.mfa ? "auth-src-mfa" : ""}`} title={badge.title}>
                {me.auth === "sso" && me.mfa ? "SSO · MFA" : badge.label}
              </span>
              {me.auth === "password" && (
                <button className="btn btn-sm btn-ghost" onClick={() => setChangingPw(true)}><IconKey size={14} /> Change password</button>
              )}
              <button className="btn btn-sm btn-ghost" onClick={onSignOut}><IconLogout size={14} /> Sign out</button>
            </div>
          </header>
          <main className="content">
            {shouldRecommendPasswordChange(me) && !pwBannerHidden && (
              <div className="banner banner-warn">
                <b>You are using the built-in super admin password from the installation.</b> We recommend changing it now.{" "}
                <button className="btn btn-sm btn-primary" onClick={() => setChangingPw(true)}>Change password</button>{" "}
                <button className="btn btn-sm" onClick={() => { sessionStorage.setItem(PW_BANNER_KEY, "1"); setPwBannerHidden(true); }}>Later</button>
              </div>
            )}
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
                <Route path="/endpoints/add" element={hasRole(me, "user") ? <AgentSetupPage /> : <Navigate to={paths.endpoints} replace />} />
              </Route>
              <Route path="/endpoints/:id" element={<EndpointDetailPage />} />
              <Route element={<ReportsArea />}>
                <Route path="/reports" element={<Reports />} />
                <Route path="/reports/exceptions" element={<Exceptions />} />
                <Route path="/reports/audit" element={<Audit />} />
              </Route>
              {isAdmin && (
                <Route element={<SettingsArea isAdmin={isAdmin} isSuper={isSuper} />}>
                  <Route path="/settings/server" element={isSuper ? <ServerPage /> : <Navigate to={settingsHome} replace />} />
                  <Route path="/settings/agents" element={isSuper ? <Catalog agents key="agents" /> : <Navigate to={settingsHome} replace />} />
                  <Route path="/settings/agents/:packageId" element={isSuper ? <Catalog agents key="agents" /> : <Navigate to={settingsHome} replace />} />
                  <Route path="/settings/users" element={<Users />} />
                </Route>
              )}

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
              <Route path="/settings" element={<Moved to={settingsHome} />} />
              <Route path="/server" element={<Moved to={paths.server} />} />
              <Route path="/users" element={<Moved to={paths.users} />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
      {changingPw && (
        <Modal title="Change your password" onClose={() => setChangingPw(false)}>
          <ChangePasswordForm me={me} onCancel={() => setChangingPw(false)} onDone={() => { setChangingPw(false); setPwBannerHidden(true); sessionStorage.setItem(PW_BANNER_KEY, "1"); }} />
        </Modal>
      )}
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
type NavIcon = ComponentType<{ size?: number; className?: string }>;
const NAV: { to: string; label: string; icon: NavIcon; match: (p: string) => boolean }[] = [
  { to: paths.overview, label: "Overview", icon: IconOverview, match: (p) => p === "/" || p.startsWith("/alerts") },
  { to: paths.needed(), label: "Patches", icon: IconPatches, match: (p) => p.startsWith("/patches") },
  { to: paths.deployments, label: "Deployments", icon: IconDeployments, match: (p) => p.startsWith("/deployments") },
  { to: paths.endpoints, label: "Endpoints", icon: IconEndpoints, match: (p) => p.startsWith("/endpoints") },
  { to: paths.reports, label: "Reports", icon: IconReports, match: (p) => p.startsWith("/reports") },
  { to: paths.server, label: "Settings", icon: IconSettings, match: (p) => p.startsWith("/settings") },
];
