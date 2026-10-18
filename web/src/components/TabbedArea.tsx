import type { ReactNode } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { EmbeddedHeader, PageHeader } from "./ui";

export type AreaTab = {
  to: string;
  label: string;
  /** Active only on exactly this address (not on deeper ones). */
  end?: boolean;
  badge?: number;
  badgeTitle?: string;
  /** Amber badge instead of red. */
  warn?: boolean;
  hidden?: boolean;
};

/**
 * One area of the console (Patches, Deployments, …): a shared page header,
 * a row of URL tabs (refresh and Back keep the tab) and the active tab's page
 * below. Pages inside drop their own title (EmbeddedHeader) but keep their
 * description and controls. Used as a layout route: the tab pages are its
 * child routes and render in the <Outlet />.
 */
export function TabbedArea({ title, sub, tabs, top }: { title: string; sub?: ReactNode; tabs: AreaTab[]; top?: ReactNode }) {
  return (
    <>
      <PageHeader title={title} sub={sub} />
      {top}
      <nav className="tabs" aria-label={`${title} sections`}>
        {tabs.filter((t) => !t.hidden).map((t) => (
          <NavLink key={t.to} to={t.to} end={t.end} className={({ isActive }) => `tab tab-link ${isActive ? "tab-on" : ""}`}>
            {t.label}
            {!!t.badge && <span className={`nav-badge ${t.warn ? "nav-badge-warn" : ""}`} title={t.badgeTitle}>{t.badge}</span>}
          </NavLink>
        ))}
      </nav>
      <EmbeddedHeader.Provider value={true}>
        <Outlet />
      </EmbeddedHeader.Provider>
    </>
  );
}
