import { enc } from "./api";

/**
 * Console addresses. Six areas (Overview, Patches, Deployments, Endpoints,
 * Reports, Settings), each a set of URL tabs. Link through these helpers
 * rather than writing paths by hand; old addresses redirect (see App.tsx).
 */
export const paths = {
  // Overview
  overview: "/",
  alerts: "/alerts",
  // Patches
  /** Needed: what the fleet needs and how each update stands ("view=all" = everything, not just what needs action). */
  needed: (view?: "all") => (view ? `/patches/needed?view=${view}` : "/patches/needed"),
  /** Library: everything that could be imported (untrusted index from update intelligence). */
  library: (q?: string) => (q ? `/patches/library?q=${enc(q)}` : "/patches/library"),
  catalog: (packageId?: string | null) => (packageId ? `/patches/catalog/${enc(packageId)}` : "/patches/catalog"),
  /** Imports: what was asked for, what the acquisition zone downloaded, and what arrived through the transfer. */
  imports: "/patches/imports",
  // Deployments
  deployments: "/deployments",
  deployment: (id: string) => `/deployments/${enc(id)}`,
  newDeployment: "/deployments/new",
  windows: "/deployments/windows",
  // Endpoints
  endpoints: "/endpoints",
  endpoint: (id: string) => `/endpoints/${enc(id)}`,
  addEndpoints: "/endpoints/add",
  // Reports
  reports: "/reports",
  /** Auditor report for a period (template sections 1–9) and its signed evidence package. */
  complianceReport: "/reports/compliance",
  /** Organization profile behind the auditor report (admin edits, everyone reads). */
  reportProfile: "/reports/profile",
  audit: (filter?: Record<string, string>) => {
    const q = filter ? new URLSearchParams(filter).toString() : "";
    return q ? `/reports/audit?${q}` : "/reports/audit";
  },
  exceptions: "/reports/exceptions",
  // Settings
  server: "/settings/server",
  users: "/settings/users",
  /** Agent versions: offpatch agent packages (kept out of the Catalog). */
  agentVersions: (packageId?: string | null) => (packageId ? `/settings/agents/${enc(packageId)}` : "/settings/agents"),
};
