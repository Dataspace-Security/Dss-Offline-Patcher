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
  /** Updates: what the fleet needs and how each update stands ("view=all" = everything, not just what needs action). */
  updates: (view?: "all") => (view ? `/patches/updates?view=${view}` : "/patches/updates"),
  catalog: (packageId?: string | null) => (packageId ? `/patches/catalog/${enc(packageId)}` : "/patches/catalog"),
  /** Downloads in the acquisition zone + bundles that arrived through the transfer. */
  transfers: "/patches/transfers",
  // Deployments
  deployments: "/deployments",
  deployment: (id: string) => `/deployments/${enc(id)}`,
  newDeployment: "/deployments/new",
  windows: "/deployments/windows",
  exceptions: "/deployments/exceptions",
  // Endpoints
  endpoints: "/endpoints",
  endpoint: (id: string) => `/endpoints/${enc(id)}`,
  addEndpoints: "/endpoints/add",
  // Reports
  reports: "/reports",
  audit: (filter?: Record<string, string>) => {
    const q = filter ? new URLSearchParams(filter).toString() : "";
    return q ? `/reports/audit?${q}` : "/reports/audit";
  },
  // Settings
  server: "/settings/server",
  users: "/settings/users",
};
