import { createContext, useContext } from "react";
import type { AuthKind, Deployment, Me, Policy, Role } from "./types";

// Roles (rank): viewer 1 · user 2 (bank) · admin 3 (bank) · super_admin 4 (vendor).
const RANK: Record<Role, number> = { viewer: 1, user: 2, admin: 3, super_admin: 4 };

/** Roles are viewer, user, admin and super_admin; unknown names read as viewer. */
export function normalizeRole(r: string | null | undefined): Role {
  switch ((r ?? "").toLowerCase()) {
    case "super_admin": case "superadmin": return "super_admin";
    case "admin": return "admin";
    case "user": return "user";
    default: return "viewer";
  }
}

export const ROLE_LABELS: Record<Role, string> = {
  super_admin: "Super admin (vendor)",
  admin: "Admin",
  user: "User",
  viewer: "Viewer",
};

/** What each role can do, in plain words (Users screen). */
export const ROLE_HELP: Record<Role, string> = {
  viewer: "Can look at everything. Cannot change anything.",
  user: "Can import, plan deployments and rollbacks, and approve other people's deployments and packages.",
  admin: "Everything a User can do, plus manage the bank's users, exceptions and revoking packages.",
  super_admin: "Vendor support: everything, including server settings, agent versions and all users.",
};

export function roleLabel(r: string | null | undefined): string {
  return ROLE_LABELS[normalizeRole(r)];
}

export function roleRank(r: string | null | undefined): number {
  return RANK[normalizeRole(r)];
}

/** /api/me: role normalised; `auth` is password or SSO (older servers send `source`). */
export function normalizeMe(raw: Partial<Me> & { role?: string }): Me {
  const auth: AuthKind = raw.auth === "password" || raw.auth === "sso"
    ? raw.auth
    : raw.source === "sso" ? "sso" : "password";
  return {
    ...raw,
    user: raw.user ?? "",
    role: normalizeRole(raw.role),
    auth,
    must_change_password: !!raw.must_change_password,
  };
}

export function hasRole(me: Me | null, min: Role): boolean {
  if (!me) return false;
  return roleRank(me.role) >= RANK[min];
}

export const AuthContext = createContext<Me | null>(null);

export function useMe(): Me | null {
  return useContext(AuthContext);
}

export function useCan(min: Role): boolean {
  return hasRole(useMe(), min);
}

/** The server records people as "<name>", "<email>" or "user:<…>". */
export function samePerson(recorded: string | null | undefined, me: Me | null): boolean {
  if (!recorded || !me) return false;
  const r = recorded.replace(/^user:/, "").toLowerCase();
  return [me.user, me.email].some((id) => !!id && id.toLowerCase() === r);
}

/**
 * The built-in super admin (vendor) still uses the password the installer
 * printed: recommend changing it. Assumed signals: `builtin`, or an empty
 * `password_changed_at` on a password-signed-in super admin.
 */
export function shouldRecommendPasswordChange(me: Me | null): boolean {
  if (!me || me.auth !== "password" || me.role !== "super_admin") return false;
  if (me.password_changed_at) return false;
  return me.builtin !== false;
}

/** Display name of a recorded actor: "user:alice" → "alice". */
export function personName(recorded: string | null | undefined): string {
  return (recorded ?? "").replace(/^user:/, "");
}

/** Bank approvers of deployments and rollbacks: User or Admin (not the vendor, not viewers). */
export function isBankApprover(me: Me | null): boolean {
  return !!me && (me.role === "user" || me.role === "admin");
}

/** Approvals every deployment / rollback needs before it starts (policy, default 2). */
export function deploymentApprovalsRequired(policy: Policy | null | undefined, d?: Pick<Deployment, "approvals_required"> | null): number {
  return d?.approvals_required || policy?.deployment_approvals || 2;
}

export type DeploymentApprovalStatus = {
  approvals: { by: string; at: string; reason: string }[];
  required: number;
  mine: boolean;        // I created it
  iApproved: boolean;
  canApprove: boolean;  // eligible to approve / reject now
  /** Why I cannot approve (shown instead of the buttons). "" when I can. */
  whyNot: string;
};

export function deploymentApprovalStatus(d: Deployment, me: Me | null, policy?: Policy | null): DeploymentApprovalStatus {
  const approvals = d.approvals ?? [];
  const required = deploymentApprovalsRequired(policy, d);
  const mine = samePerson(d.created_by, me);
  const iApproved = approvals.some((a) => samePerson(a.by, me));
  const pending = d.state === "pending_approval";
  let whyNot = "";
  if (!pending) whyNot = "It is not waiting for approval.";
  else if (mine) whyNot = `You created this — ${required} other ${required === 1 ? "person" : "people"} must approve.`;
  else if (iApproved) whyNot = "You already approved this. Waiting for someone else.";
  else if (me?.role === "super_admin") whyNot = "Only the bank's Admins and Users approve deployments.";
  else if (!isBankApprover(me)) whyNot = "Only Admins and Users can approve deployments.";
  return { approvals, required, mine, iApproved, canApprove: pending && whyNot === "", whyNot };
}

/** "Needs 2 approvals before it starts" (confirmation text for Patch this and rollbacks). */
export function needsApprovalsText(n: number): string {
  return `Needs ${n} approval${n === 1 ? "" : "s"} before it starts`;
}

/** "2 other people (Users or Admins, not you) must approve it." */
export function othersMustApprove(n: number): string {
  return `${n} other ${n === 1 ? "person" : "people"} (Users or Admins, not you) must approve it.`;
}
