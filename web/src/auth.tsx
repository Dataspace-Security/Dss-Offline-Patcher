import { createContext, useContext } from "react";
import type { Me, Role } from "./types";

const RANK: Record<Role, number> = { viewer: 0, operator: 1, approver: 2, admin: 3 };

export function hasRole(me: Me | null, min: Role): boolean {
  if (!me) return false;
  const r = RANK[me.role];
  return r !== undefined && r >= RANK[min];
}

export const AuthContext = createContext<Me | null>(null);

export function useMe(): Me | null {
  return useContext(AuthContext);
}

export function useCan(min: Role): boolean {
  return hasRole(useMe(), min);
}
