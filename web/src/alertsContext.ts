import { createContext, useContext } from "react";

/** Lets pages (e.g. Alerts after an acknowledge) refresh the nav badge immediately. */
export const AlertsRefreshContext = createContext<() => void>(() => {});

export function useRefreshAlerts(): () => void {
  return useContext(AlertsRefreshContext);
}
