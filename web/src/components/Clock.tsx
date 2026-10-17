import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

const ClockContext = createContext<number | null>(null);

/**
 * One shared ticking clock. Only components that call useClock() re-render on
 * each tick: the provider's children are created by the parent, so React
 * skips them unless they read the context. Keeps a 1 s clock from
 * re-rendering a whole page (e.g. a large target table).
 */
export function ClockProvider({ ms = 1000, children }: { ms?: number; children: ReactNode }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(t);
  }, [ms]);
  return <ClockContext.Provider value={now}>{children}</ClockContext.Provider>;
}

/** The current time from the nearest ClockProvider (Date.now() without one). */
export function useClock(): number {
  return useContext(ClockContext) ?? Date.now();
}
