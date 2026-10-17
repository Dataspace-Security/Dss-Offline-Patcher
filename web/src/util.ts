import { useCallback, useEffect, useRef, useState } from "react";
import { errMsg } from "./api";

/** Go zero time and empty strings are treated as "never". */
export function parseTime(s: string | undefined | null): Date | null {
  if (!s) return null;
  const d = new Date(s);
  if (isNaN(d.getTime()) || d.getUTCFullYear() < 1971) return null;
  return d;
}

export function fmtTime(s: string | undefined | null): string {
  const d = parseTime(s);
  if (!d) return "—";
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function relTime(s: string | undefined | null, now = Date.now()): string {
  const d = parseTime(s);
  if (!d) return "never";
  const diff = Math.round((now - d.getTime()) / 1000);
  const abs = Math.abs(diff);
  let v: string;
  if (abs < 45) v = `${abs}s`;
  else if (abs < 3600) v = `${Math.round(abs / 60)}m`;
  else if (abs < 86400) v = `${Math.round(abs / 3600)}h`;
  else v = `${Math.round(abs / 86400)}d`;
  return diff >= 0 ? `${v} ago` : `in ${v}`;
}

export function fmtBytes(n: number | undefined | null): string {
  if (n === undefined || n === null || isNaN(n)) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

export function splitList(s: string): string[] {
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

export function shortHash(h: string | undefined, n = 12): string {
  if (!h) return "—";
  return h.length > n ? `${h.slice(0, n)}…` : h;
}

/**
 * Fetch data, optionally polling every `intervalMs`.
 *
 * - A timer tick is skipped while a request is still in flight (slow server:
 *   no pile-up of identical requests).
 * - Only the newest request may update state: a response that arrives after
 *   a newer request was started (manual reload, dependency change) is
 *   dropped, so an out-of-order reply never overwrites fresher data.
 * - The sequence and in-flight state are reset whenever `deps` change.
 */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[], intervalMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<number>(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const alive = useRef(true);
  const seq = useRef(0);       // id of the newest request started
  const inFlight = useRef(0);  // id of the request in flight (0 = none)

  const run = useCallback(async (fromTimer: boolean) => {
    if (fromTimer && inFlight.current !== 0) return;
    const my = ++seq.current;
    inFlight.current = my;
    const current = () => alive.current && my === seq.current;
    try {
      const d = await fnRef.current();
      if (!current()) return;
      setData(d);
      setError(null);
      setLoadedAt(Date.now());
    } catch (e) {
      if (current()) setError(errMsg(e));
    } finally {
      if (inFlight.current === my) inFlight.current = 0;
      if (current()) setLoading(false);
    }
  }, []);

  const reload = useCallback(() => run(false), [run]);

  useEffect(() => {
    alive.current = true;
    // A new dependency set: forget any request still running for the old one.
    seq.current++;
    inFlight.current = 0;
    setLoading(true);
    void run(false);
    let t: number | undefined;
    if (intervalMs) t = window.setInterval(() => void run(true), intervalMs);
    return () => {
      alive.current = false;
      if (t) window.clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error, loading, reload, loadedAt, setData };
}

/** Re-render periodically so relative times stay fresh. */
export function useNow(ms = 15000): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), ms);
    return () => window.clearInterval(t);
  }, [ms]);
  return now;
}

export function toRFC3339(localValue: string): string {
  // value from <input type="datetime-local"> is local time
  const d = new Date(localValue);
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
