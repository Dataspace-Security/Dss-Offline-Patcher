import { useEffect, useSyncExternalStore } from "react";

/** Colour theme the person picked; "system" follows the operating system. */
export type ThemePref = "light" | "dark" | "system";

/** Same key as public/theme-init.js, which applies the theme before first paint. */
const THEME_KEY = "offpatch.theme";
const DARK_QUERY = "(prefers-color-scheme: dark)";
const listeners = new Set<() => void>();

function isPref(v: unknown): v is ThemePref {
  return v === "light" || v === "dark" || v === "system";
}

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return isPref(v) ? v : "system";
  } catch {
    return "system"; // storage blocked: follow the system
  }
}

let current: ThemePref = readPref();

function systemDark(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia(DARK_QUERY).matches;
}

/** Put the resolved theme on <html data-theme>; the CSS tokens follow it. */
function apply(pref: ThemePref) {
  const dark = pref === "dark" || (pref === "system" && systemDark());
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
}

export function setThemePref(pref: ThemePref) {
  current = pref;
  try {
    localStorage.setItem(THEME_KEY, pref);
  } catch {
    /* not remembered, but still applied for this page */
  }
  apply(pref);
  listeners.forEach((l) => l());
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** Current preference; re-applies on OS changes (System) and on changes from other tabs. */
export function useThemePref(): ThemePref {
  const pref = useSyncExternalStore(subscribe, () => current);
  useEffect(() => {
    apply(pref);
    const mq = typeof window.matchMedia === "function" ? window.matchMedia(DARK_QUERY) : null;
    const onSystem = () => { if (current === "system") apply("system"); };
    const onStorage = (e: StorageEvent) => {
      if (e.key === THEME_KEY) {
        current = isPref(e.newValue) ? e.newValue : "system";
        apply(current);
        listeners.forEach((l) => l());
      }
    };
    mq?.addEventListener("change", onSystem);
    window.addEventListener("storage", onStorage);
    return () => {
      mq?.removeEventListener("change", onSystem);
      window.removeEventListener("storage", onStorage);
    };
  }, [pref]);
  return pref;
}
