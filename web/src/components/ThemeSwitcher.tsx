import type { KeyboardEvent, ReactNode } from "react";
import { setThemePref, useThemePref, type ThemePref } from "../theme";
import { IconMonitor, IconMoon, IconSun } from "./icons";

const OPTIONS: { value: ThemePref; label: string; icon: ReactNode }[] = [
  { value: "light", label: "Light", icon: <IconSun size={15} /> },
  { value: "dark", label: "Dark", icon: <IconMoon size={15} /> },
  { value: "system", label: "System", icon: <IconMonitor size={15} /> },
];

/** Light / Dark / System switch (a radio group; arrow keys move between options). */
export function ThemeSwitcher({ showLabels }: { showLabels?: boolean }) {
  const pref = useThemePref();

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(e.key)) return;
    e.preventDefault();
    const i = OPTIONS.findIndex((o) => o.value === pref);
    const step = e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 1;
    const next = OPTIONS[(i + step + OPTIONS.length) % OPTIONS.length];
    setThemePref(next.value);
    const btn = e.currentTarget.querySelector<HTMLButtonElement>(`[data-value="${next.value}"]`);
    btn?.focus();
  };

  return (
    <div className={`theme-switch ${showLabels ? "theme-switch-labels" : ""}`} role="radiogroup" aria-label="Colour theme" onKeyDown={onKey}>
      {OPTIONS.map((o) => {
        const on = o.value === pref;
        return (
          <button key={o.value} type="button" role="radio" aria-checked={on} data-value={o.value}
                  tabIndex={on ? 0 : -1} title={`${o.label} theme`} aria-label={o.label}
                  className={`theme-opt ${on ? "theme-opt-on" : ""}`} onClick={() => setThemePref(o.value)}>
            {o.icon}
            {showLabels && <span>{o.label}</span>}
          </button>
        );
      })}
    </div>
  );
}
