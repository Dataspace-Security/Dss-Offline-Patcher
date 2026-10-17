import { useEffect, useState } from "react";

/** True while the browser tab is visible (used to slow polling when hidden). */
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(() => typeof document === "undefined" || document.visibilityState !== "hidden");
  useEffect(() => {
    const h = () => setVisible(document.visibilityState !== "hidden");
    document.addEventListener("visibilitychange", h);
    return () => document.removeEventListener("visibilitychange", h);
  }, []);
  return visible;
}
