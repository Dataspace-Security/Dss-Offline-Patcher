import { useMemo } from "react";
import { encodeQr } from "./qr";

const QUIET = 4;

/** QR code as SVG (one path; dark modules in black on white so any scanner reads it in both themes). */
export function QrCode({ text, size = 200, label }: { text: string; size?: number; label: string }) {
  const result = useMemo(() => {
    try {
      return { qr: encodeQr(text), error: null as string | null };
    } catch (e) {
      return { qr: null, error: e instanceof Error ? e.message : String(e) };
    }
  }, [text]);
  if (!result.qr) return <div className="banner banner-error">Could not draw the QR code: {result.error}. Type the key by hand instead.</div>;
  const { qr } = result;
  const dim = qr.size + QUIET * 2;
  let d = "";
  qr.modules.forEach((row, y) => row.forEach((dark, x) => { if (dark) d += `M${x + QUIET} ${y + QUIET}h1v1h-1z`; }));
  return (
    <svg className="qr-code" width={size} height={size} viewBox={`0 0 ${dim} ${dim}`} role="img" aria-label={label} shapeRendering="crispEdges">
      <rect width={dim} height={dim} fill="#fff" />
      <path d={d} fill="#000" />
    </svg>
  );
}
