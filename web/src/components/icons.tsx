import type { ReactNode, SVGProps } from "react";

/**
 * Small inline icon set (24×24, stroke = currentColor). Decorative by
 * default: the text next to an icon carries the meaning.
 */
type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 18, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
         strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" {...rest}>
      {children}
    </svg>
  );
}

export const IconOverview = (p: IconProps) => (
  <Svg {...p}><rect x="3" y="3" width="7.5" height="9" rx="1.5" /><rect x="13.5" y="3" width="7.5" height="5" rx="1.5" /><rect x="13.5" y="11" width="7.5" height="10" rx="1.5" /><rect x="3" y="15" width="7.5" height="6" rx="1.5" /></Svg>
);
export const IconPatches = (p: IconProps) => (
  <Svg {...p}><path d="M21 8.5 12 3.5 3 8.5v7l9 5 9-5v-7Z" /><path d="m3 8.5 9 5 9-5" /><path d="M12 13.5v7" /><path d="m7.5 6 9 5" /></Svg>
);
export const IconDeployments = (p: IconProps) => (
  <Svg {...p}><path d="M5 12h9" /><path d="m10 7 5 5-5 5" /><path d="M19 4v16" /></Svg>
);
export const IconEndpoints = (p: IconProps) => (
  <Svg {...p}><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8" /><path d="M12 16v4" /></Svg>
);
export const IconReports = (p: IconProps) => (
  <Svg {...p}><path d="M4 20V4" /><path d="M4 20h16" /><rect x="7.5" y="11" width="3" height="6" rx=".5" /><rect x="12.5" y="7" width="3" height="10" rx=".5" /><rect x="17.5" y="13" width="2" height="4" rx=".5" /></Svg>
);
export const IconSettings = (p: IconProps) => (
  <Svg {...p}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" /></Svg>
);
export const IconSun = (p: IconProps) => (
  <Svg {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></Svg>
);
export const IconMoon = (p: IconProps) => (
  <Svg {...p}><path d="M20.5 14.5A8.5 8.5 0 1 1 9.5 3.5a7 7 0 0 0 11 11Z" /></Svg>
);
export const IconMonitor = (p: IconProps) => (
  <Svg {...p}><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></Svg>
);
export const IconEye = (p: IconProps) => (
  <Svg {...p}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" /></Svg>
);
export const IconEyeOff = (p: IconProps) => (
  <Svg {...p}><path d="M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-2.6 3.6M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.8 9.8 0 0 0 5.4-1.6" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /><path d="m3 3 18 18" /></Svg>
);
export const IconShieldCheck = (p: IconProps) => (
  <Svg {...p}><path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6L12 3Z" /><path d="m8.8 12 2.2 2.2 4.3-4.4" /></Svg>
);
export const IconUsers = (p: IconProps) => (
  <Svg {...p}><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0 1 13 0" /><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18.5 14.5A6.5 6.5 0 0 1 21.5 20" /></Svg>
);
export const IconOffline = (p: IconProps) => (
  <Svg {...p}><path d="m3 3 18 18" /><path d="M8.5 16.5a5 5 0 0 1 7 0" /><path d="M5 12.9a10 10 0 0 1 4.2-2.6M14.9 10.3A10 10 0 0 1 19 12.9" /><path d="M2 9.3A15 15 0 0 1 6.2 6.6M12 5a15 15 0 0 1 10 4.3" /><circle cx="12" cy="20" r=".6" fill="currentColor" /></Svg>
);
export const IconLock = (p: IconProps) => (
  <Svg {...p}><rect x="4.5" y="10.5" width="15" height="10" rx="2" /><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" /></Svg>
);
export const IconLogout = (p: IconProps) => (
  <Svg {...p}><path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3" /><path d="M10 16l-4-4 4-4" /><path d="M6 12h10" /></Svg>
);
export const IconKey = (p: IconProps) => (
  <Svg {...p}><circle cx="8" cy="15" r="4" /><path d="m10.8 12.2 8.7-8.7M17 6l2.5 2.5M14.5 8.5l2 2" /></Svg>
);
export const IconAlert = (p: IconProps) => (
  <Svg {...p}><path d="M10.3 3.9 2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /><path d="M12 9.5v4M12 17h.01" /></Svg>
);

/**
 * Product mark: the DSS "D" (two nested D strokes with round ends, opening to
 * the left, and a teal bar in the middle). Traced from the owner's logo
 * (537×648 PNG): stroke 89, outer D radius 280, inner D radius 140, both
 * centred at (193, 324). The white strokes use currentColor, so the mark is
 * navy on light backgrounds and white on dark ones; the bar stays teal.
 * Same drawing as public/favicon.svg.
 */
export const BRAND_TEAL = "#4FC1AE";
const MARK_W = 518;
const MARK_H = 650;

export function BrandMark({ size = 28, className }: { size?: number; className?: string }) {
  return (
    <svg className={className} width={Math.round((size * MARK_W) / MARK_H)} height={size} viewBox={`-1 -1 ${MARK_W} ${MARK_H}`}
         aria-hidden="true" focusable="false">
      <g fill="none" strokeWidth={89} strokeLinecap="round">
        <path d="M44.5 44H193a280 280 0 0 1 0 560H44.5" stroke="currentColor" />
        <path d="M44.5 184H193a140 140 0 0 1 0 280H44.5" stroke="currentColor" />
        <path d="M44.5 324H186.5" stroke={BRAND_TEAL} />
      </g>
    </svg>
  );
}

/** Logo: mark + "DSS Patcher" wordmark. */
export function BrandLogo({ size = 28, sub }: { size?: number; sub?: ReactNode }) {
  return (
    <span className="brand-logo">
      <BrandMark size={size} className="brand-logo-mark" />
      <span className="brand-logo-text">
        <span className="brand-name">DSS <b>Patcher</b></span>
        {sub && <span className="brand-sub">{sub}</span>}
      </span>
    </span>
  );
}
