// Hand-written SVG charts for the Overview dashboard (no chart library).
// Every chart carries a text alternative (aria-label + a visually hidden
// table or list) so no value is reachable by colour or hover alone.
import { useCallback, useEffect, useId, useState, type KeyboardEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";

/** Width of an element, kept current with ResizeObserver (0 until measured). Returns a callback ref. */
export function useWidth<T extends HTMLElement>(): [(el: T | null) => void, number] {
  const [el, setEl] = useState<T | null>(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    if (!el) return;
    setW(el.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => setW(Math.round(entries[0]?.contentRect.width ?? 0)));
    ro.observe(el);
    return () => ro.disconnect();
  }, [el]);
  const ref = useCallback((node: T | null) => setEl(node), []);
  return [ref, w];
}

/** SVG-safe id (React ids contain colons). */
function useSvgId(prefix: string): string {
  return `${prefix}${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
}

const tok = (name: string) => `var(${name})`;

// ---------------------------------------------------------------------------
// Radial gauge (hero figure)

export type GaugeTone = "green" | "amber" | "red" | "grey";

export function RadialGauge({ pct, tone, label, caption }: { pct: number | null; tone: GaugeTone; label: string; caption: ReactNode }) {
  const size = 180;
  const stroke = 14;
  const r = (size - stroke) / 2;
  const sweep = 240; // degrees, open at the bottom
  const circ = 2 * Math.PI * r;
  const arc = (circ * sweep) / 360;
  const value = pct === null ? 0 : Math.max(0, Math.min(100, pct));
  const filled = (arc * value) / 100;
  const rotate = 90 + (360 - sweep) / 2; // start at the lower left
  return (
    <figure className="dash-gauge" role="img" aria-label={`${label}: ${pct === null ? "no data" : `${pct} percent`}`}>
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} aria-hidden="true">
        <g transform={`rotate(${rotate} ${size / 2} ${size / 2})`}>
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tok(`--${tone}-bg`)} strokeWidth={stroke}
                  strokeDasharray={`${arc} ${circ}`} strokeLinecap="round" />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tok(tone === "grey" ? "--grey-solid" : `--${tone}-solid`)}
                  strokeWidth={stroke} strokeLinecap="round" className="dash-gauge-fill"
                  strokeDasharray={`${filled} ${circ}`} opacity={value === 0 ? 0 : 1} />
        </g>
      </svg>
      <div className="dash-gauge-center">
        <div className="dash-hero-value">{pct === null ? "—" : `${pct}%`}</div>
        <div className="dash-gauge-caption">{caption}</div>
      </div>
    </figure>
  );
}

// ---------------------------------------------------------------------------
// Stacked part-to-whole bar (fleet health). Segments navigate on click / Enter.

export type Segment = { key: string; label: string; value: number; fill: string; hatch?: boolean; to: string; help?: string };

export function StackedBar({ segments, label, height = 28 }: { segments: Segment[]; label: string; height?: number }) {
  const [wrapRef, width] = useWidth<HTMLDivElement>();
  const navigate = useNavigate();
  const [hover, setHover] = useState<string | null>(null);
  const clipId = useSvgId("clip");
  const hatchId = useSvgId("hatch");
  const total = segments.reduce((a, s) => a + s.value, 0);
  const shown = segments.filter((s) => s.value > 0);
  const gap = 2;
  const usable = Math.max(0, width - gap * Math.max(0, shown.length - 1));
  // Every non-empty class stays visible: at least 4 px wide.
  const minW = 4;
  const raw = shown.map((s) => (total ? (s.value / total) * usable : 0));
  const short = raw.reduce((a, w) => a + Math.max(0, minW - w), 0);
  const big = raw.reduce((a, w) => a + (w > minW ? w : 0), 0);
  const widths = raw.map((w) => (w <= minW ? minW : w - (big ? (short * w) / big : 0)));
  const xs = widths.map((_, i) => widths.slice(0, i).reduce((a, w) => a + w + gap, 0));
  const hovered = shown.findIndex((s) => s.key === hover);
  const go = (to: string) => navigate(to);
  const onKey = (e: KeyboardEvent, to: string) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      go(to);
    }
  };
  return (
    <div className="dash-stack" ref={wrapRef}>
      {width > 0 && total > 0 && (
        <svg width={width} height={height} role="group" aria-label={label} className="dash-stack-svg">
          <defs>
            <clipPath id={clipId}><rect x={0} y={0} width={width} height={height} rx={4} /></clipPath>
            {shown.filter((s) => s.hatch).map((s) => (
              <pattern key={s.key} id={`${hatchId}-${s.key}`} width={6} height={6} patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                <rect width={6} height={6} fill={tok("--surface-3")} />
                <line x1={0} y1={0} x2={0} y2={6} stroke={tok(s.fill)} strokeWidth={2.5} />
              </pattern>
            ))}
          </defs>
          <g clipPath={`url(#${clipId})`}>
            {shown.map((s, i) => (
              <rect key={s.key} x={xs[i]} y={0} width={widths[i]} height={height}
                    fill={s.hatch ? `url(#${hatchId}-${s.key})` : tok(s.fill)}
                    className={`dash-seg ${hover && hover !== s.key ? "dash-seg-dim" : ""}`}
                    role="link" tabIndex={0}
                    aria-label={`${s.label}: ${s.value} of ${total}. Open the list.`}
                    onClick={() => go(s.to)} onKeyDown={(e) => onKey(e, s.to)}
                    onMouseEnter={() => setHover(s.key)} onMouseLeave={() => setHover(null)}
                    onFocus={() => setHover(s.key)} onBlur={() => setHover(null)} />
            ))}
          </g>
        </svg>
      )}
      {hovered >= 0 && (
        <div className="dash-tip" role="presentation"
             style={{ left: Math.min(Math.max(xs[hovered] + widths[hovered] / 2, 90), Math.max(90, width - 90)) }}>
          <b>{shown[hovered].label}</b>
          <span className="num">{shown[hovered].value.toLocaleString()} · {Math.floor((shown[hovered].value / total) * 100)}%</span>
          {shown[hovered].help && <span className="dash-tip-help">{shown[hovered].help}</span>}
        </div>
      )}
    </div>
  );
}

/** Legend swatch matching a segment (solid or hatched). */
export function Swatch({ fill, hatch }: { fill: string; hatch?: boolean }) {
  return <span className={`dash-swatch ${hatch ? "dash-swatch-hatch" : ""}`} style={{ ["--sw" as string]: tok(fill) }} aria-hidden="true" />;
}

// ---------------------------------------------------------------------------
// Horizontal bars on one shared scale (missing updates by severity).

export type HBar = { key: string; label: ReactNode; value: number; fill: string; sub?: ReactNode };

export function HBars({ bars, label, unit, wide }: { bars: HBar[]; label: string; unit: string; wide?: boolean }) {
  const max = Math.max(1, ...bars.map((b) => b.value));
  return (
    <div className={`dash-hbars ${wide ? "dash-hbars-wide" : ""}`} role="group" aria-label={label}>
      {bars.map((b) => {
        const pct = (b.value / max) * 100;
        return (
          <div key={b.key} className="dash-hbar">
            <div className="dash-hbar-label">{b.label}</div>
            <div className="dash-hbar-track" aria-hidden="true">
              <svg width="100%" height="14" className="dash-hbar-svg">
                {b.value > 0 && (
                  <rect x={0} y={0} height={14} rx={4} width={`${Math.max(pct, 1.5)}%`} fill={tok(b.fill)} className="dash-hbar-fill"><title>{`${b.value.toLocaleString()} ${unit}`}</title></rect>
                )}
              </svg>
            </div>
            <div className="dash-hbar-value num" aria-label={`${b.value} ${unit}`}>{b.value.toLocaleString()}</div>
            {b.sub && <div className="dash-hbar-sub">{b.sub}</div>}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Progress bar for a rollout: done · working · failed · waiting.

export function ProgressBar({ done, working, failed, waiting, label }: { done: number; working: number; failed: number; waiting: number; label: string }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const total = done + working + failed + waiting;
  const parts = [
    { k: "done", v: done, fill: "--green-solid" },
    { k: "working", v: working, fill: "--blue-solid" },
    { k: "failed", v: failed, fill: "--red-solid" },
  ].filter((p) => p.v > 0);
  const gap = 2;
  const h = 8;
  const xsW = parts.reduce<{ x: number; w: number }[]>((acc, p) => {
    const x = acc.length ? acc[acc.length - 1].x + acc[acc.length - 1].w + gap : 0;
    return [...acc, { x, w: total ? Math.max(3, (p.v / total) * width - gap) : 0 }];
  }, []);
  return (
    <div className="dash-progress" ref={ref} role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={total}
         aria-valuenow={done} aria-valuetext={`${done} done, ${working} in progress, ${failed} failed, ${waiting} waiting, of ${total}`}>
      {width > 0 && (
        <svg width={width} height={h} aria-hidden="true">
          <rect x={0} y={0} width={width} height={h} rx={4} fill={tok("--surface-3")} />
          {parts.map((p, i) => (
            <rect key={p.k} x={xsW[i].x} y={0} width={xsW[i].w} height={h} rx={i === 0 ? 4 : 1} fill={tok(p.fill)} className="dash-progress-fill" />
          ))}
        </svg>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Line / area over days (one series per chart: small multiples, never two
// y-axes). Missing days break the line. Hover shows a crosshair and the value.

export type LinePoint = { x: string; label: string; value: number | null };

export function LineArea({ points, label, fill, max, unit, height = 132, format = (v) => v.toLocaleString() }: {
  points: LinePoint[]; label: string; fill: string; max?: number; unit: string; height?: number; format?: (v: number) => string;
}) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const gradId = useSvgId("area");
  const padL = 34, padR = 8, padT = 8, padB = 20;
  const vals = points.map((p) => p.value).filter((v): v is number => v !== null);
  const top = max ?? niceMax(Math.max(1, ...vals));
  const w = Math.max(0, width - padL - padR);
  const h = height - padT - padB;
  const n = points.length;
  const x = (i: number) => padL + (n <= 1 ? w / 2 : (i / (n - 1)) * w);
  const y = (v: number) => padT + h - (Math.max(0, Math.min(top, v)) / top) * h;
  // Runs of consecutive days with a value.
  const runs = points.reduce<number[][]>((acc, p, i) => {
    if (p.value === null) return acc;
    const last = acc[acc.length - 1];
    if (last && last[last.length - 1] === i - 1) return [...acc.slice(0, -1), [...last, i]];
    return [...acc, [i]];
  }, []);
  const line = (run: number[]) => run.map((i, k) => `${k ? "L" : "M"}${x(i).toFixed(1)},${y(points[i].value ?? 0).toFixed(1)}`).join(" ");
  const area = (run: number[]) => `${line(run)} L${x(run[run.length - 1]).toFixed(1)},${padT + h} L${x(run[0]).toFixed(1)},${padT + h} Z`;
  const ticks = [0, top / 2, top];
  const xTicks = n > 1 ? [0, Math.floor((n - 1) / 2), n - 1] : [0];
  const hp = hover !== null ? points[hover] : null;
  const colW = n > 1 ? w / (n - 1) : w;
  return (
    <div className="dash-line" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={label} onMouseLeave={() => setHover(null)}>
          <defs>
            <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={tok(fill)} stopOpacity={0.28} />
              <stop offset="100%" stopColor={tok(fill)} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={padL} x2={padL + w} y1={y(t)} y2={y(t)} className="dash-grid-line" />
              <text x={padL - 6} y={y(t)} className="dash-axis" textAnchor="end" dominantBaseline="middle">{format(Math.round(t))}</text>
            </g>
          ))}
          {xTicks.map((i) => (
            <text key={i} x={x(i)} y={height - 4} className="dash-axis"
                  textAnchor={n > 1 && i === 0 ? "start" : n > 1 && i === n - 1 ? "end" : "middle"}>{points[i]?.label}</text>
          ))}
          {runs.map((r) => <path key={`a${r[0]}`} d={area(r)} fill={`url(#${gradId})`} />)}
          {runs.map((r) => <path key={`l${r[0]}`} d={line(r)} fill="none" stroke={tok(fill)} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />)}
          {runs.filter((r) => r.length === 1).map((r) => (
            <circle key={`d${r[0]}`} cx={x(r[0])} cy={y(points[r[0]].value ?? 0)} r={4} fill={tok(fill)} stroke={tok("--surface")} strokeWidth={2} />
          ))}
          {hover !== null && hp && hp.value !== null && (
            <g aria-hidden="true">
              <line x1={x(hover)} x2={x(hover)} y1={padT} y2={padT + h} className="dash-crosshair" />
              <circle cx={x(hover)} cy={y(hp.value)} r={4.5} fill={tok(fill)} stroke={tok("--surface")} strokeWidth={2} />
            </g>
          )}
          {points.map((p, i) => (
            <rect key={p.x} x={x(i) - colW / 2} y={padT} width={Math.max(4, colW)} height={h} fill="transparent"
                  onMouseEnter={() => setHover(i)}>
              <title>{`${p.label}: ${p.value === null ? "no snapshot" : `${format(p.value)} ${unit}`}`}</title>
            </rect>
          ))}
        </svg>
      )}
      {hover !== null && hp && (
        <div className="dash-tip" role="presentation"
             style={{ left: Math.min(Math.max(x(hover), 80), Math.max(80, width - 80)) }}>
          <b>{hp.label}</b>
          <span className="num">{hp.value === null ? "No snapshot that day" : `${format(hp.value)} ${unit}`}</span>
        </div>
      )}
    </div>
  );
}

/** A round upper bound for an axis: 1, 2, 5 × 10^n. */
export function niceMax(v: number): number {
  const p = Math.pow(10, Math.floor(Math.log10(Math.max(1, v))));
  const m = [1, 2, 5, 10].find((k) => k * p >= v) ?? 10;
  return m * p;
}

// ---------------------------------------------------------------------------
// Donut (part-to-whole for a few categories; the legend carries the numbers).

export type DonutSlice = { key: string; label: string; value: number; fill: string; title?: string };

export function Donut({ slices, label, center, size = 148 }: { slices: DonutSlice[]; label: string; center: ReactNode; size?: number }) {
  const [hover, setHover] = useState<string | null>(null);
  const shown = slices.filter((s) => s.value > 0);
  const total = shown.reduce((a, s) => a + s.value, 0);
  const stroke = 22;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const gap = shown.length > 1 ? 2 : 0;
  const arcs = shown.reduce<{ s: DonutSlice; off: number; len: number }[]>((acc, s) => {
    const off = acc.length ? acc[acc.length - 1].off + acc[acc.length - 1].len + gap : 0;
    return [...acc, { s, off, len: Math.max(1, (s.value / total) * c - gap) }];
  }, []);
  return (
    <figure className="dash-donut" style={{ width: size, height: size }}>
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img" aria-label={label}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tok("--surface-3")} strokeWidth={stroke} />
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          {arcs.map(({ s, off, len }) => (
            <circle key={s.key} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={tok(s.fill)} strokeWidth={stroke}
                    strokeDasharray={`${len} ${c - len}`} strokeDashoffset={-off}
                    className={`dash-seg ${hover && hover !== s.key ? "dash-seg-dim" : ""}`}
                    onMouseEnter={() => setHover(s.key)} onMouseLeave={() => setHover(null)}>
              <title>{s.title ?? `${s.label}: ${s.value.toLocaleString()} of ${total.toLocaleString()} (${Math.round((s.value / total) * 100)}%)`}</title>
            </circle>
          ))}
        </g>
      </svg>
      <div className="dash-donut-center">{center}</div>
    </figure>
  );
}

// ---------------------------------------------------------------------------
// Stacked columns per bucket (several series, one shared y-axis).

export type ColumnPart = { key: string; label: string; value: number; fill: string };
export type ColumnBucket = { key: string; label: string; parts: ColumnPart[] };

export function Columns({ buckets, label, height = 150 }: { buckets: ColumnBucket[]; label: string; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const padL = 26, padB = 20, padT = 8;
  const totals = buckets.map((b) => b.parts.reduce((a, p) => a + p.value, 0));
  const top = niceMax(Math.max(1, ...totals));
  const w = Math.max(0, width - padL);
  const h = height - padB - padT;
  const slot = buckets.length ? w / buckets.length : w;
  const barW = Math.max(8, Math.min(44, slot * 0.56));
  const y = (v: number) => (v / top) * h;
  const ticks = top <= 2 ? [0, top] : [0, top / 2, top];
  return (
    <div className="dash-cols" ref={ref}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={label}>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={padL} x2={width} y1={padT + h - y(t)} y2={padT + h - y(t)} className="dash-grid-line" />
              <text x={padL - 6} y={padT + h - y(t)} className="dash-axis" textAnchor="end" dominantBaseline="middle">{Math.round(t)}</text>
            </g>
          ))}
          {buckets.map((b, i) => {
            const cx = padL + slot * i + slot / 2;
            const stack = b.parts.filter((p) => p.value > 0).reduce<{ p: ColumnPart; y0: number; hh: number }[]>((acc, p) => {
              const y0 = acc.length ? acc[acc.length - 1].y0 + acc[acc.length - 1].hh + 2 : 0;
              return [...acc, { p, y0, hh: Math.max(2, y(p.value) - (acc.length ? 2 : 0)) }];
            }, []);
            return (
              <g key={b.key}>
                <title>{`${b.label}: ${b.parts.map((p) => `${p.value} ${p.label.toLowerCase()}`).join(", ")}`}</title>
                <rect x={cx - slot / 2} y={padT} width={slot} height={h} fill="transparent" />
                {stack.map(({ p, y0, hh }, k) => (
                  <rect key={p.key} x={cx - barW / 2} y={padT + h - y0 - hh} width={barW} height={hh}
                        rx={k === stack.length - 1 ? 4 : 0} fill={tok(p.fill)} className="dash-col" />
                ))}
                {totals[i] === 0 && <line x1={cx - barW / 2} x2={cx + barW / 2} y1={padT + h} y2={padT + h} stroke={tok("--border-strong")} strokeWidth={2} />}
                <text x={cx} y={height - 4} className="dash-axis" textAnchor="middle">{b.label}</text>
              </g>
            );
          })}
        </svg>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Card shell, skeletons, empty state, hidden text alternative.

export function DashCard({ title, sub, action, className = "", children, labelledBy }: {
  title: ReactNode; sub?: ReactNode; action?: ReactNode; className?: string; children: ReactNode; labelledBy?: string;
}) {
  const fallbackId = useSvgId("card");
  const id = labelledBy ?? fallbackId;
  return (
    <section className={`dash-card ${className}`} aria-labelledby={id}>
      <header className="dash-card-head">
        <div>
          <h2 id={id} className="dash-card-title">{title}</h2>
          {sub && <div className="dash-card-sub">{sub}</div>}
        </div>
        {action && <div className="dash-card-action">{action}</div>}
      </header>
      {children}
    </section>
  );
}

export function Skeleton({ lines = 3, chart }: { lines?: number; chart?: "gauge" | "bar" }) {
  return (
    <div className="dash-skel" aria-busy="true" aria-label="Loading">
      {chart === "gauge" && <div className="dash-skel-circle" />}
      {chart === "bar" && <div className="dash-skel-bar" />}
      {Array.from({ length: lines }, (_, i) => <div key={i} className="dash-skel-line" style={{ width: `${90 - i * 17}%` }} />)}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="dash-empty">
      <div className="dash-empty-title">{title}</div>
      {children && <div className="dash-empty-body">{children}</div>}
    </div>
  );
}

export function SrOnly({ children }: { children: ReactNode }) {
  return <div className="dash-sr">{children}</div>;
}
