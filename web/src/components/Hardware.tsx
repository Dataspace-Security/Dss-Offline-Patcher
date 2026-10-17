import type { ReactNode } from "react";
import type { Hardware } from "../types";
import { KV, Mono } from "./ui";
import { fmtBytes, parseTime } from "../util";

type Disk = NonNullable<Hardware["disks"]>[number];

export const usedPct = (d: Disk) => (d.total_bytes > 0 ? Math.round(((d.total_bytes - d.free_bytes) / d.total_bytes) * 100) : 0);
const meterColor = (pct: number) => (pct >= 90 ? "bg-red" : pct >= 75 ? "bg-amber" : "bg-green");

export function DiskBar({ d }: { d: Disk }) {
  const pct = usedPct(d);
  return (
    <div className="disk-row">
      <div className="disk-label">
        <Mono>{d.mount}</Mono> <span className="muted">· {fmtBytes(d.free_bytes)} free of {fmtBytes(d.total_bytes)}</span>
        <span className={pct >= 90 ? "text-red" : pct >= 75 ? "text-amber" : ""}> · {pct}% used</span>
      </div>
      <div className="score-meter" role="progressbar" aria-label={`${d.mount} used`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        <span className={meterColor(pct)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function uptime(boot: string | undefined, now: number): string {
  const t = boot ? parseTime(boot) : null;
  if (!t) return "—";
  const s = Math.max(0, Math.floor((now - t.getTime()) / 1000));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

export function HardwareCard({ hw, now }: { hw?: Hardware; now: number }) {
  if (!hw || (!hw.model && !hw.memory_bytes && !(hw.disks ?? []).length)) {
    return (
      <section className="card">
        <h2>Hardware</h2>
        <p className="muted">Not reported yet. Agents report hardware from this version on, at their next check-in.</p>
      </section>
    );
  }
  const rows: [string, ReactNode][] = [
    ["Model", [hw.manufacturer, hw.model].filter(Boolean).join(" · ") || "—"],
    ["Serial number", hw.serial_number ? <Mono>{hw.serial_number}</Mono> : "—"],
    ["CPU", hw.cpu ? `${hw.cpu}${hw.cpu_cores ? ` · ${hw.cpu_cores} cores` : ""}` : hw.cpu_cores ? `${hw.cpu_cores} cores` : "—"],
    ["Memory (RAM)", hw.memory_bytes ? fmtBytes(hw.memory_bytes) : "—"],
    ["Uptime", <>{uptime(hw.boot_time, now)}{hw.boot_time && <span className="muted"> · since {parseTime(hw.boot_time)?.toLocaleString()}</span>}</>],
    ["Logged-in user", hw.logged_in_user || <span className="muted">nobody</span>],
    ["IP addresses", (hw.ip_addresses ?? []).length ? (hw.ip_addresses ?? []).map((ip) => <div key={ip}><Mono>{ip}</Mono></div>) : "—"],
    ["MAC address", hw.mac_address ? <Mono>{hw.mac_address}</Mono> : "—"],
    ["Time zone", hw.timezone || "—"],
  ];
  return (
    <section className="card">
      <h2>Hardware</h2>
      <KV rows={rows} />
      <h3>Storage</h3>
      {(hw.disks ?? []).length ? hw.disks!.map((d) => <DiskBar key={d.mount} d={d} />) : <p className="muted">No disks reported.</p>}
    </section>
  );
}
