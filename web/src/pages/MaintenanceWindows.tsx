import { useState, type FormEvent } from "react";
import { api, enc, errMsg } from "../api";
import { useCan } from "../auth";
import { Empty, ErrorBanner, PageHeader, Pill, ReasonModal, Time } from "../components/ui";
import type { MaintenanceWindow, NewMaintenanceWindow, Weekday } from "../types";
import { splitList, useLoad, useNow } from "../util";

const DAYS: Weekday[] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;

function browserTZ(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

function validTZ(tz: string): boolean {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

/** Current weekday + minutes-since-midnight in an IANA time zone, or null if the zone is unknown to this browser. */
function nowIn(tz: string, now: number): { day: Weekday; minutes: number } | null {
  try {
    const parts = new Intl.DateTimeFormat("en-US", {
      timeZone: tz, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
    }).formatToParts(new Date(now));
    const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
    const day = get("weekday").toLowerCase().slice(0, 3) as Weekday;
    const minutes = (Number(get("hour")) % 24) * 60 + Number(get("minute"));
    if (!DAYS.includes(day) || isNaN(minutes)) return null;
    return { day, minutes };
  } catch {
    return null;
  }
}

function toMin(hhmm: string): number {
  const [h, m] = hhmm.split(":").map(Number);
  return h * 60 + m;
}

/**
 * Best-effort client-side "is it open now?". A window whose end is earlier than
 * its start crosses midnight: it opens on a listed day and runs into the next day.
 * Mirrors the server: start == end is never open.
 */
export function windowOpen(w: Pick<MaintenanceWindow, "days" | "start" | "end" | "timezone">, now: number): boolean | null {
  if (!HHMM.test(w.start) || !HHMM.test(w.end)) return null;
  const n = nowIn(w.timezone || "UTC", now);
  if (!n) return null;
  const days = w.days ?? [];
  const s = toMin(w.start);
  const e = toMin(w.end);
  const today = days.includes(n.day);
  const yesterday = days.includes(DAYS[(DAYS.indexOf(n.day) + 6) % 7]);
  if (s <= e) return today && n.minutes >= s && n.minutes < e;
  return (today && n.minutes >= s) || (yesterday && n.minutes < e);
}

export default function MaintenanceWindows() {
  const canEdit = useCan("operator");
  const now = useNow(30000);
  const { data, error, reload } = useLoad(() => api.get<MaintenanceWindow[]>("/api/maintenance-windows"), [], 30000);
  const [showForm, setShowForm] = useState(false);
  const [deleting, setDeleting] = useState<MaintenanceWindow | null>(null);

  return (
    <>
      <PageHeader title="Maintenance windows" sub="When endpoints in a group may install updates and (optionally) reboot">
        {canEdit && !showForm && <button className="btn btn-primary" onClick={() => setShowForm(true)}>New window</button>}
      </PageHeader>
      <div className="banner banner-info">
        Windows apply per endpoint group (<span className="tag">all</span> = every endpoint). Times are local to the window's time
        zone, and a window may <b>cross midnight</b> (e.g. 22:00–04:00 runs into the next day). Deployments wait for a window unless
        they ignore windows or their deadline has passed. An endpoint with no matching window is not held back.
      </div>
      {showForm && <WindowForm onCancel={() => setShowForm(false)} onCreated={() => { setShowForm(false); void reload(); }} />}
      <ErrorBanner error={error} />
      {data && data.length === 0 && <Empty>No maintenance windows defined.</Empty>}
      {data && data.length > 0 && (
        <table className="table">
          <thead>
            <tr><th>Name</th><th>Groups</th><th>Days</th><th>Time</th><th>Time zone</th><th>Reboot</th><th>Open now?</th><th>Created</th><th /></tr>
          </thead>
          <tbody>
            {data.map((w) => {
              const open = windowOpen(w, now);
              const crosses = HHMM.test(w.start) && HHMM.test(w.end) && toMin(w.end) < toMin(w.start);
              return (
                <tr key={w.window_id}>
                  <td className="cell-title">{w.name}</td>
                  <td>{(w.groups ?? []).map((g) => <span key={g} className="tag">{g}</span>)}</td>
                  <td className="nowrap">
                    {DAYS.map((d) => (
                      <span key={d} className={`daychip ${(w.days ?? []).includes(d) ? "daychip-on" : ""}`}>{d.slice(0, 2)}</span>
                    ))}
                  </td>
                  <td className="nowrap mono">
                    {w.start}–{w.end}
                    {crosses && <div className="cell-sub">crosses midnight</div>}
                  </td>
                  <td>{w.timezone || "UTC"}</td>
                  <td>{w.allow_reboot ? <Pill state="pending_reboot" label="allowed" /> : <span className="muted">no</span>}</td>
                  <td>
                    {open === null ? <span className="muted" title="Unknown time zone in this browser">?</span>
                      : open ? <Pill state="verified" label="open" /> : <Pill state="stale" label="closed" />}
                  </td>
                  <td className="nowrap"><Time value={w.created_at} hideRel /><div className="cell-sub">{w.created_by}</div></td>
                  <td className="right">
                    {canEdit && <button className="btn btn-sm btn-danger-ghost" onClick={() => setDeleting(w)}>Delete…</button>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {data && data.length > 0 && <div className="hint">“Open now?” is computed in this browser and is a best-effort indication; the server decides.</div>}
      {deleting && (
        <ReasonModal
          title={`Delete window “${deleting.name}”`}
          description="Endpoints in these groups will no longer be held to this window. Deployments that relied on it may start installing outside it."
          confirmLabel="Delete window"
          danger
          onClose={() => setDeleting(null)}
          onSubmit={async (reason) => {
            await api.post(`/api/maintenance-windows/${enc(deleting.window_id)}/delete`, { reason });
            await reload();
          }}
        />
      )}
    </>
  );
}

function WindowForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [groups, setGroups] = useState("all");
  const [days, setDays] = useState<Weekday[]>(["mon", "tue", "wed", "thu", "fri"]);
  const [start, setStart] = useState("22:00");
  const [end, setEnd] = useState("04:00");
  const [tz, setTz] = useState(browserTZ());
  const [allowReboot, setAllowReboot] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const now = useNow(30000);

  const problems: string[] = [];
  if (!name.trim()) problems.push("Name is required.");
  if (splitList(groups).length === 0) problems.push("At least one group is required (use “all” for every endpoint).");
  if (days.length === 0) problems.push("Pick at least one day.");
  if (!HHMM.test(start) || !HHMM.test(end)) problems.push("Start and end must be HH:MM.");
  else if (start === end) problems.push("Start and end must differ (a window with equal start and end is never open).");
  if (!tz.trim()) problems.push("Time zone is required.");
  else if (!validTZ(tz.trim())) problems.push(`“${tz}” is not a time zone this browser recognises (use an IANA name like Europe/Berlin).`);

  const crosses = HHMM.test(start) && HHMM.test(end) && toMin(end) < toMin(start);
  const previewOpen = problems.length === 0 ? windowOpen({ days, start, end, timezone: tz.trim() }, now) : null;

  const toggleDay = (d: Weekday) =>
    setDays(days.includes(d) ? days.filter((x) => x !== d) : DAYS.filter((x) => x === d || days.includes(x)));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (problems.length || busy) return;
    setBusy(true);
    setError(null);
    const body: NewMaintenanceWindow = {
      name: name.trim(), groups: splitList(groups), days, start, end, timezone: tz.trim(), allow_reboot: allowReboot,
    };
    try {
      await api.post<MaintenanceWindow>("/api/maintenance-windows", body);
      onCreated();
    } catch (err) {
      setError(errMsg(err));
      setBusy(false);
    }
  };

  return (
    <form className="form card section" onSubmit={submit}>
      <h2>New maintenance window</h2>
      <div className="form-grid">
        <label className="field">
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Weeknight servers" autoFocus />
        </label>
        <label className="field">
          <span>Groups <em className="muted">comma-separated · “all” = every endpoint</em></span>
          <input value={groups} onChange={(e) => setGroups(e.target.value)} />
        </label>
      </div>
      <div className="field">
        <span>Days <em className="muted">the day the window starts</em></span>
        <div className="day-picker">
          {DAYS.map((d) => (
            <label key={d} className="check">
              <input type="checkbox" checked={days.includes(d)} onChange={() => toggleDay(d)} /> {d}
            </label>
          ))}
        </div>
      </div>
      <div className="form-grid form-grid-4">
        <label className="field">
          <span>Start (HH:MM)</span>
          <input type="time" value={start} onChange={(e) => setStart(e.target.value)} />
        </label>
        <label className="field">
          <span>End (HH:MM)</span>
          <input type="time" value={end} onChange={(e) => setEnd(e.target.value)} />
          {crosses && <small className="hint">Crosses midnight — ends the next day.</small>}
        </label>
        <label className="field">
          <span>Time zone <em className="muted">IANA</em></span>
          <input value={tz} onChange={(e) => setTz(e.target.value)} className="mono" placeholder="Europe/Berlin" />
        </label>
        <label className="check setup-ca">
          <input type="checkbox" checked={allowReboot} onChange={(e) => setAllowReboot(e.target.checked)} />
          <span>Allow reboots in this window</span>
        </label>
      </div>
      {previewOpen !== null && (
        <div className="hint">If saved now, this window would be <b>{previewOpen ? "open" : "closed"}</b>.</div>
      )}
      <ErrorBanner error={error} />
      {problems.length > 0 && <ul className="problems">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
      <div className="form-actions">
        <button type="button" className="btn" onClick={onCancel}>Cancel</button>
        <button className="btn btn-primary" disabled={problems.length > 0 || busy}>{busy ? "Creating…" : "Create window"}</button>
      </div>
    </form>
  );
}
