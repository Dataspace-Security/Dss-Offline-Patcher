// Small building blocks for the report profile form: text fields and an
// editable rows table. All updates are immutable (new arrays/objects).
import type { ReactNode } from "react";

export function TextField({ label, value, onChange, ro, hint, multiline, type = "text", full, placeholder }: {
  label: string; value: string; onChange: (v: string) => void; ro: boolean; hint?: string; multiline?: boolean;
  type?: "text" | "date" | "number"; full?: boolean; placeholder?: string;
}) {
  return (
    <label className={`field ${full ? "rprof-full" : ""}`}>
      <span>{label}</span>
      {multiline ? (
        <textarea rows={3} value={value} readOnly={ro} disabled={ro} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input type={type} value={value} readOnly={ro} disabled={ro} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
      )}
      {hint && <small className="hint">{hint}</small>}
    </label>
  );
}

export type Column<T> = {
  key: keyof T & string;
  label: string;
  kind?: "text" | "date" | "number" | "textarea" | "select";
  options?: readonly { value: string; label: string }[];
  width?: string;
  placeholder?: string;
};

export function cellDate(v: string): string {
  // <input type="date"> needs YYYY-MM-DD; RFC 3339 stamps are cut to the day.
  return /^\d{4}-\d{2}-\d{2}/.test(v) ? v.slice(0, 10) : "";
}

function Cell<T>({ col, row, ro, onChange }: { col: Column<T>; row: T; ro: boolean; onChange: (v: string | number) => void }) {
  const raw = row[col.key] as unknown;
  const v = raw === null || raw === undefined ? "" : String(raw);
  const label = col.label;
  if (col.kind === "select") {
    return (
      <select aria-label={label} value={v} disabled={ro} onChange={(e) => onChange(e.target.value)}>
        {col.options?.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    );
  }
  if (col.kind === "textarea") {
    return <textarea aria-label={label} value={v} readOnly={ro} disabled={ro} placeholder={col.placeholder} onChange={(e) => onChange(e.target.value)} />;
  }
  if (col.kind === "number") {
    return <input aria-label={label} type="number" min={0} step={1} value={v} readOnly={ro} disabled={ro}
                  onChange={(e) => onChange(e.target.value === "" ? 0 : Math.max(0, Math.round(Number(e.target.value))))} />;
  }
  if (col.kind === "date") {
    return <input aria-label={label} type="date" value={cellDate(v)} readOnly={ro} disabled={ro} onChange={(e) => onChange(e.target.value)} />;
  }
  return <input aria-label={label} value={v} readOnly={ro} disabled={ro} placeholder={col.placeholder} onChange={(e) => onChange(e.target.value)} />;
}

/** Editable table of rows; `fixedRows` hides add/remove (e.g. one row per priority). */
export function RowsEditor<T>({ rows, columns, onChange, ro, blank, addLabel, fixedRows, lead, empty }: {
  rows: T[]; columns: Column<T>[]; onChange: (rows: T[]) => void; ro: boolean; blank?: () => T; addLabel?: string;
  fixedRows?: boolean; lead?: { label: string; render: (row: T) => ReactNode }; empty?: string;
}) {
  const update = (i: number, key: keyof T, v: string | number) =>
    onChange(rows.map((r, j) => (j === i ? { ...r, [key]: v } : r)));
  const remove = (i: number) => onChange(rows.filter((_, j) => j !== i));
  return (
    <div className="rprof-scroll">
      <table className="rprof-table">
        <thead>
          <tr>
            {lead && <th>{lead.label}</th>}
            {columns.map((c) => <th key={c.key} style={c.width ? { width: c.width } : undefined}>{c.label}</th>)}
            {!fixedRows && !ro && <th className="rprof-del"><span className="sr-only">Remove</span></th>}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td colSpan={columns.length + (lead ? 1 : 0) + 1} className="muted">{empty ?? "None."}</td></tr>
          )}
          {rows.map((r, i) => (
            <tr key={i}>
              {lead && <td>{lead.render(r)}</td>}
              {columns.map((c) => <td key={c.key}><Cell col={c} row={r} ro={ro} onChange={(v) => update(i, c.key, v)} /></td>)}
              {!fixedRows && !ro && (
                <td className="rprof-del">
                  <button type="button" className="btn btn-sm btn-ghost btn-danger-ghost" onClick={() => remove(i)} aria-label={`Remove row ${i + 1}`}>Remove</button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {!fixedRows && !ro && blank && (
        <button type="button" className="btn btn-sm" style={{ marginTop: 8 }} onClick={() => onChange([...rows, blank()])}>{addLabel ?? "Add row"}</button>
      )}
    </div>
  );
}
