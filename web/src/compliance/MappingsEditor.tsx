import type { RegulatoryMapping } from "./types";
import { APPLICABLE, STATUS_VALUES } from "./types";
import { emptyMapping, templateRowFor } from "./normalize";
import { mappingTitle } from "./templateText";
import { cellDate, TextField } from "./ProfileParts";

const APPLICABLE_LABEL: Record<string, string> = { yes: "Yes", no: "No", unknown: "Unknown" };

/** §4 regulatory mappings: one card per framework (template rows keep their name; custom rows can be renamed or removed). */
export function MappingsEditor({ rows, ro, onChange }: { rows: RegulatoryMapping[]; ro: boolean; onChange: (rows: RegulatoryMapping[]) => void }) {
  const update = (i: number, patch: Partial<RegulatoryMapping>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="rprof-maps">
      {rows.map((m, i) => {
        const template = !!templateRowFor(m);
        const reviewed = m.applicable !== "unknown" && m.reviewer.trim() !== "";
        return (
          <fieldset key={i} className="fieldset rprof-map">
            <legend>
              {mappingTitle(m) || "Custom framework"}
              <span className={`rprof-map-state ${reviewed ? "text-green" : "muted"}`}>{reviewed ? " · reviewed" : " · needs compliance review"}</span>
            </legend>
            <div className="rprof-grid rprof-grid-3">
              <TextField label="Framework / regulator (required)" value={m.framework} ro={ro} onChange={(v) => update(i, { framework: v })} />
              <TextField label="Instrument / identifier / version" value={m.instrument} ro={ro} onChange={(v) => update(i, { instrument: v })} />
              <TextField label="Clause reference (exact)" value={m.clause_ref} ro={ro} onChange={(v) => update(i, { clause_ref: v })} />
              <label className="field">
                <span>Applicable</span>
                <select value={m.applicable} disabled={ro} onChange={(e) => update(i, { applicable: e.target.value as RegulatoryMapping["applicable"] })}>
                  {APPLICABLE.map((a) => <option key={a} value={a}>{APPLICABLE_LABEL[a]}</option>)}
                </select>
              </label>
              <TextField label="Potential patch-related expectation" value={m.expectation} ro={ro} multiline onChange={(v) => update(i, { expectation: v })} />
              <TextField label="Evidence the report can provide" value={m.evidence} ro={ro} multiline onChange={(v) => update(i, { evidence: v })} />
              <TextField label="Applicability rationale" value={m.rationale} ro={ro} multiline onChange={(v) => update(i, { rationale: v })} />
              <label className="field">
                <span>Result</span>
                <select value={m.result} disabled={ro} onChange={(e) => update(i, { result: e.target.value })}>
                  <option value="">Not set</option>
                  {STATUS_VALUES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <TextField label="Reviewer" value={m.reviewer} ro={ro} onChange={(v) => update(i, { reviewer: v })} />
              <TextField label="Reviewed on" type="date" value={cellDate(m.reviewed_at)} ro={ro} onChange={(v) => update(i, { reviewed_at: v })} />
              <TextField label="Notes" value={m.notes} ro={ro} multiline full onChange={(v) => update(i, { notes: v })} />
            </div>
            {!template && !ro && (
              <div className="form-actions">
                <button type="button" className="btn btn-sm btn-ghost btn-danger-ghost" onClick={() => onChange(rows.filter((_, j) => j !== i))}>Remove</button>
              </div>
            )}
          </fieldset>
        );
      })}
      {!ro && <div><button type="button" className="btn btn-sm" onClick={() => onChange([...rows, emptyMapping("")])}>Add custom framework</button></div>}
    </div>
  );
}
