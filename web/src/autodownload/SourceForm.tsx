import { useState, type FormEvent } from "react";
import { Modal } from "../components/ui";
import {
  ARCHES, SOURCE_HELP, SOURCE_LABELS, UPSTREAM_LABELS, sourceProblems,
  type SourceEntry, type SourceType, type Upstream,
} from "./types";

const TYPES: SourceType[] = ["vendor-url", "internal-mirror", "winget", "microsoft-catalog", "msrc"];

function blank(type: SourceType): SourceEntry {
  const base: SourceEntry = { id: "", type, enabled: true, added_by: "", note: "" };
  if (type === "vendor-url") return { ...base, kind: "msi", arch: "x64" };
  if (type === "internal-mirror") return { ...base, replaces: "winget-manifests" };
  return base;
}

interface SourceFormProps {
  /** The source being edited; null = a new one. */
  initial: SourceEntry | null;
  /** Every other source (short names must be unique). */
  others: SourceEntry[];
  onClose: () => void;
  onSave: (s: SourceEntry) => void;
}

/** Add or edit one download source, with the fields its type needs. */
export function SourceForm({ initial, others, onClose, onSave }: SourceFormProps) {
  const [s, setS] = useState<SourceEntry>(initial ?? blank("vendor-url"));
  const [tried, setTried] = useState(false);
  const isNew = initial === null;
  const problems = sourceProblems(s, others);
  const set = <K extends keyof SourceEntry>(k: K, v: SourceEntry[K]) => setS((cur) => ({ ...cur, [k]: v }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTried(true);
    if (problems.length === 0) onSave(s);
  };

  const text = (k: keyof SourceEntry, label: string, opts: { placeholder?: string; hint?: string; mono?: boolean } = {}) => (
    <label className="field">
      <span>{label}</span>
      <input value={(s[k] as string | undefined) ?? ""} placeholder={opts.placeholder} className={opts.mono ? "mono" : undefined}
        onChange={(e) => set(k, e.target.value as never)} />
      {opts.hint && <span className="hint">{opts.hint}</span>}
    </label>
  );

  return (
    <Modal title={isNew ? "Add a download source" : `Edit source ${initial.id}`} onClose={onClose} wide
      footer={<div className="form-actions">
        <button type="button" className="btn" onClick={onClose}>Cancel</button>
        <button type="submit" form="source-form" className="btn btn-primary">{isNew ? "Add source" : "Keep changes"}</button>
      </div>}>
      <form id="source-form" onSubmit={submit}>
        <div className="form-grid">
          <label className="field">
            <span>Type</span>
            <select value={s.type} disabled={!isNew} onChange={(e) => setS({ ...blank(e.target.value as SourceType), id: s.id, note: s.note })}>
              {TYPES.map((t) => <option key={t} value={t}>{SOURCE_LABELS[t]}</option>)}
            </select>
          </label>
          <label className="field">
            <span>Short name</span>
            <input value={s.id} disabled={!isNew} placeholder="e.g. acme-agent" onChange={(e) => set("id", e.target.value.toLowerCase())} />
            <span className="hint">Lower-case letters, digits and '-'. Used to name the downloaded packages.</span>
          </label>
        </div>
        <p className="hint">{SOURCE_HELP[s.type]}</p>

        {s.type === "vendor-url" && (
          <div className="form-grid">
            {text("name", "Product name", { placeholder: "Acme Endpoint Agent" })}
            {text("vendor", "Vendor (optional)", { placeholder: "Acme Ltd" })}
            {text("url", "Download link (https)", { placeholder: "https://downloads.acme.example/agent-2.3.0.msi", mono: true })}
            {text("version", "Version this link downloads", { placeholder: "2.3.0" })}
            <label className="field">
              <span>Installer type</span>
              <select value={s.kind ?? "msi"} onChange={(e) => set("kind", e.target.value as "msi" | "msu")}>
                <option value="msi">MSI (.msi)</option>
                <option value="msu">Windows update (.msu)</option>
              </select>
              <span className="hint">EXE installers are not supported.</span>
            </label>
            <label className="field">
              <span>For</span>
              <select value={s.arch ?? ""} onChange={(e) => set("arch", e.target.value as SourceEntry["arch"])}>
                <option value="">Any architecture</option>
                {ARCHES.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
            </label>
            {text("expected_sha256", "SHA-256 from the vendor", { mono: true, hint: "64 characters. The download is refused if it does not match." })}
            {text("signer", "…or code-signing name", { placeholder: "Acme Ltd", hint: "Only on a Windows downloader: the file must carry a valid signature from this name." })}
            {s.kind === "msi"
              ? text("product_code", "MSI product code (optional)", { placeholder: "{GUID}", mono: true, hint: "Leave empty to read it from the file." })
              : text("kb", "KB number", { placeholder: "KB5044284" })}
          </div>
        )}
        {s.type === "internal-mirror" && (
          <div className="form-grid">
            {text("url", "Mirror address (https)", { placeholder: "https://mirror.bank.example/winget/", mono: true })}
            <label className="field">
              <span>Stands in for</span>
              <select value={s.replaces ?? "winget-manifests"} onChange={(e) => set("replaces", e.target.value as Upstream)}>
                {(Object.keys(UPSTREAM_LABELS) as Upstream[]).map((u) => <option key={u} value={u}>{UPSTREAM_LABELS[u]}</option>)}
              </select>
            </label>
          </div>
        )}
        {s.type === "winget" && (
          <div className="form-grid">
            {text("url", "Index address (optional)", { placeholder: "https://cdn.winget.microsoft.com/cache/source2.msix", mono: true })}
            {text("manifests_url", "Manifests address (optional)", { mono: true })}
          </div>
        )}
        {(s.type === "microsoft-catalog" || s.type === "msrc") && (
          <div className="form-grid">{text("url", "Address (optional)", { mono: true, hint: "Leave empty for Microsoft's public address." })}</div>
        )}

        <div className="form-grid">
          {text("note", "Note (optional)", { placeholder: "Why this source, who approved it" })}
          <label className="check"><input type="checkbox" checked={s.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Use this source</label>
        </div>
        {tried && problems.length > 0 && <ul className="problems">{problems.map((p) => <li key={p}>{p}</li>)}</ul>}
      </form>
    </Modal>
  );
}
