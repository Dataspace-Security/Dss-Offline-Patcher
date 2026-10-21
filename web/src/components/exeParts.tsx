import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { useCan } from "../auth";
import { paths } from "../paths";
import type { ExeInstallerType, Package } from "../types";
import { KV, Mono } from "./ui";

/** Names of the EXE installer technologies (winget InstallerType). */
export const EXE_TYPE_LABELS: Record<ExeInstallerType, string> = {
  inno: "Inno Setup", nullsoft: "Nullsoft", burn: "WiX Burn", exe: "EXE",
};

export function exeTypeLabel(t: string | undefined): string {
  return EXE_TYPE_LABELS[(t ?? "").toLowerCase() as ExeInstallerType] ?? "EXE";
}

type PkgLike = Pick<Package, "kind"> & Partial<Pick<Package, "exe" | "rollback_unsupported" | "vendor_signature" | "archive" | "portable" | "msix">>;

export const isExePackage = (p: Pick<Package, "kind"> | null | undefined): boolean => p?.kind === "exe";

/** "EXE · Inno Setup" for EXE packages ("· per user", "· archive"), Portable / MSIX, the kind otherwise. */
export function packageKindLabel(p: PkgLike): string {
  if (p.kind === "portable") return "Portable";
  if (p.kind === "msix") return "MSIX";
  let s: string = p.kind;
  if (isExePackage(p)) {
    const t = p.exe?.installer_type;
    s = t && t !== "exe" ? `EXE · ${exeTypeLabel(t)}` : "EXE";
    if (p.exe?.scope === "user") s += " · per user";
  }
  return p.archive ? `${s} · archive` : s;
}

const KIND_TITLES: Record<string, string> = {
  exe: "Signed vendor EXE installer, run silently by the agent",
  portable: "Portable app: the agent copies its verified files to Program Files (agents 0.10.0+)",
  msix: "MSIX package, provisioned for all users of the machine (agents 0.10.0+)",
};

export function KindTag({ p }: { p: PkgLike }) {
  return <span className="tag" title={KIND_TITLES[p.kind]}>{packageKindLabel(p)}</span>;
}

export const EXE_NO_ROLLBACK = "not supported for this installer";

/**
 * Why a rollback deployment of p is impossible ("" = supported). An EXE
 * package can only be rolled back when the app registers a quiet uninstall.
 */
export function rollbackBlocker(p: PkgLike): string {
  if (isExePackage(p) && !p.exe?.uninstall?.quiet_uninstall) return EXE_NO_ROLLBACK;
  return p.rollback_unsupported ?? "";
}

const SIG_OK = new Set(["valid", "ok", "verified"]);

/** "Signed by Microsoft Corporation — verified" (signer pmctl checked at acquisition). */
export function signerText(p: PkgLike): string {
  const signer = p.exe?.signer || p.portable?.signer || p.msix?.signer || p.vendor_signature?.signer || "";
  if (!signer) return "";
  const st = (p.vendor_signature?.status ?? "").toLowerCase();
  const verdict = SIG_OK.has(st) || (!st && !!p.exe?.signer) ? "verified" : st.replace(/_/g, " ");
  return `Signed by ${signer}${verdict ? ` — ${verdict}` : ""}`;
}

/** The silent argv, one argument per token (no shell). */
function Args({ args }: { args: string[] | undefined }) {
  if (!args?.length) return <span className="muted">none</span>;
  return <Mono>{args.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ")}</Mono>;
}

function codes(list: number[] | undefined): string {
  return (list ?? []).join(", ");
}

/** EXE section of the package detail: installer type, signer, silent arguments, detection, rollback. */
export function ExeDetails({ p }: { p: PkgLike }) {
  const e = p.exe;
  if (!isExePackage(p)) return null;
  if (!e) {
    return <div className="hint">EXE package: the server did not send the installer details.</div>;
  }
  const d = e.detect ?? { display_name: "" };
  const detection: ReactNode = d.display_name
    ? <>Apps &amp; features shows <b>{d.display_name}</b>{d.display_version ? <> version <Mono>{d.display_version}</Mono></> : null}
        {d.publisher ? <span className="muted"> · {d.publisher}</span> : null}
        {d.product_code ? <div className="cell-sub"><Mono>{d.product_code}</Mono></div> : null}</>
    : "";
  const rb = rollbackBlocker(p);
  return (
    <>
      <h3>EXE installer</h3>
      <KV rows={[
        ["Installer type", exeTypeLabel(e.installer_type)],
        ["Signer", signerText(p) || <span className="text-red">no signer recorded</span>],
        ["Silent arguments", <Args args={e.silent_args} />],
        ["Success codes", <>{codes(e.success_codes) || "0"} <span className="muted small">· 3010 / 1641 = installed, restart needed</span></>],
        ["Busy codes", e.busy_codes?.length ? <>{codes(e.busy_codes)} <span className="muted small">· retried later</span></> : ""],
        ["Detection", detection],
        ["Install scope", e.scope === "machine" ? "whole machine" : e.scope === "user" ? "each signed-in user (run in their session; waits while nobody is signed in)" : e.scope],
        ["Rollback", rb ? <span className="text-amber">Rollback: {rb}</span> : "supported (quiet uninstall from Apps & features)"],
      ]} />
      <ArchiveDetails p={p} />
    </>
  );
}

/** Archive packages: the installer inside the verified zip and the files the agent checks. */
function ArchiveDetails({ p }: { p: PkgLike }) {
  const a = p.archive;
  if (!a) return null;
  const total = a.files.reduce((n, f) => n + f.size, 0);
  return (
    <KV rows={[
      ["Archive", <>zip with <b>{a.files.length}</b> files ({Math.round(total / 1048576)} MB), each checked against its SHA-256 by the agent</>],
      ["Runs", <Mono>{a.entry}</Mono>],
    ]} />
  );
}

/** Portable and MSIX sections of the package detail. */
export function FormatDetails({ p }: { p: PkgLike }) {
  if (p.kind === "portable") {
    const po = p.portable;
    if (!po) return <div className="hint">Portable app: the server did not send its details.</div>;
    return (
      <>
        <h3>Portable app</h3>
        <KV rows={[
          ["Signer", signerText(p) || <span className="text-red">no signer recorded</span>],
          ["Installed to", <Mono>{`%ProgramFiles%\\DSS Patcher Apps\\${po.folder}`}</Mono>],
          ["Program", <Mono>{po.command}</Mono>],
          ["Detection", <>Apps &amp; features entry <Mono>{po.arp_key}</Mono>: <b>{po.display_name}</b> <Mono>{po.display_version}</Mono></>],
          ["Start menu", po.shortcut ? po.shortcut : <span className="muted">no shortcut</span>],
          ["Updates", "the folder is replaced; while the app runs the update is retried later"],
        ]} />
        <ArchiveDetails p={p} />
      </>
    );
  }
  if (p.kind === "msix") {
    const m = p.msix;
    if (!m) return <div className="hint">MSIX package: the server did not send its identity.</div>;
    return (
      <>
        <h3>MSIX package</h3>
        <KV rows={[
          ["Package family", <Mono>{m.package_family_name}</Mono>],
          ["Version", <Mono>{m.version}</Mono>],
          ["Publisher", <span className="small">{m.publisher}</span>],
          ["Signer", signerText(p) || <span className="muted">not checked at acquisition (the agent requires a valid signature)</span>],
          ["Install", "provisioned for every user; signed-in users get it at their next sign-in"],
          ["Rollback", <span className="text-amber">{rollbackBlocker(p) || "not supported"}</span>],
        ]} />
      </>
    );
  }
  return null;
}

/** Server detail of a target skipped because its agent is too old for the package (manifest.AgentTooOld*: EXE, archive, portable, MSIX, per-user). */
export const AGENT_TOO_OLD_PREFIX = "agent too old for ";
export const isAgentTooOld = (detail: string | undefined): boolean =>
  (detail ?? "").toLowerCase().startsWith(AGENT_TOO_OLD_PREFIX);

/** A target's detail text; "agent too old" adds an Upgrade agent hint for the super admin (vendor). */
export function TargetDetailText({ detail }: { detail: string | undefined }) {
  const isSuper = useCan("super_admin");
  if (!detail) return <span className="muted">—</span>;
  if (!isAgentTooOld(detail)) return <>{detail}</>;
  return (
    <>
      {detail}
      {isSuper && <> · <Link to={paths.agentVersions()} title="Deploy a newer agent to this machine">Upgrade agent</Link></>}
    </>
  );
}
