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

type PkgLike = Pick<Package, "kind"> & Partial<Pick<Package, "exe" | "rollback_unsupported" | "vendor_signature">>;

export const isExePackage = (p: Pick<Package, "kind"> | null | undefined): boolean => p?.kind === "exe";

/** "EXE · Inno Setup" for EXE packages, the kind otherwise. */
export function packageKindLabel(p: PkgLike): string {
  if (!isExePackage(p)) return p.kind;
  const t = p.exe?.installer_type;
  return t && t !== "exe" ? `EXE · ${exeTypeLabel(t)}` : "EXE";
}

export function KindTag({ p }: { p: PkgLike }) {
  return <span className="tag" title={isExePackage(p) ? "Signed vendor EXE installer, run silently by the agent" : undefined}>{packageKindLabel(p)}</span>;
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
  const signer = p.exe?.signer || p.vendor_signature?.signer || "";
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
        ["Install scope", e.scope === "machine" ? "whole machine" : e.scope],
        ["Rollback", rb ? <span className="text-amber">Rollback: {rb}</span> : "supported (quiet uninstall from Apps & features)"],
      ]} />
    </>
  );
}

/** Server detail of a target skipped because its agent cannot run EXE packages (manifest.AgentTooOldForExe). */
export const AGENT_TOO_OLD_PREFIX = "agent too old for EXE packages";
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
      {isSuper && <> · <Link to={paths.agentVersions()} title="Deploy agent 0.9.0 or later to this machine">Upgrade agent</Link></>}
    </>
  );
}
