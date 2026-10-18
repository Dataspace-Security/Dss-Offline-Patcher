// Auto-download policy (Settings → Auto-download, super admin only). Shapes of
// GET/PUT /api/acquisition/policy (docs/05-api.md) and small helpers.

export type Arch = "x64" | "x86" | "arm64";
export const ARCHES: Arch[] = ["x64", "x86", "arm64"];

export type Classification = "security" | "all";

export type WindowsEntry = {
  product: string; build: number; arch: Arch; classification: Classification; enabled: boolean;
};

export type AppEntry = {
  source: "winget"; id: string; arch: Arch[]; channel: "latest"; enabled: boolean; note: string;
};

export type SourceType = "winget" | "microsoft-catalog" | "msrc" | "vendor-url" | "internal-mirror";
export type Upstream = "winget-index" | "winget-manifests" | "microsoft-catalog" | "msrc";

export type SourceEntry = {
  id: string; type: SourceType; enabled: boolean; added_by: string; note: string;
  url?: string; manifests_url?: string;
  name?: string; vendor?: string; expected_sha256?: string; signer?: string;
  kind?: "msi" | "msu"; version?: string; product_code?: string; kb?: string; arch?: Arch | "";
  replaces?: Upstream;
};

export type Limits = { max_download_gb_per_run: number; keep_last_n_versions: number };

export type AcqPolicy = { windows: WindowsEntry[]; apps: AppEntry[]; sources: SourceEntry[]; limits: Limits };

export type SourceResult = {
  kind: "source" | "app" | "windows"; id: string; type?: string;
  result: "new" | "up_to_date" | "failed" | "unsupported" | "waiting" | "disabled" | "applied" | string;
  detail?: string; packages?: string[];
};

export type KnownWindows = { product: string; build: number; arch: Arch; server?: boolean; catalog_product: string };

export type Downloader = {
  source: string; host: string; finished_at: string; outcome: string; schedule: string;
  policy_version: number; policy_sha256: string; policy_applied_at: string; policy_error?: string;
  run_request?: string; sources: SourceResult[]; reports_policy: boolean;
};

export type RunRequested = { run_id: string; requested_by: string; requested_at: string; queued_to: string };

export type PolicyResponse = {
  version: number; edited_by: string; edited_at: string; sha256: string; summary: string[];
  policy: AcqPolicy; is_default: boolean; default_source: "acquire.json" | "downloader" | "none"; banner?: string;
  default_feeds: string[]; downloader: Downloader | null; delivery: { direct: boolean };
  windows_choices: KnownWindows[]; last_run_request: RunRequested | null;
};

export type PolicySaved = PolicyResponse & { queued_to: string; queued_error?: string };

export type PolicyVersion = { version: number; edited_by: string; edited_at: string; sha256: string; summary: string[] };

export const SOURCE_LABELS: Record<SourceType, string> = {
  winget: "winget (apps)",
  "microsoft-catalog": "Microsoft Update Catalog",
  msrc: "Microsoft security releases (MSRC)",
  "vendor-url": "Vendor download link",
  "internal-mirror": "Internal mirror",
};

export const SOURCE_HELP: Record<SourceType, string> = {
  winget: "Where app versions and installers are looked up. Leave the addresses empty to use the public winget community index.",
  "microsoft-catalog": "Where Windows update files come from. Switching it off stops all Windows downloads.",
  msrc: "Microsoft's monthly list of security updates. Switching it off stops all Windows downloads.",
  "vendor-url": "One installer at a fixed https link from the vendor. It is only accepted if it matches the SHA-256 you enter (or, on a Windows downloader, the vendor's code-signing name).",
  "internal-mirror": "A bank-approved copy of a public source. The downloader uses it instead of the public address.",
};

export const UPSTREAM_LABELS: Record<Upstream, string> = {
  "winget-index": "winget index (app versions)",
  "winget-manifests": "winget manifests (installer details)",
  "microsoft-catalog": "Microsoft Update Catalog",
  msrc: "Microsoft security releases (MSRC)",
};

export const RESULT_LABELS: Record<string, string> = {
  new: "Downloaded",
  up_to_date: "Up to date",
  failed: "Failed",
  unsupported: "Can't download",
  waiting: "Waiting",
  disabled: "Off",
  applied: "In use",
};

export const RESULT_TONE: Record<string, string> = {
  new: "verified", up_to_date: "verified", applied: "verified", failed: "failed", unsupported: "pending_reboot", waiting: "pending", disabled: "stale",
};

export function emptyPolicy(): AcqPolicy {
  return { windows: [], apps: [], sources: [], limits: { max_download_gb_per_run: 0, keep_last_n_versions: 0 } };
}

/** Fill missing arrays (older or partial responses). */
export function normalizePolicy(p: Partial<AcqPolicy> | null | undefined): AcqPolicy {
  return {
    windows: p?.windows ?? [],
    apps: (p?.apps ?? []).map((a) => ({ ...a, arch: a.arch ?? [], note: a.note ?? "" })),
    sources: (p?.sources ?? []).map((s) => ({ ...s, note: s.note ?? "", added_by: s.added_by ?? "" })),
    limits: { max_download_gb_per_run: p?.limits?.max_download_gb_per_run ?? 0, keep_last_n_versions: p?.limits?.keep_last_n_versions ?? 0 },
  };
}

export const windowsKey = (w: Pick<WindowsEntry, "product" | "build" | "arch">) => `${w.product} ${w.build} ${w.arch}`;

const HEX64 = /^[0-9a-fA-F]{64}$/;
const SOURCE_ID = /^[a-z0-9][a-z0-9-]{0,40}$/;
const VERSION = /^[0-9]+(\.[0-9]+){1,3}([-+][A-Za-z0-9.]+)?$/;
const KB = /^KB[0-9]{4,10}$/i;
const GUID = /^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$/;
export const WINGET_ID = /^[A-Za-z0-9_+-]{1,32}(\.[A-Za-z0-9_+-]{1,32}){1,7}$/;

/** Problems with a URL in plain words ("" = fine). The server checks again. */
export function urlProblem(raw: string | undefined, required: boolean): string {
  const v = (raw ?? "").trim();
  if (!v) return required ? "Enter the address." : "";
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return "This is not a web address.";
  }
  if (u.protocol !== "https:") return "Only https:// addresses are allowed.";
  if (u.username || u.password) return "Don't put a user name or password in the address.";
  if (u.hash) return "Remove the #… part.";
  for (const k of u.searchParams.keys()) {
    if (/(token|key|secret|passw|pwd|auth|sig|credential|session)/i.test(k)) return "Don't put passwords or keys in the address.";
  }
  return "";
}

/** Problems with one source in plain words. */
export function sourceProblems(s: SourceEntry, others: SourceEntry[]): string[] {
  const out: string[] = [];
  if (!SOURCE_ID.test(s.id)) out.push("Short name: lower-case letters, digits and '-' only (e.g. acme-agent).");
  else if (others.some((o) => o.id === s.id)) out.push("Another source already uses this short name.");
  const u = (field: string, v: string | undefined, req: boolean) => { const p = urlProblem(v, req); if (p) out.push(`${field}: ${p}`); };
  switch (s.type) {
    case "winget":
      u("Index address", s.url, false);
      u("Manifests address", s.manifests_url, false);
      break;
    case "microsoft-catalog":
    case "msrc":
      u("Address", s.url, false);
      break;
    case "internal-mirror":
      u("Mirror address", s.url, true);
      if (!s.replaces) out.push("Choose what the mirror stands in for.");
      break;
    case "vendor-url": {
      u("Download link", s.url, true);
      if (!s.name?.trim()) out.push("Enter the product name.");
      const sha = (s.expected_sha256 ?? "").trim(), signer = (s.signer ?? "").trim();
      if (!sha && !signer) out.push("Enter the SHA-256 the vendor publishes, or the code-signing name: unverified downloads are never accepted.");
      if (sha && signer) out.push("Enter the SHA-256 or the code-signing name, not both.");
      if (sha && !HEX64.test(sha)) out.push("SHA-256: 64 characters 0-9 and a-f.");
      if (!VERSION.test((s.version ?? "").trim())) out.push("Version: like 1.2.3 (the version this link downloads).");
      if (s.kind === "msu" && !KB.test((s.kb ?? "").trim())) out.push("An .msu needs its KB number (like KB5044284).");
      if (s.kind === "msi" && s.product_code && !GUID.test(s.product_code.trim())) out.push("Product code: a {GUID}, or leave it empty.");
      break;
    }
  }
  return out;
}

/** The policy as the server expects it (trimmed strings, no empty optional fields). */
export function toPayload(p: AcqPolicy): AcqPolicy {
  const clean = (s: SourceEntry): SourceEntry => {
    const out: SourceEntry = { id: s.id.trim(), type: s.type, enabled: s.enabled, added_by: s.added_by, note: s.note.trim() };
    const keep: Record<SourceType, (keyof SourceEntry)[]> = {
      winget: ["url", "manifests_url"],
      "microsoft-catalog": ["url"],
      msrc: ["url"],
      "internal-mirror": ["url", "replaces"],
      "vendor-url": ["url", "name", "vendor", "expected_sha256", "signer", "kind", "version", "product_code", "kb", "arch"],
    };
    for (const k of keep[s.type]) {
      const v = s[k];
      if (typeof v === "string" && v.trim() !== "") (out as Record<string, unknown>)[k] = v.trim();
    }
    if (s.type === "vendor-url" && s.kind !== "msu") delete out.kb;
    if (s.type === "vendor-url" && s.kind !== "msi") delete out.product_code;
    return out;
  };
  return {
    windows: p.windows.map((w) => ({ ...w })),
    apps: p.apps.map((a) => ({ ...a, id: a.id.trim(), note: a.note.trim() })),
    sources: p.sources.map(clean),
    limits: { ...p.limits },
  };
}

export function sourceSummary(s: SourceEntry): string {
  const host = (raw?: string) => {
    try { return raw ? new URL(raw).host : ""; } catch { return raw ?? ""; }
  };
  switch (s.type) {
    case "vendor-url":
      return `${s.name ?? ""} ${s.version ?? ""} · ${(s.kind ?? "").toUpperCase()} from ${host(s.url)} · ${s.expected_sha256 ? "checked by SHA-256" : `signed by "${s.signer ?? ""}"`}`;
    case "internal-mirror":
      return `${UPSTREAM_LABELS[s.replaces ?? "winget-manifests"] ?? s.replaces} from ${host(s.url)}`;
    case "winget":
      return s.url || s.manifests_url ? [s.url && `index ${host(s.url)}`, s.manifests_url && `manifests ${host(s.manifests_url)}`].filter(Boolean).join(", ") : "public winget community";
    default:
      return s.url ? host(s.url) : "Microsoft's public address";
  }
}
