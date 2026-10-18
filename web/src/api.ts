// Single API client: always sends the CSRF header and same-origin cookies
// (password or SSO session), parses {error} bodies, and signals a return to
// the login screen on 401.

export const UNAUTHORIZED_EVENT = "offpatch:unauthorized";
/** The server refuses everything but a password change until the temporary password is replaced. */
export const PASSWORD_CHANGE_EVENT = "offpatch:password-change-required";
export const PASSWORD_CHANGE_REQUIRED = "password_change_required";
/** Bank roles must set up authenticator-app MFA first: the session only allows enrolment until then. */
export const MFA_ENROLL_EVENT = "offpatch:mfa-enrollment-required";
export const MFA_ENROLLMENT_REQUIRED = "mfa_enrollment_required";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** `signIn`: a sign-in attempt; a 401 is a wrong password, not an expired session. */
type Opts = { method?: string; body?: unknown; signIn?: boolean };

async function raw(path: string, opts: Opts = {}): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    // Required for cookie (SSO) authenticated state changes; harmless otherwise.
    "X-Offpatch-CSRF": "1",
  };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(path, {
      method: opts.method ?? "GET",
      headers,
      credentials: "same-origin",
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  } catch (e) {
    throw new ApiError(0, `Network error: ${(e as Error).message}`);
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const j = await res.json();
      if (j && typeof j.error === "string") msg = j.error;
    } catch {
      /* non-JSON error body */
    }
    if (res.status === 401 && !opts.signIn) {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    if (res.status === 403 && msg === MFA_ENROLLMENT_REQUIRED) {
      window.dispatchEvent(new Event(MFA_ENROLL_EVENT));
      msg = "Set up two-step sign-in first.";
    }
    if (res.status === 403 && msg === PASSWORD_CHANGE_REQUIRED) {
      window.dispatchEvent(new Event(PASSWORD_CHANGE_EVENT));
      msg = "Change your password first.";
    }
    throw new ApiError(res.status, msg);
  }
  return res;
}

async function json<T>(path: string, opts: Opts = {}): Promise<T> {
  const res = await raw(path, opts);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(path: string) => json<T>(path),
  post: <T>(path: string, body: unknown) => json<T>(path, { method: "POST", body }),
  /** Sign-in calls: a 401 is a wrong password, not "signed out". */
  signIn: <T>(path: string, body: unknown) => json<T>(path, { method: "POST", body, signIn: true }),
  patch: <T>(path: string, body: unknown) => json<T>(path, { method: "PATCH", body }),
  put: <T>(path: string, body: unknown) => json<T>(path, { method: "PUT", body }),
  blob: async (path: string) => (await raw(path)).blob(),
};

/** Like downloadFile, but uses the server's Content-Disposition file name when it sends one. */
export async function downloadFileNamed(path: string, fallback: string): Promise<string> {
  const res = await raw(path);
  const cd = res.headers.get("Content-Disposition") ?? "";
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
  let fileName = m ? m[1] : "";
  try { fileName = decodeURIComponent(fileName); } catch { /* not percent-encoded */ }
  const name = fileName.replace(/[\\/:*?"<>|]+/g, "_").trim() || fallback;
  saveBlob(await res.blob(), name);
  return name;
}

/** Fetch an authenticated file and hand it to the browser as a download. */
export async function downloadFile(path: string, filename: string): Promise<void> {
  saveBlob(await api.blob(path), filename);
}

export function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const enc = encodeURIComponent;

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
