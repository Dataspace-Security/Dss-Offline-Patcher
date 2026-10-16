// Single API client: adds the bearer token (if any), always sends the CSRF
// header and same-origin cookies (SSO session), parses {error} bodies, and
// signals a return to the login screen on 401.

const TOKEN_KEY = "offpatch.token";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string): void {
  sessionStorage.setItem(TOKEN_KEY, t);
}
export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

export const UNAUTHORIZED_EVENT = "offpatch:unauthorized";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

type Opts = { method?: string; body?: unknown; token?: string };

async function raw(path: string, opts: Opts = {}): Promise<Response> {
  const token = opts.token ?? getToken();
  const headers: Record<string, string> = {
    Accept: "application/json",
    // Required for cookie (SSO) authenticated state changes; harmless otherwise.
    "X-Offpatch-CSRF": "1",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
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
    if (res.status === 401 && opts.token === undefined) {
      clearToken();
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
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
  get: <T>(path: string, token?: string) => json<T>(path, { token }),
  post: <T>(path: string, body: unknown) => json<T>(path, { method: "POST", body }),
  patch: <T>(path: string, body: unknown) => json<T>(path, { method: "PATCH", body }),
  blob: async (path: string) => (await raw(path)).blob(),
};

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
