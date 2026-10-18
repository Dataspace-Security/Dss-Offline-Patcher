// Authenticator-app (TOTP) MFA endpoints. Names follow the server's mfa-api doc.
import { api } from "../api";

export const MFA_PATHS = {
  verify: "/api/auth/mfa",
  enrollStart: "/api/auth/mfa/enroll/start",
  enrollConfirm: "/api/auth/mfa/enroll/confirm",
  disable: "/api/auth/mfa/disable",
};

/**
 * POST /api/auth/login answer: `mfa_required` → code step (no session yet, a
 * short-lived pre-auth cookie); `mfa_enrollment_required` → a session limited
 * to enrolment (the app shows the set-up screen from /api/me).
 */
export type LoginResponse = { mfa_required?: boolean; mfa_enrollment_required?: boolean; email?: string } | undefined;

export type EnrollStart = { secret_base32: string; otpauth_uri: string };
export type EnrollConfirm = { recovery_codes: string[] };

export function verifyCode(code: string) {
  return api.signIn<unknown>(MFA_PATHS.verify, { code });
}
export function verifyRecoveryCode(recovery_code: string) {
  return api.signIn<unknown>(MFA_PATHS.verify, { recovery_code });
}
export async function startEnroll(): Promise<EnrollStart> {
  const r = await api.post<Partial<EnrollStart>>(MFA_PATHS.enrollStart, {});
  if (!r?.secret_base32 || !r.otpauth_uri) throw new Error("The server did not return a key for the authenticator app.");
  return { secret_base32: r.secret_base32, otpauth_uri: r.otpauth_uri };
}
export async function confirmEnroll(code: string): Promise<EnrollConfirm> {
  const r = await api.post<Partial<EnrollConfirm>>(MFA_PATHS.enrollConfirm, { code });
  return { recovery_codes: Array.isArray(r?.recovery_codes) ? r.recovery_codes.map(String) : [] };
}
export function disableMfa(code: string) {
  return api.post<unknown>(MFA_PATHS.disable, { code });
}

/** "JBSWY3DPEHPK3PXP" → "JBSW Y3DP EHPK 3PXP". */
export function groupSecret(s: string): string {
  return s.replace(/\s+/g, "").replace(/(.{4})/g, "$1 ").trim();
}

/** Only otpauth:// URIs are drawn as a QR code. */
export function isOtpauthUri(u: string): boolean {
  return /^otpauth:\/\/totp\//i.test(u);
}
