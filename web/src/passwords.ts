// Password rules shared by the sign-in screens and Settings → Users.
// They mirror the server (roles contract); the server stays the authority.

export const MIN_PASSWORD_LENGTH = 12;
// Simple, strict enough for a sign-in id; the server validates too.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Problems with a new password, in plain words ([] = fine). */
export function passwordProblems(password: string, email: string): string[] {
  const local = email.split("@")[0] ?? "";
  return [
    ...(password.length < MIN_PASSWORD_LENGTH ? [`Use at least ${MIN_PASSWORD_LENGTH} characters.`] : []),
    ...(password && email && [email.toLowerCase(), local.toLowerCase()].includes(password.toLowerCase())
      ? ["The password cannot be the e-mail address."] : []),
  ];
}

/** E-mail addresses are the sign-in id; stored lower-case. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Problems with a new user's e-mail address ([] = fine). */
export function emailProblems(email: string): string[] {
  if (!email) return ["Type an e-mail address."];
  if (email.length > 254 || !EMAIL_RE.test(email)) return ["This is not a valid e-mail address."];
  return [];
}

// No look-alike characters (0/O, 1/l/I) so it can be read out or typed from paper.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const TEMP_LENGTH = 16;

/** A random temporary password (crypto RNG, rejection sampling: no modulo bias). */
export function generateTempPassword(): string {
  const out: string[] = [];
  const limit = 256 - (256 % ALPHABET.length);
  while (out.length < TEMP_LENGTH) {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b < limit && out.length < TEMP_LENGTH) out.push(ALPHABET[b % ALPHABET.length]);
    }
  }
  // Groups of four are easier to read and type.
  return out.join("").replace(/(.{4})(?=.)/g, "$1-");
}
