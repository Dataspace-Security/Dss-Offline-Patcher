# Security testing (roadmap B11)

This directory records the automated security testing done for offpatch, its results, how to re-run it, and the scope for the external penetration test. The automated checks do **not** replace the pen test. People have to do the pen test.

- One command runs every check: `bash scripts/security-check.sh` (see [How to run](#how-to-run)).
- Test date of the results below: 2026-10-16. Toolchain: go1.27.1 darwin/arm64, Node 26.

## 1. What was tested

| Area | Method | Code |
|---|---|---|
| Manifest JSON parsing and schema validation | Go native fuzzing (`FuzzParse`) | `internal/manifest/fuzz_test.go` |
| Bundle (`.pmb` tar) extraction: traversal, links, devices, duplicates, size limits, truncation | Go native fuzzing (`FuzzExtractSafe`) | same |
| Ed25519 signature verification and public-key parsing | Go native fuzzing (`FuzzVerify`) | same |
| Go dependencies and standard library | `govulncheck` v1.9.0 (reachability-aware) | whole module |
| Console (npm) dependencies | `npm audit` | `web/` |
| Software bill of materials | CycloneDX 1.6 JSON | `scripts/sbom.sh` → `dist/sbom/` |
| Static checks | `go vet`, native and `GOOS=windows` | whole module |

### Fuzz harness design

- **FuzzParse** runs `manifest.Parse` and then `ValidateSchema` on arbitrary bytes. It must never panic. It also checks a property: if a manifest passes validation, every `file.name` must be `payload/<base>`, where `<base>` is not `.` or `..`, has no separator, no trailing dot, and is not a Windows device name. It also checks that `size > 0`, that `sha256` is 64 lowercase hex characters, and that there are 1–500 packages.
- **FuzzExtractSafe** takes either raw archive bytes or a structured encoding. The structured encoding is decoded into tar entries with fuzzed name, type (regular, dir, symlink, hardlink, char/block device, fifo, GNU sparse, cont), size and body. It can also inflate the declared size and truncate the archive. The seed corpus contains a valid signed bundle plus variants: `../` and absolute paths, backslash traversal, nested dirs, symlinks and hardlinks, devices, fifos, a duplicate payload and a duplicate manifest, a declared 1 TiB size, files over the per-file and total limits, too many files, case-colliding names, `CON` and a trailing-dot name, a 32 MiB manifest, an oversized signature, `payload` as a file or symlink, an empty archive, and truncated archives. Each iteration extracts into a fresh temp directory with small limits (4 files, 4 KiB/file, 8 KiB total). Every iteration asserts:
  - no panic;
  - walking the **parent** temp dir finds nothing outside `dest/payload/`, no non-regular files (links or devices) and no Windows-unsafe names;
  - bytes on disk ≤ `MaxTotal`, every file ≤ `MaxFileBytes`, and file count ≤ `MaxFiles`. These hold **even when extraction fails part-way**;
  - on success, every `Files` entry is directly inside `dest/payload`, and its key, size and SHA-256 match the bytes on disk. The manifest and signature are present.
- **FuzzVerify** calls `Verify` with an arbitrary raw key (any length), message and signature string. It also runs `ParsePublic` on the key bytes as text and then `Verify`. It asserts no panic, that a key that is not 32 bytes never verifies, and that the genuine seed key never accepts its signature over a different message.

## 2. Results

### 2.1 Fuzzing

| Fuzzer | Duration | Executions | Corpus (seed + new) | Outcome |
|---|---|---|---|---|
| FuzzParse | 75 s | 6,507,132 | 432 | Property violation found (bug 2), fixed. Clean afterwards. |
| FuzzExtractSafe | 90 s (`-fuzzminimizetime=2s`) | 58,542 | 242 | Clean. Earlier 75 s run: 1,991 execs, because minimization stalled at the 60 s default. |
| FuzzVerify | 75 s | 3,307,168 | 35 | Panic found (bug 1), fixed. Clean afterwards. |

All runs used 4 workers on an Apple-silicon laptop. FuzzExtractSafe is about 600 exec/s because every iteration creates and removes temp directories and files. That is expected, and it is why the script passes a short `-fuzzminimizetime`.

**Bugs found and fixed** (regression seeds are in `internal/manifest/testdata/fuzz/`, and plain `go test` replays them):

1. **`manifest.Verify` panics on a public key that is not 32 bytes** (`FuzzVerify`, seed `nil-public-key-panic`). `ed25519.Verify` panics when the key length is wrong, so a nil or truncated key crashed the caller instead of failing. The current callers (intake, agent and `pmctl`) only pass keys that came through `ParsePublic`, which checks the length, so attackers cannot reach this today. A later code path, such as a key lookup that returns a zero value, would have turned it into a crash of the intake goroutine or the agent. **Fix:** `Verify` now rejects `len(pub) != ed25519.PublicKeySize` and returns an error (`manifest.go`).
2. **`ValidateSchema` accepted unsafe payload file names** (`FuzzParse` property; seeds `dotdot-file-name-validated` and `windows-device-file-name-validated`). The base-name regex `[A-Za-z0-9._-]{1,200}` allowed `payload/..`, `payload/.`, `payload/...`, trailing-dot names (`a.msu.`, which Windows silently aliases to `a.msu`) and Windows device names (`CON`, `NUL.msu`, `COM1.msi`, `LPT1`...). `ExtractSafe` already refused `.`/`..`, so a full intake still rejected those bundles at the "file missing" check. The manifest validator was weaker than the extractor, though. `internal/store` builds `<quarantine>/payload/filepath.Base(file.name)`, and with `..` that path resolves to the quarantine *parent*. On a Windows `pmserver`, a device name would open a device instead of a file. **Fix:** one shared `validBase()` (`manifest.go`), used by both `ValidateSchema` and `ExtractSafe` (`bundle.go`). It rejects dot-segments, trailing dots and reserved device names.

### 2.2 govulncheck (v1.9.0, `./...`)

- **Third-party modules: no known vulnerabilities.** That covers `modernc.org/sqlite` v1.60.1, `modernc.org/libc` v1.77.1, `golang.org/x/sys` v0.49.0, `github.com/google/uuid` v1.6.0 and the rest. **No `go.mod` changes were needed.**
- **Standard library go1.27.1: 10 reachable vulnerabilities**, all fixed in **go1.27.2**: GO-2026-6617, -6613, -6612, -6611, -6610, -6609, -6608, -6607, -6605 and -6603. Most are in `net/http` HTTP/1 and HTTP/2 (server crash, desync, CPU and memory exhaustion, Range header size), plus `mime/multipart` and `crypto/tls` (ECH). They are reachable through pmserver's HTTP server, the agent client and the OIDC client.
  Also imported but not reached: GO-2026-6604 (`os.Root` follows junctions on Windows). Present in the module but not imported: GO-2026-6600 and GO-2026-6599 (`html/template`).
- **Action required:** build release binaries with **go1.27.2 or later** (a patch release on the same 1.27 line). I did not change the toolchain from this task. Adding a `toolchain` directive would make every `go` command try to download a toolchain, and that would break offline builds. Upgrade the installed Go on the build host instead. Until that happens, `security-check.sh` **fails on govulncheck**. That failure is intended.

### 2.3 npm audit (`web/`)

Before: 4 advisories (1 high, 3 moderate).

| Package | Advisory | Affects |
|---|---|---|
| vite ≤ 6.4.2 (high) | GHSA-fx2h-pf6j-xcff `server.fs.deny` bypass on Windows; GHSA-4w7w-66w2-5vf9 path traversal in optimized deps `.map`; GHSA-v6wh-96g9-6wx3 launch-editor NTLM leak | **dev server only** |
| esbuild ≤ 0.24.2 (moderate) | GHSA-67mh-4wv8-2f99 any website can query the dev server | **dev server only** |
| react-router / react-router-dom 6.0–7.17 (moderate) | GHSA-wrjc-x8rr-h8h6 open redirect via backslash in `<Link>`/`useNavigate`; GHSA-337j-9hxr-rhxg SSR `deserializeErrors` (we do not use SSR) | **production bundle** (client-side routing) |

`npm audit fix` without `--force` had nothing it could fix. The only fixes are major upgrades. I applied them because `npm run typecheck` and `npm run build` pass with **no source changes**:

- `vite` 5.4.21 → **8.3.4** and `@vitejs/plugin-react` 4.7.0 → **6.1.2** (devDependencies; the Vite advisories are dev-server only and never shipped in the embedded static build).
- `react-router-dom` 6.30.6 → **7.18.4**. This is a runtime dependency and the open-redirect advisory applies to the shipped console. The console only uses `BrowserRouter`, `Routes`/`Route`, `Navigate`, `Link`/`NavLink`, `useNavigate`, `useParams` and `useSearchParams`, all with absolute paths, so the v7 behaviour changes (relative splat paths, `startTransition`) do not apply. Smoke test: the production build was served with `vite preview` and loaded the login screen with no console errors.

After: **`npm audit` reports 0 vulnerabilities** (all dependencies, including dev). Note that Vite 8 needs Node ^20.19 or ≥ 22.12 on the build host.

### 2.4 SBOM

`scripts/sbom.sh` writes CycloneDX 1.6 JSON to `dist/sbom/`. `/dist/` is git-ignored.

| File | Mode | Content |
|---|---|---|
| `offpatch-module.cdx.json` | `cyclonedx-gomod mod` (pinned v1.12.0) | all 10 required Go modules |
| `pmserver.cdx.json`, `pmagent.cdx.json`, `pmctl.cdx.json` | `cyclonedx-gomod bin` on binaries built with `-trimpath` for `SBOM_GOOS/SBOM_GOARCH` (default windows/amd64) | exactly what is linked, including `std@go1.27.1` |
| `web-console.cdx.json` | `@cyclonedx/cyclonedx-npm` (pinned 6.0.1), `--omit dev` | the 9 runtime npm packages embedded in pmserver |

The script uses `bin` mode rather than `app` mode because `app` mode requires the main module's version from git, and it fails in a repository without commits or tags. Set `OFFPATCH_VERSION` to stamp the release version. The license warnings for `offpatch` and `std` are expected (local module, stdlib).

## 3. Residual risks and follow-ups

1. **Go toolchain 1.27.1 has 10 reachable stdlib CVEs.** Rebuild with go1.27.2 or later before any pilot (see 2.2). This is the only open item that makes the security gate fail.
2. **Fuzzing time is short.** About 1–1.5 minutes per target on one laptop. Run longer sessions (hours) in CI or overnight, especially `FuzzExtractSafe`. The corpus that builds up in `$(go env GOCACHE)/fuzz` should be kept between runs.
3. **Fuzzing covers only `internal/manifest`.** The intake pipeline (`internal/intake`: sequence/replay, key/source authorization, quarantine moves), the HTTP handlers, JSON request decoding and the agent's response parsing are not fuzzed. Candidates: an HTTP-level fuzzer for `/api/agent/*` request bodies, and the agent's assignment and manifest-response decoding.
4. **Extraction leaves partial files on failure.** `ExtractSafe` stops at the first violation and leaves whatever it already wrote in the destination. The total stays within the limits. Callers must delete the quarantine directory of a rejected bundle; check this in intake.
5. **The extraction tests ran on macOS (case-insensitive APFS).** Windows-specific path behaviour (8.3 short names, NTFS alternate data streams, `:` in names) is blocked by the `[A-Za-z0-9._-]` charset, but nobody has fuzzed it *on* Windows. Run `go test -fuzz=FuzzExtractSafe` on a Windows host once.
6. **The react-router v7 upgrade was only smoke-tested** (build, typecheck, login page render). Click through the console end to end against a running pmserver before release.
7. Existing MVP limitations from `docs/02-architecture.md` remain (single node; vendor Authenticode is recorded, not re-verified in the isolated zone; egress denial must be enforced by the network).

## How to run

```bash
# everything (needs network or warm caches for govulncheck DB, pinned tools, npm registry)
bash scripts/security-check.sh                 # FUZZTIME defaults to 20s per fuzzer
FUZZTIME=5m bash scripts/security-check.sh     # longer fuzzing

# individual pieces
go test ./internal/manifest/                   # unit tests + fuzz regression corpus
go test -run='^$' -fuzz='^FuzzExtractSafe$' -fuzztime=10m -fuzzminimizetime=5s ./internal/manifest/
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
(cd web && npm audit --omit=dev --audit-level=high)
bash scripts/sbom.sh                           # → dist/sbom/*.cdx.json
```

`security-check.sh` runs every step, prints a PASS/FAIL summary and exits 1 if any step failed. When a fuzzer fails, Go writes the input to `internal/manifest/testdata/fuzz/<FuzzName>/<hash>`. Fix the bug, then keep the file (renamed descriptively) as a regression seed.

---

## 4. Penetration-test scope (for the external tester)

### 4.1 Objective

Find out whether an attacker can do any of the following:

- get unapproved or modified content installed on an endpoint;
- run code on pmserver or pmagent;
- read or alter catalog, deployment or audit data without authorization;
- deny patching (DoS) through the channels described below.

The product is an **offline** patch manager. Bundles cross a one-way transfer boundary into an isolated management zone, and agents talk only to pmserver. Read `docs/02-architecture.md` (trust model, abuse cases), `docs/04-bundle-format.md` and `docs/05-api.md` first.

### 4.2 Test environment to be provided

- pmserver (Windows Server and Linux builds) with a fresh `-data` dir, TLS enabled, and the console at `/`.
- At least two Windows endpoints running pmagent: one enrolled, one spare for enrollment testing.
- A `pmctl` workstation with a **test** signing key, used to build valid bundles. The tester may also receive a second, untrusted key.
- Admin accounts (email + password, each with an enrolled authenticator app) for each role: `viewer`, `user`, `admin`, plus the built-in `super_admin`. OIDC login and mTLS agent auth are tested if they are enabled in the build under test.
- Write access to the pmserver inbox directory, which simulates the transfer adapter or diode output.
- Source code access (grey-box) is recommended.

### 4.3 Assets and trust boundaries

| # | Asset / interface | Trust boundary crossed | Who the attacker is |
|---|---|---|---|
| A1 | **Bundle intake** (`<data>/inbox/*.pmb` → received → quarantine) | Transfer boundary: connected zone → isolated zone | Anyone who can place a file on the transfer media or diode |
| A2 | **Admin API** `/api/*` (`offpatch_session` cookie from email + password + TOTP, or OIDC) | Admin network → pmserver | Low-privilege admin (viewer/user), stolen password or session, malicious insider |
| A3 | **Agent API** `/api/agent/*` (enroll token, device secret / mTLS) | Endpoint network → pmserver | Compromised endpoint, rogue host on the endpoint network |
| A4 | **Console** (React SPA served by pmserver) | Admin browser | Attacker-controlled data shown in the UI: bundle fields, hostnames, inventory, report details |
| A5 | **pmagent** on endpoints | pmserver → endpoint (and local users) | Compromised pmserver or repository, MITM on the endpoint network, local non-admin user |
| A6 | **On-disk state**: repository (content-addressed, 0444), `pm.db`, audit hash chain, agent state and cache | OS-level | Local attacker or backup restore |

Lower priority: `pmctl` in the connected zone (catalog download, `acquire`). Treat its HTTP fetches from the vendor as untrusted input.

### 4.4 Abuse cases to attempt

(These come from `docs/02-architecture.md`. Each one should fail, and the failure should be visible in the transfer receipt or the audit log.)

**Bundle intake (A1)**
1. Tamper with a payload after signing: change a byte, truncate it, or append data. Expect a hash mismatch rejection.
2. Forge a manifest: no signature, a signature from an untrusted key, a trusted key used for a `source` it is not authorized for, or `key_id` pointing at a different key than the one that signed.
3. Replay: resend an accepted bundle, or reuse a `bundle_id`. Send a lower or equal `sequence`. Use `expires_at` in the past, `expires_at` more than 90 days after `created_at`, or `created_at` in the future.
4. Malformed archives: path traversal (`../`, absolute, backslash, `payload/..`), symlinks, hardlinks, devices, fifos, nested directories, duplicate entries, unlisted files, case-colliding names, Windows device names, trailing dots, alternate data streams (`a.msu:evil`), a tar bomb and declared sizes over `max_file_bytes` or `max_bundle_bytes`, more than `max_files`, a truncated tar, a huge `manifest.json`, and non-tar files with a `.pmb` extension.
5. Race the intake watcher: rename `*.part` into place, or replace or modify the file between hashing and extraction (TOCTOU). Use symlinked or junctioned inbox entries. Fill the disk.
6. Inject content: crafted strings in `title`, `vendor`, `source_url` and `package_id` (HTML/JS, very long, Unicode bidi characters) that the console or audit export later renders.
7. Check that nothing in `quarantine/` is ever served, and that a `vendor_signature.status: invalid` package is rejected.

**Admin API and console (A2, A4)**
8. Authorization: viewer → any write; user → revoke, exceptions, user management; admin → super admin accounts; bank roles → agent-version approve / reject / revoke / deploy; user or super admin → approving an agent-version deployment; the limited first-sign-in session (403 `mfa_enrollment_required`) → anything but enrolment; IDOR on `/api/bundles/{id}`, `/api/deployments/{id}` and `/api/endpoints/{id}`; mandatory `reason` bypass.
9. Authentication: password and TOTP brute force or timing (shared lockout: 5 failures → 15 min; per-IP rate limit), TOTP code replay (each code works once), recovery-code reuse, skipping the MFA step (the `offpatch_mfa` pre-auth cookie, 5 min), user enumeration, session fixation and CSRF (`X-Offpatch-CSRF`), OIDC `state`/`nonce`/redirect handling, logout and expiry. Static admin tokens were removed: `Authorization: Bearer` on `/api/*` must get 401. MFA secrets must be unreadable without `mfa.key` (AES-256-GCM at rest).
10. Path traversal in `/api/agent-setup/files/{name}` and in any other name parameter.
11. Approval integrity: approve a package, then try to change what is served for it, either through the API or by modifying the repository on disk, and check that the agent refuses it.
12. Audit: try to create, change or delete audit events through the API. Verify that `GET /api/audit/verify` detects direct DB edits. Check the export for injection (CSV/JSON).
13. Console: XSS through every field that comes from a bundle or an agent; clickjacking; CSP and security headers; open redirect in client routing (react-router was upgraded to 7.18.4 for GHSA-wrjc-x8rr-h8h6); that no credential or session token is kept in web storage (the session is an HttpOnly cookie).
14. Enrollment tokens: reuse, expiry, scope (groups and site) and visibility after creation.

**Agent API and agent (A3, A5)**
15. Device isolation: with endpoint A's secret or cert, try to read B's assignments, manifests or content, report results for B, or re-enroll as B.
16. Content access: `GET /api/agent/content/{sha256}` for unapproved, rejected or revoked packages, or for packages not targeted at this endpoint. Abuse the `Range` header (many ranges, overlapping or huge ones).
17. Report forgery: report `installed`/`verified` without installing. Inject large or invalid `detail` and `exit_code` values. Flood check-ins and reports. Send oversized inventory.
18. Malicious server or MITM against the agent: serve a modified payload, a manifest re-signed with an untrusted key, an assignment for a package with an older or tampered manifest, a redirect to a foreign origin, or a downgrade. The agent must refuse all of them and must never run anything other than `wusa`/`msiexec` on a verified file.
19. Local privilege escalation on the endpoint: ACLs on the agent state and cache dirs and on the service binary path; the downloaded-file window between hash check and install (TOCTOU); argument injection into `wusa`/`msiexec` through package fields.

**Platform**
20. TLS configuration (protocols, ciphers, cert validation on the agent side, mTLS enforcement), HTTP request smuggling and desync (relevant to the go1.27.1 net/http advisories), slowloris and large bodies, and the HTTP/2 abuse listed in section 2.2.

### 4.5 Out of scope

- The connected-zone vendor sources (Microsoft Update Catalog, vendor CDNs) and Microsoft's own package signing.
- Physical attacks on the transfer media or diode hardware, and social engineering.
- DoS by volumetric network flooding. Application-level resource exhaustion (items 5, 16, 17, 20) **is** in scope.
- Compromise of the signing key or an HSM in the acquisition zone. Assume that key is secure. Key-*use* checks (source authorization, `key_id` matching) are in scope.
- The IdP's own security (when OIDC is used) and the Windows OS hardening of hosts beyond the files and services offpatch installs.
- Production or customer environments: test only in the provided lab.

### 4.6 Rules and deliverables

- Report each finding with steps to reproduce, affected component (A1–A6), severity (CVSS 4.0) and a suggested fix. For bundle findings, attach the offending `.pmb`.
- Report any way to get unapproved or modified content executed on an endpoint **immediately**, without waiting for the final report.
- Fixed findings must get a regression test. For bundle and manifest bugs, add the input as a seed in `internal/manifest/testdata/fuzz/`.
