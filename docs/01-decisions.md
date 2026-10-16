# 01 — Decision record (MVP)

Status: **accepted for MVP build**, pending Phase 0/2 sign-off by security and operations.
Date: 2026-10-16

| # | Decision | Choice | Rationale | Revisit when |
|---|---|---|---|---|
| D1 | First endpoint platform | **Windows** — `.msu` (via `wusa.exe`) and `.msi` (via `msiexec.exe`) | Most common enterprise target. | Linux/macOS demand validated. |
| D2 | Transfer boundary (MVP) | **Simulated one-way drop directory** behind a `transfer.Adapter` interface | Real gateway/diode product not yet chosen. A file drop matches how most diodes present to the receiver (files appear; nothing flows back). | Gateway product selected (Phase 5). |
| D3 | Language / runtime | **Go** for the management server, CLI and agent; **React + TypeScript** for the console | Static single binaries are easy to carry across an air gap. No runtime install on endpoints. | — |
| D4 | Storage | **SQLite** (pure-Go driver) + filesystem content store | Zero external dependencies inside the isolated zone. Fine for one site and up to roughly 5k endpoints. | Multi-site HA or >5k endpoints → PostgreSQL. |
| D5 | Bundle signing | **Ed25519** detached signature over the exact `manifest.json` bytes | Stdlib, fast, no canonicalisation pitfalls. | HSM/KMS integration (Phase 2 key-management design). |
| D6 | Hash algorithm | **SHA-256** for every payload file and for the bundle as transferred | Standard, matches vendor catalogues. | — |
| D7 | Replay protection | Monotonic `sequence` per `source` + `expires_at` + unique `bundle_id` | Stops a valid but old (vulnerable) bundle from being re-sent. | — |
| D8 | Admin auth (MVP) | Static bearer tokens (stored as SHA-256) mapped to user + role | Unblocks the vertical slice. | **Must** be replaced by IdP (OIDC/SAML or AD) + MFA before pilot. |
| D9 | Agent auth | One-time, expiring enrollment token → per-device secret (stored hashed server-side) | Unique device identity; nothing shared between devices. | mTLS device certificates (Phase 4). |
| D10 | Transport | HTTP(S); TLS configurable on server, CA pinning on agent | Lets the demo run on localhost. | TLS mandatory outside the lab. |
| D11 | Reboots | Agent **never** reboots in MVP; it reports `pending_reboot` | Reboot policy needs operations agreement. | Phase 6 reboot policy. |
| D12 | Rollback | **Not offered.** Recovery is a documented per-package-class procedure. | The workflow warns against implying universal rollback. | — |
| D13 | Content scanning | Optional external `scan_command` hook at intake (e.g. ClamAV `clamscan`) | Scanner choice belongs to the organisation. | Scanner selected. |
| D14 | Audit integrity | Append-only, SHA-256 **hash-chained** audit log with a verify endpoint | Tampering with any past event is detectable. | Signed periodic checkpoints exported off-box. |

## Prohibited flows (enforced in design, must also be enforced in network controls)

- Endpoint → internet: **denied**. The agent only talks to its configured server origin and refuses download URLs from any other origin. It has no vendor/Windows Update fallback.
- Isolated zone → connected zone: **none**. The intake service only reads files; it never writes back across the boundary.
- Received bundle → endpoint without approval: **impossible**. The repository serves only content addressed by approved packages.

## Open items requiring the organisation (cannot be decided in code)

1. Real gateway/diode product and interface (D2).
2. Identity provider and MFA (D8).
3. Key custody (HSM/KMS), rotation interval and compromise response (D5).
4. Scale, sites and bandwidth (D4).
5. Reboot policy and maintenance windows per endpoint class (D11).

## Revisions (2026-10-16, second pass)

| # | Was | Now |
|---|---|---|
| D1 | Windows only | Windows, plus Linux (`deb`/`rpm`) and macOS (`pkg`) agents. Package kinds: `msu`, `msi`, `deb`, `rpm`, `pkg`, `agent`. |
| D2 | Drop directory only | Adapter interface: `dropdir`, plus `command` (vendor upload CLI). Signed sender receipts are reconciled on the receiver. |
| D5 | Single bundle key in a file | Bundle keys may live in an HSM (`exec:` signer). An **offline root key** signs trust documents for rotation and revocation, which agents verify. |
| D8 | Static admin tokens | **OIDC SSO** with MFA enforcement, role mapping from IdP groups, sessions, user disable. Static tokens remain as break-glass and can be switched off (`allow_static_tokens: false`). Two-person approval per severity; separation of duties. |
| D9 | Bearer device secret | **mTLS client certificates** from the internal CA (`pmserver init-pki`), renewed automatically. The bearer secret is used only in `insecure_http` lab mode. |
| D10 | TLS optional | **TLS mandatory.** Plain HTTP requires the explicit `insecure_http` flag. |
| D11 | Never reboot | Default is still `never`. Deployments may choose `in_window` or `at_deadline`, governed by per-group maintenance windows that allow reboots. |
| D14 | Hash chain only | Plus Ed25519-signed checkpoints exported off-box (WORM), and retention pruning anchored to them. |
