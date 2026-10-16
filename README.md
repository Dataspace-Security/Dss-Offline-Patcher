# offpatch — offline endpoint patch management (MVP)

Inventory, approve, distribute, install and verify patches (Windows, Linux, macOS) on endpoints that have **no internet access**. Updates cross a one-way transfer boundary as signed bundles, wait in quarantine until a human approves them, and are served only from an internal repository. Endpoints re-verify every signature and hash before installing.

Product workflow: [docs/00-product-workflow.md](docs/00-product-workflow.md) · Decisions: [docs/01-decisions.md](docs/01-decisions.md) · Architecture and threat model: [docs/02-architecture.md](docs/02-architecture.md) · State model: [docs/03-state-model.md](docs/03-state-model.md) · Bundle format: [docs/04-bundle-format.md](docs/04-bundle-format.md) · API: [docs/05-api.md](docs/05-api.md) · Roadmap: [docs/06-roadmap.md](docs/06-roadmap.md)

## Components

| Binary | Zone | What it does |
|---|---|---|
| `pmctl` | Connected acquisition | `keygen`, `build` signed `.pmb` bundles from downloaded vendor files, `inspect`, `send` through the transfer adapter |
| `pmserver` | Isolated management | Intake → quarantine → validation → catalog → approval → immutable repository → staged deployments → verification → hash-chained audit, plus the React console at `/` |
| `pmagent` | Endpoint | Windows (`.msu` / `.msi`), Linux (`.deb` / `.rpm`) and macOS (`.pkg`). Enrolls with a CSR and gets an mTLS certificate that renews automatically. Re-verifies signatures and hashes. Respects maintenance windows, bandwidth limits and reboot policy. Runs health checks and signed self-upgrades. Runs as a Windows service, systemd unit or launchd daemon. `-platform sim` simulates a Windows endpoint for demos. |

## Quick start (single machine, simulated endpoints)

Requirements: Go 1.27.2+ (1.27.1 builds, but has standard-library CVEs), Node 20.19+ or 22.12+ (only to rebuild the console).

```bash
make ui        # build the console (web/dist, embedded into pmserver)
```

```bash
make demo      # builds binaries, runs the full flow, leaves pmserver on :8080
```

Open http://127.0.0.1:8080 and sign in with the admin token from `demo/tokens.txt`. Stop the server with:

```bash
kill $(cat demo/mgmt/pmserver.pid)
```

## Tests

```bash
make test
```

`internal/e2e` drives the real HTTP server with simulated agents through the §9 acceptance criteria:

- **Intake rejects:** a modified payload, a bad signature, an untrusted key, malformed JSON, a replayed sequence, tar traversal/links, and partial (`.part`) files.
- **Approval gate:** unapproved content cannot be deployed or downloaded. A reason is required. The operator role cannot approve.
- **Staged rollout:** pilot ring → advance → broad ring, auto-pause on failure threshold, resume, completion.
- **Status:** `pending_reboot` is not verified until after the reboot. Exception and not-applicable targeting work. Silent endpoints become `offline`, never compliant.
- **Endpoint tamper check:** the endpoint detects tampered repository content and refuses to install it.
- **Revoke:** revoking a package cancels its deployments.
- **Audit:** the lifecycle export is complete, the chain verifies, the table is append-only, and direct DB tampering is detected.

## Deploying to real Windows endpoints

The easiest path is the console: **Endpoints → Create enrollment token**. It shows step-by-step PowerShell commands with the server URL, token and signing key already filled in, plus download buttons for `bundle.pub` and `pmagent.exe`. To offer the agent binary for download, stage it on the server in `<data_dir>/agent-dist/` (the demo does this). The same guide is under **Agent setup** in the navigation.

Manually:

```bash
make windows   # bin/windows/pmagent.exe, pmctl.exe, pmserver.exe
```

On each endpoint (elevated):

```bash
pmagent.exe enroll -server https://pm.internal:8443 -token <enr_…> -pubkey bundle.pub -ca ca.pem
```

```bash
pmagent.exe service install
```

```bash
sc start offpatch-agent
```

> **Not yet validated on real Windows.** The Windows build compiles and vets. The `wusa`/`msiexec`/PowerShell integration follows Microsoft's documented exit codes, but it has only been exercised through the simulated platform. Run it on a test VM before any pilot.

## Status and remaining work

See [docs/06-roadmap.md](docs/06-roadmap.md) for item-by-item status and evidence. Before a production pilot, still to do:

- **Windows validation (B1).** The Windows agent and MSI have not yet run on a real Windows machine. Linux (deb/rpm, self-upgrade) has been validated in containers, and macOS inventory on a real Mac.
- **Go 1.27.2.** Build with it to pick up standard-library security fixes (`scripts/security-check.sh` flags 1.27.1).
- **Organisation decisions (section A).** Identity provider, transfer product, key custody, retention, and so on. Then a penetration test and a pilot.

More documentation: [admin guide](docs/07-admin-guide.md) · [runbooks](docs/runbooks/) · [acquisition](docs/08-acquisition.md) · [capacity](docs/09-capacity.md) · [security testing](docs/security/README.md) · [packaging](packaging/)
