# offpatch — offline endpoint patch management (MVP)

Inventory, approve, distribute, install and verify patches (Windows, Linux, macOS) on endpoints that have **no internet access**. Updates cross a one-way transfer boundary as signed bundles, wait in quarantine until a human approves them, and are served only from an internal repository. Endpoints re-verify every signature and hash before installing.

Product workflow: [docs/00-product-workflow.md](docs/00-product-workflow.md) · Decisions: [docs/01-decisions.md](docs/01-decisions.md) · Architecture and threat model: [docs/02-architecture.md](docs/02-architecture.md) · State model: [docs/03-state-model.md](docs/03-state-model.md) · Bundle format: [docs/04-bundle-format.md](docs/04-bundle-format.md) · API: [docs/05-api.md](docs/05-api.md) · Roadmap: [docs/06-roadmap.md](docs/06-roadmap.md)

## Components

| Binary | Zone | What it does |
|---|---|---|
| `pmctl` | Connected acquisition | `keygen`, `build` signed `.pmb` bundles from downloaded vendor files, `inspect`, `send` through the transfer adapter |
| `pmserver` | Isolated management | Intake → quarantine → validation → catalog → approval → immutable repository → staged deployments → verification → hash-chained audit, plus the React console at `/` |
| `pmagent` | Endpoint | Windows (`.msu` / `.msi`), Linux (`.deb` / `.rpm`) and macOS (`.pkg`). Enrolls with a CSR and gets an mTLS certificate that renews automatically. Re-verifies signatures and hashes. Respects maintenance windows, bandwidth limits and reboot policy. Runs health checks and signed self-upgrades. Runs as a Windows service, systemd unit or launchd daemon. `-platform sim` simulates a Windows endpoint for demos. |

## Install: one command per machine

Build the release once (`make dist`, needs Go and Node) and check each tarball against `offpatch-<version>.SHA256SUMS` before carrying it anywhere. The installer (`install-ubuntu.sh`, Ubuntu 22.04 / 24.04 / 26.04, amd64 or arm64) needs `--role`; there is no default. From a release tarball nothing is downloaded or compiled, so it works in an offline zone. From a repository checkout it builds from source and installs Go (SHA-256 verified) if needed.

### Production layout: separate machines

| Machine | Zone | Command | What it holds |
|---|---|---|---|
| Acquisition host | Connected (internet) | `--role acquisition` | `pmctl auto` daily timer as user `offpatch-acq`, the **bundle signing key**. Never the root key. |
| Offline machine / HSM | None | `pmctl keygen -out root` (by hand) | The **root key** (`root.key`), kept offline. Only `root.pub` leaves it. |
| Management server | Isolated | `--role server` | `pmserver` (TLS + mTLS, internal CA), **public keys only**, daily verified backups. No private signing key. |
| Endpoints | Isolated | console one-liner (Windows) or `--role agent` | `pmagent` |

**1. Acquisition host (connected zone).**

```bash
tar xzf offpatch-<version>-linux-amd64.tar.gz && cd offpatch-<version>-linux-amd64
sudo ./install-ubuntu.sh --role acquisition
```

This creates `/etc/offpatch/keys/bundle.key` (readable only by `offpatch-acq`) and `bundle.pub`, writes `/etc/offpatch/acquire.json`, and runs `offpatch-acquire.timer` daily at 07:00. Bundles go to `/var/lib/offpatch-acq/outbox`; point `send.to` / `send.command` in `acquire.json` at your transfer gateway. It never creates a root key.

**2. Root key (offline machine).** `pmctl keygen -out root` on a machine that is never networked ([runbook 02 A2](docs/runbooks/02-acquisition-zone-setup-and-monthly-run.md)). Carry only `root.pub` out.

**3. Management server (isolated zone).** Copy `bundle.pub` (from step 1) and `root.pub` (from step 2), public keys only, then run:

```bash
sudo ./install-ubuntu.sh --role server --hosts pm.corp.internal,10.20.0.5 \
     --pubkey bundle.pub --root-pubkey root.pub \
     --audit-dir /mnt/audit-worm/offpatch --allow-from 10.20.0.0/16
```

- `--pubkey` is required on the first install. Public keys are copied to `/etc/offpatch/keys` and never replaced on later runs (rotate keys with a signed trust document, [runbook 03](docs/runbooks/03-key-rotation.md)). The installer refuses to run if any `*.key` file is in `/etc/offpatch/keys`.
- The break-glass admin token is **shown once** and not stored on the machine. Put it in the safe.
- `--hosts`: DNS names and IPs endpoints use to reach the server (they go into its certificate).
- `--audit-dir`: off-box / WORM storage for audit export. It warns loudly when this is on the same filesystem as the data.
- `--allow-from` (repeatable): ufw opens the port to these sources only.
- It installs `offpatch-backup.timer`: a daily verified `pmserver backup` into `/var/lib/offpatch-backup` (`--backup-dir`), keeping 14 (`--backup-keep`). Copy the backups off the machine. See [runbook 05](docs/runbooks/05-backup-and-restore.md).
- Whoever delivers bundles into `/var/lib/offpatch-server/inbox` (the transfer receiver) must be in group `offpatch-inbox`.

**4. Windows endpoints.** In the console, **Endpoints → Create enrollment token** (use *max uses* for several machines) and paste the one-line command it shows into **Windows PowerShell as Administrator** on each endpoint. The command pins the server's CA by SHA-256 fingerprint, downloads and verifies `pmagent.exe`, enrolls the machine and starts the `offpatch-agent` service. Re-running it with a new token repairs the install and keeps the enrollment; a machine enrolled with another server is re-enrolled. Ubuntu endpoints: `sudo ./install-ubuntu.sh --role agent --server https://pm.corp.internal:8443 --token enr_… --ca ca.pem --pubkey bundle.pub --root-pubkey root.pub`.

**Upgrades.** Re-run the same command with the same `--role` from the new release. Keys, certificates, token, `pmserver.json` and data are kept. On a server it first takes a verified backup (`/var/lib/offpatch-backup/pre-upgrade-*`; `--skip-backup` to skip) and keeps the previous binaries in `/opt/offpatch/bin.prev`. Port, TLS mode and audit directory come from the existing `pmserver.json`. A conflicting `--port`, `--insecure-lab` or `--audit-dir` is refused. A local agent that has self-upgraded past the release is not downgraded, and an upgraded local agent is restarted.

Other options: `--status`; `--uninstall` (it lists the secrets left on disk; `--purge` also deletes keys and data and asks for confirmation, or needs `--yes`); `--insecure-lab` (plain HTTP, first install only).

### Single-box lab: `--role all`

```bash
sudo ./install-ubuntu.sh --role all --hosts 192.168.88.129 [--with-agent]
```

Server, acquisition, signing key and root key on one machine, for evaluation only. It prints a warning to that effect. Acquisition still runs as its own user `offpatch-acq`, which can only drop files into the server inbox. The break-glass token is kept in `/etc/offpatch/admin-token.txt` (root only, 0600). `--with-agent` also enrolls the machine itself. Older lab installs, where everything ran as `offpatch`, are moved to this layout when you re-run with `--role all`. The lab queues console acquisition requests straight into `/var/lib/offpatch-acq/requests` (`acquisition_requests_dir`) and `offpatch-acquire-requests.path` fetches them right away with `pmctl auto -only-requests`; production roles keep the carried file (runbook 02).

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
