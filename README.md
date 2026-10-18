# offpatch — offline endpoint patch management (MVP)

Inventory, approve, distribute, install and verify patches (Windows, Linux, macOS) on endpoints that have **no internet access**. Updates cross a one-way transfer boundary as signed bundles, wait in quarantine until a human approves them, and are served only from an internal repository. Endpoints re-verify every signature and hash before installing.

Product workflow: [docs/00-product-workflow.md](docs/00-product-workflow.md) · Decisions: [docs/01-decisions.md](docs/01-decisions.md) · Architecture and threat model: [docs/02-architecture.md](docs/02-architecture.md) · State model: [docs/03-state-model.md](docs/03-state-model.md) · Bundle format: [docs/04-bundle-format.md](docs/04-bundle-format.md) · API: [docs/05-api.md](docs/05-api.md) · Roadmap: [docs/06-roadmap.md](docs/06-roadmap.md)

## Components

| Binary | Zone | What it does |
|---|---|---|
| `pmctl` | Connected acquisition | `keygen`, `build` signed `.pmb` bundles from downloaded vendor files, `inspect`, `send` through the transfer adapter |
| `pmserver` | Isolated management | Intake → quarantine → validation → catalog → approval → immutable repository → staged deployments → verification → hash-chained audit, plus the React console at `/` |
| `pmagent` | Endpoint | Windows (`.msu` / `.msi`), Linux (`.deb` / `.rpm`) and macOS (`.pkg`). Enrolls with a CSR and gets an mTLS certificate that renews automatically. Re-verifies signatures and hashes. Respects maintenance windows, bandwidth limits and reboot policy. Runs health checks and signed self-upgrades. Runs as a Windows service, systemd unit or launchd daemon. `-platform sim` simulates a Windows endpoint for demos. |

## Install (production, one command)

Build the release once (`make dist`, needs Go and Node) and check the tarball against `offpatch-<version>.SHA256SUMS`. On **one Ubuntu server** (22.04 / 24.04 / 26.04, amd64 or arm64) with internet access for the downloader:

```bash
tar xzf offpatch-<version>-linux-amd64.tar.gz && cd offpatch-<version>-linux-amd64
sudo ./install-ubuntu.sh
```

No arguments = `--role all`, the single-server production install. It installs and starts:

- `pmserver` (console + agent API, TLS with an internal CA and mTLS for agents) as user `offpatch` on port 8443, with a certificate for this machine's address (the IPv4 of the default route, or an address of this machine given in `--hosts`).
- The built-in super admin `superadmin@dataspacesecurity.com` (`--admin-email` to change) with the vendor's default password (vendor handbook; only its hash is in `pmserver`). The console asks for a new password at the first sign-in.
- The downloader `pmctl auto` as its own user `offpatch-acq`, **every hour** (`offpatch-acquire.timer`; when the previous run is still downloading, the new one skips cleanly), plus a watcher that fetches console acquisition requests right away. It holds the bundle signing key and can only drop files into the server inbox.
- A daily verified backup (`offpatch-backup.timer`, 02:30, keeps 14) into `/var/lib/offpatch-backup`. Copy it off the machine: it holds the CA key.

Hardening applied by default:

- **Egress lock** (nftables table `inet offpatch_egress` in `/etc/nftables.d/offpatch.nft`, loaded at boot by `offpatch-egress.service`): only `offpatch-acq` may open new outbound connections, to TCP 80/443 and DNS (53). The server account `offpatch` may open new connections to loopback only; its replies to agents and browsers are not affected. Other users, root and SSH are not touched. Refusals are logged as `offpatch-egress denied:` (`journalctl -k`). The lock also blocks outbound SSO (OIDC), SMTP and webhooks from `pmserver`, and a downloader proxy on a port other than 80/443: add your own rule for those, or use `--no-egress-lock` (not recommended; `--egress-lock` turns it back on).
- **Root key**: the offline root key is created as `/etc/offpatch/keys/root.key`, and the summary tells you to move it off the server: mount offline media and run `sudo ./install-ubuntu.sh --export-root-key /media/usb`. It copies `root.key`, `root.pub` and `root.sha256`, verifies the copy, asks you to type `DELETE`, then shreds the server copy (`root.pub` stays). With `--root-pubkey root.pub` (root key made on an offline machine, [runbook 02 A2](docs/runbooks/02-acquisition-zone-setup-and-monthly-run.md)) no root key is created.
- **Firewall**: if ufw is active, the console port is opened only from the `--allow-from` CIDRs (repeatable) or, without them, from the local subnet of the server's address, and the summary shows which. The installer never enables ufw (that could cut off SSH); when ufw is inactive it prints the commands to do so.
- **Compliance disclosure**: `pmserver.json` gets `"deployment_mode": "single-server"`. The compliance report states it in the scope limitations and in PM-04: the downloader runs on the management server, and egress is limited to the downloader account by host firewall rules. The acquisition-stale alert fires after 3 h without a status report (`acquisition_stale_after`).

Then, in the console (the summary prints the URL with the real IP):

1. Sign in and change the password.
2. **Settings → Users**: create the bank's Admin.
3. **Endpoints → Create enrollment token** → run the PowerShell line on each PC (Windows PowerShell as Administrator). PCs need **TCP 8443 to the server's IP**; nothing connects to the PCs. The line pins the server's CA by SHA-256 fingerprint, downloads and verifies `pmagent.exe`, enrolls the PC and starts the `offpatch-agent` service. Use *max uses* for several PCs. Re-running it with a new token repairs the install.
4. **Patches → Needed → Import**, **Catalog → Approve**, **Patch this** (2 approvals).

First-install options: `--hosts "pm.bank.local,10.20.0.5"` (names and IPs for the certificate), `--port`, `--allow-from CIDR`, `--audit-dir /mnt/worm/offpatch` (off-box / WORM audit export; it warns when it is on the data filesystem), `--backup-dir`, `--backup-keep`, `--root-pubkey`, `--with-agent` (also enroll this server as an endpoint). From a release tarball nothing is downloaded or compiled. From a repository checkout it builds from source and installs Go (SHA-256 verified) if needed.

**Upgrades.** Re-run `sudo ./install-ubuntu.sh` from the new release; the role of the earlier install is remembered. Keys, certificates, `pmserver.json` and data are kept. It first takes a verified backup (`/var/lib/offpatch-backup/pre-upgrade-*`; `--skip-backup` to skip) and keeps the previous binaries in `/opt/offpatch/bin.prev`. Port, TLS mode and audit directory come from the existing `pmserver.json`; a conflicting `--port`, `--insecure-lab` or `--audit-dir` is refused. An upgrade switches the acquisition timer to hourly and adds `deployment_mode` when it is missing (binaries older than this release refuse that key: when rolling back to `bin.prev`, remove it from `pmserver.json`). An upgrade from a release with static admin tokens removes `admin_tokens` / `allow_static_tokens` and shreds `admin-token.txt` / `admin-token.sha256`. A local agent that has self-upgraded past the release is not downgraded.

Other options: `--status` (services, egress lock, root key still on disk); `--uninstall` (removes the services and the egress lock and lists the secrets left on disk; `--purge` also deletes keys and data and asks for confirmation, or needs `--yes`); `--insecure-lab` (plain HTTP, first install only, isolated lab only).

### Stricter alternative: two-machine layout

On a single server the internet-facing downloader runs next to the server's data, separated by accounts and the egress lock. Running the downloader on its own machine in the connected zone, with a one-way transfer to an isolated server, is stricter: a compromised downloader then reaches no server data. Use one role per machine:

| Machine | Zone | Command | What it holds |
|---|---|---|---|
| Acquisition host | Connected (internet) | `--role acquisition` | `pmctl auto` hourly timer as user `offpatch-acq`, the **bundle signing key**. Never the root key. |
| Offline machine / HSM | None | `pmctl keygen -out root` (by hand) | The **root key** (`root.key`), kept offline. Only `root.pub` leaves it. |
| Management server | Isolated | `--role server` | `pmserver` (TLS + mTLS, internal CA), **public keys only**, daily verified backups. No private signing key. |
| Endpoints | Isolated | console one-liner (Windows) or `--role agent` | `pmagent` |

**1. Acquisition host (connected zone).** `sudo ./install-ubuntu.sh --role acquisition` creates `/etc/offpatch/keys/bundle.key` (readable only by `offpatch-acq`) and `bundle.pub`, writes `/etc/offpatch/acquire.json`, and runs `offpatch-acquire.timer` every hour. Bundles go to `/var/lib/offpatch-acq/outbox`; point `send.to` / `send.command` in `acquire.json` at your transfer gateway. It never creates a root key.

**2. Root key (offline machine).** `pmctl keygen -out root` on a machine that is never networked ([runbook 02 A2](docs/runbooks/02-acquisition-zone-setup-and-monthly-run.md)). Carry only `root.pub` out.

**3. Management server (isolated zone).** Copy `bundle.pub` and `root.pub` (public keys only), then run:

```bash
sudo ./install-ubuntu.sh --role server --hosts pm.corp.internal,10.20.0.5 \
     --pubkey bundle.pub --root-pubkey root.pub \
     --audit-dir /mnt/audit-worm/offpatch --allow-from 10.20.0.0/16
```

- `--pubkey` is required on the first install. Public keys are copied to `/etc/offpatch/keys` and never replaced on later runs (rotate keys with a signed trust document, [runbook 03](docs/runbooks/03-key-rotation.md)). The installer refuses to run if any `*.key` file is in `/etc/offpatch/keys`.
- `pmserver.json` gets `"deployment_mode": "two-machine"`. The acquisition-stale alert stays at 26 h, because status reports cross the transfer only when files are carried.
- Whoever delivers bundles into `/var/lib/offpatch-server/inbox` (the transfer receiver) must be in group `offpatch-inbox`.
- Super admin, backups, `--allow-from` and ufw work as in the single-server install. There is no egress lock (the server has no downloader); restrict egress in the network.

**4. Endpoints.** As in the single-server install (Endpoints → Create enrollment token). Ubuntu endpoints: `sudo ./install-ubuntu.sh --role agent --server https://pm.corp.internal:8443 --token enr_… --ca ca.pem --pubkey bundle.pub --root-pubkey root.pub`.

## Quick start (single machine, simulated endpoints)

Requirements: Go 1.27.2+ (1.27.1 builds, but has standard-library CVEs), Node 20.19+ or 22.12+ (only to rebuild the console).

```bash
make ui        # build the console (web/dist, embedded into pmserver)
```

```bash
make demo      # builds binaries, runs the full flow, leaves pmserver on :8080
```

Open http://127.0.0.1:8080 and sign in with a user from `demo/users.txt` (the demo super admin, or `alice`, a `user` with an authenticator secret for MFA). Stop the server with:

```bash
kill $(cat demo/mgmt/pmserver.pid)
```

## Tests

```bash
make test
```

`internal/e2e` drives the real HTTP server with simulated agents through the §9 acceptance criteria:

- **Intake rejects:** a modified payload, a bad signature, an untrusted key, malformed JSON, a replayed sequence, tar traversal/links, and partial (`.part`) files.
- **Approval gate:** unapproved content cannot be deployed or downloaded. A reason is required. A viewer cannot approve.
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

More documentation: [admin guide](docs/07-admin-guide.md) · [runbooks](docs/runbooks/) · [acquisition](docs/08-acquisition.md) · [capacity](docs/09-capacity.md) · [auditor compliance report](docs/10-compliance-report.md) · [security testing](docs/security/README.md) · [packaging](packaging/)
