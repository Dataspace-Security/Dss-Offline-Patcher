# SQLite container images

The management server embeds SQLite. It creates `pm.db` beneath the configured
`data_dir` on first startup. No PostgreSQL or Redis service is required.

Build from the repository root:

```sh
docker build -f packaging/server/Dockerfile \
  --build-arg VERSION=0.9.0-sqlite --build-arg AGENT_VERSION=0.9.0 \
  -t offpatch/pmserver:0.9.0-sqlite .
docker build --target tools -f packaging/server/Dockerfile \
  --build-arg VERSION=0.9.0-sqlite --build-arg AGENT_VERSION=0.9.0 \
  -t offpatch/tools:0.9.0-sqlite .
```

The server image runs as UID/GID 65532 with native TLS on 8443. It includes only
`pmserver` and the embedded React console — no `pmctl` and no agent binaries, so
a compromised server container has neither the acquisition tool nor the bundle
signing key workflow available (docs/02-architecture.md's acquisition/management
separation holds inside containers too). The tools image (built with
`--target tools`) holds `pmctl` (its entrypoint, for `pmctl auto` acquisition
scheduling) and the Windows amd64, Linux amd64/arm64 and macOS arm64 agent
binaries under `/opt/offpatch/agent-dist`, plus `pmserver` itself so that
`docker run --entrypoint /usr/local/bin/pmserver offpatch/tools:<version> ...`
can run one-off `init-pki`/`backup`/`verify-backup` against the shared volumes
(the tools image's own `pmctl` entrypoint does not implement those — they are
`pmserver` subcommands). Never give the tools image's acquisition-zone volumes
(signing key, outbox) to the pmserver container, and never run the tools image
on the pmserver container's own network.

Initialize configuration, trust keys and PKI using runbook 01 before starting.
Persistent configuration and data volumes must be writable by UID/GID 65532
during initialization. `pmserver` serves agent downloads from
`<data_dir>/agent-dist/` (the data volume), not from the tools image's
`/opt/offpatch/agent-dist` — copy the binaries from the tools image into that
volume once, e.g.:

```sh
docker create --name offpatch-tools-tmp offpatch/tools:<version>
docker cp offpatch-tools-tmp:/opt/offpatch/agent-dist/. /srv/offpatch/data/agent-dist/
docker rm offpatch-tools-tmp
```

Always persist these paths outside the container layer:

| Container path | Contents |
|---|---|
| `/etc/offpatch-server` | Configuration, trust keys and PKI; mount read-only after initialization where possible |
| `/var/lib/offpatch-server` | `pm.db`, repository, inbox/quarantine, MFA/audit keys and distributed agent binaries |
| `/backup` | Verified application backup snapshots; mount when running backup commands |

Run only one management instance against the database. Back up with
`pmserver backup -config /etc/offpatch-server/pmserver.json -recipients /etc/offpatch-server/backup-recipients.txt -dir /backup/<timestamp>`
and verify with `pmserver verify-backup -config /etc/offpatch-server/pmserver.json -dir /backup/<timestamp>`
(`-recipients` has no absolute default, so it must always be passed explicitly here; see runbook 05).
Copy encrypted backups off the host. Do not copy the live SQLite file in place of its backup API.

The runtime has no shell or HTTP probe utility. Probe HTTPS `/auth/config` with
the application's CA. Its response must be 200. Temps' regular HTTP proxy cannot
replace the native mTLS transport for agent connections; retain direct private
access or verify a suitable TCP passthrough route before enrolling endpoints.

No keys, initial credentials or database files are baked into these images.
