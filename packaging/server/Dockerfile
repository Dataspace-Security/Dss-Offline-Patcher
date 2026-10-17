# offpatch management server image. Build from the repository root:
#   docker build -f packaging/server/Dockerfile --build-arg VERSION=0.1.0 -t offpatch/pmserver:0.1.0 .
#
# Volumes (container layout, see docs/runbooks/README.md "Paths by install method"):
#   /etc/offpatch-server      pmserver.json, bundle.pub, root.pub, pki/ (CA + server cert)
#   /var/lib/offpatch-server  data_dir (db, inbox, repository, audit-signing key)
# The image runs as distroless "nonroot" (UID/GID 65532). Before the first start:
#   install -d -m 0700 -o 65532 -g 65532 /srv/offpatch/etc /srv/offpatch/data
#   (put pmserver.json and the public keys in /srv/offpatch/etc, owned 65532, mode 0600/0644)
#   docker run --rm -u 65532:65532 -v /srv/offpatch/etc:/etc/offpatch-server offpatch/pmserver:0.1.0 \
#     init-pki -dir /etc/offpatch-server/pki -hosts pm.corp.internal,10.20.0.5
# Run:
#   docker run -d --name pmserver --read-only -p 8443:8443 \
#     -v /srv/offpatch/etc:/etc/offpatch-server -v /srv/offpatch/data:/var/lib/offpatch-server \
#     offpatch/pmserver:0.1.0
# The transfer receiver writes into /srv/offpatch/data/inbox on the host: give it write access
# to that directory only (e.g. setgid group shared with UID 65532).
#
# Health check: the image has no shell or curl, so there is no Docker HEALTHCHECK. Probe from the
# orchestrator instead: HTTPS GET /auth/config on the listen port must return 200 (Kubernetes:
# httpGet with scheme HTTPS).
# Backups: mount a third volume (e.g. -v /srv/offpatch/backup:/backup, owned 65532) and run
#   docker exec pmserver /usr/local/bin/pmserver backup -config /etc/offpatch-server/pmserver.json \
#     -dir /backup/$(date -u +%Y%m%dT%H%M%SZ)
# from a host timer (runbook 05).
#
# For an isolated network, build here, `docker save` the image and carry it
# across the boundary like any other artifact.
FROM node:22-alpine AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
ARG VERSION=dev
ARG AGENT_VERSION=0.1.0
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X offpatch/internal/server.Version=${VERSION} -X offpatch/internal/agent.Version=${AGENT_VERSION}" \
      -o /out/pmserver ./cmd/pmserver

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="offpatch pmserver" org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/pmserver /usr/local/bin/pmserver
USER nonroot:nonroot
VOLUME ["/etc/offpatch-server", "/var/lib/offpatch-server"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pmserver"]
CMD ["-config", "/etc/offpatch-server/pmserver.json"]
