# offpatch management server image. Build from the repository root:
#   docker build -f packaging/server/Dockerfile -t offpatch/pmserver:0.1.0 .
# Run (config + data on volumes; PKI inside the config volume):
#   docker run -d -p 8443:8443 -v /srv/offpatch/etc:/etc/offpatch-server -v /srv/offpatch/data:/var/lib/offpatch-server offpatch/pmserver:0.1.0
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
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/pmserver ./cmd/pmserver

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pmserver /usr/local/bin/pmserver
USER nonroot:nonroot
VOLUME ["/etc/offpatch-server", "/var/lib/offpatch-server"]
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/pmserver", "-config", "/etc/offpatch-server/pmserver.json"]
