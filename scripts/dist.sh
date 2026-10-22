#!/usr/bin/env bash
# Build self-contained Linux release tarballs for the one-command install:
#   dist/offpatch-<version>-linux-<arch>.tar.gz
# Each holds install-ubuntu.sh, prebuilt pmserver/pmctl/pmagent, the agent
# binaries the console offers to endpoints (incl. pmagent.exe), VERSION, AGENT_VERSION and
# SHA256SUMS. On the target: tar xzf …; cd offpatch-*; sudo ./install-ubuntu.sh --role <role>
# The console (web/dist) must be built first (`make ui`); it is embedded in pmserver.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${VERSION:-$(tr -d ' \r\n' < VERSION 2>/dev/null)}
VERSION=${VERSION:-$(git describe --tags --always 2>/dev/null || echo dev)}
# Agent version: AGENT_VERSION env, else the default compiled into internal/agent (var Version).
# Written to AGENT_VERSION in the tarball; install-ubuntu.sh reads it (and never downgrades a
# local agent that has self-upgraded past it).
AGENT_VERSION=${AGENT_VERSION:-$(sed -n 's/^var Version = "\(.*\)"$/\1/p' internal/agent/agent.go | head -n 1)}
[ -n "$AGENT_VERSION" ] || { echo "cannot determine AGENT_VERSION" >&2; exit 1; }
[ -f web/dist/index.html ] || { echo "web/dist missing: run 'make ui' first" >&2; exit 1; }

export CGO_ENABLED=0
ldflags="-s -w -X offpatch/internal/agent.Version=$AGENT_VERSION -X offpatch/internal/server.Version=$VERSION"
build() { GOOS=$1 GOARCH=$2 go build -trimpath -ldflags "$ldflags" -o "$3" "./cmd/$4"; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
agents="$work/agent-dist"
mkdir -p "$agents" dist
build windows amd64 "$agents/pmagent.exe" pmagent
build linux amd64 "$agents/pmagent-linux-amd64" pmagent
build linux arm64 "$agents/pmagent-linux-arm64" pmagent
build darwin arm64 "$agents/pmagent-macos-arm64" pmagent

for arch in amd64 arm64; do
  name="offpatch-$VERSION-linux-$arch"
  root="$work/$name"
  mkdir -p "$root/bin/linux-$arch" "$root/bin/agent-dist"
  for c in pmserver pmctl pmagent; do build linux "$arch" "$root/bin/linux-$arch/$c" "$c"; done
  cp "$agents"/* "$root/bin/agent-dist/"
  cp install-ubuntu.sh README.md "$root/"
  chmod 0755 "$root/install-ubuntu.sh" "$root/bin/linux-$arch"/*
  echo "$VERSION" > "$root/VERSION"
  echo "$AGENT_VERSION" > "$root/AGENT_VERSION"
  ( cd "$root" && find bin install-ubuntu.sh VERSION AGENT_VERSION -type f | sort | xargs sha256sum > SHA256SUMS )
  tar --owner=0 --group=0 --numeric-owner -C "$work" -czf "dist/$name.tar.gz" "$name"
  echo "dist/$name.tar.gz"
done
( cd dist && sha256sum offpatch-"$VERSION"-linux-*.tar.gz > "offpatch-$VERSION.SHA256SUMS" )
echo "dist/offpatch-$VERSION.SHA256SUMS"
