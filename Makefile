.PHONY: all ui build windows test demo dist clean

all: ui build

ui:
	cd web && npm ci && npm run build

build:
	go build -o bin/pmctl ./cmd/pmctl
	go build -o bin/pmserver ./cmd/pmserver
	go build -o bin/pmagent ./cmd/pmagent

# Windows binaries for the agent (endpoints) and the acquisition tool.
windows:
	GOOS=windows GOARCH=amd64 go build -o bin/windows/pmagent.exe ./cmd/pmagent
	GOOS=windows GOARCH=amd64 go build -o bin/windows/pmctl.exe ./cmd/pmctl
	GOOS=windows GOARCH=amd64 go build -o bin/windows/pmserver.exe ./cmd/pmserver

test:
	go vet ./... && GOOS=windows go vet ./...
	go test -race ./...

demo: build
	./scripts/demo.sh

# One-command install tarballs: dist/offpatch-<version>-linux-{amd64,arm64}.tar.gz
dist: ui
	./scripts/dist.sh

clean:
	rm -rf bin demo

# ---- release artifacts (D2) ----
VERSION ?= 0.1.0
NFPM := go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0
LDFLAGS := -trimpath -ldflags "-s -w -X offpatch/internal/agent.Version=$(VERSION)"

.PHONY: release linux-packages
release: ui
	rm -rf dist/release && mkdir -p dist/release
	for t in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/arm64 darwin/amd64; do \
	  os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  for c in pmagent pmctl pmserver; do \
	    GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(LDFLAGS) -o dist/release/$$c-$(VERSION)-$$os-$$arch$$ext ./cmd/$$c || exit 1; \
	  done; \
	done
	$(MAKE) linux-packages
	cd dist/release && shasum -a 256 * > SHA256SUMS
	./scripts/sbom.sh
	@echo "release artifacts in dist/release (sign SHA256SUMS before carrying them into the isolated zone)"

linux-packages:
	mkdir -p dist/release
	for arch in amd64 arm64; do \
	  mkdir -p bin/linux-pkg && GOOS=linux GOARCH=$$arch CGO_ENABLED=0 go build $(LDFLAGS) -o bin/linux-pkg/pmagent ./cmd/pmagent || exit 1; \
	  for fmt in deb rpm; do \
	    GOARCH=$$arch VERSION=$(VERSION) $(NFPM) package -f packaging/linux/nfpm.yaml -p $$fmt -t dist/release/ || exit 1; \
	  done; \
	done
