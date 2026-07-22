## tokyo3-auth — build targets
##
## Usage: make <target>
##

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE               := github.com/abagile/tokyo3-auth
CMD_AUTHD            := ./cmd/authd
CMD_AUTH_AWS_CREDS   := ./cmd/auth-aws-creds

BIN_DIR              := bin
AUTHD_BIN            := $(BIN_DIR)/authd
AWS_CREDS_BIN        := $(BIN_DIR)/auth-aws-creds

GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION    := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w -X main.Version=$(VERSION)

GO      := go
GOFLAGS :=

IMAGE_NAME ?= abagile/tokyo3-auth
IMAGE_TAG  ?= $(VERSION)

COMPOSE_PROJECT_NAME     ?= tokyo3_auth
TOKYO3_SHARED_VOLUME     ?= tokyo3_shared_data
TOKYO3_BACKPLANE_NETWORK ?= tokyo3_backplane
TOKYO3_IDP_NETWORK       ?= tokyo3_idp
export COMPOSE_PROJECT_NAME TOKYO3_SHARED_VOLUME TOKYO3_BACKPLANE_NETWORK TOKYO3_IDP_NETWORK
SHARED_VOLUME            := $(COMPOSE_PROJECT_NAME)_shared_data

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        check \
        keygen gen-certs _sync-shared \
        docker-build docker-build-amd64 docker-build-cli docker-push \
        docker-up docker-up-mesh docker-down \
        install install-cli clean clean-all help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile authd + auth-aws-creds into ./bin/
build: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AUTHD_BIN) $(CMD_AUTHD)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AWS_CREDS_BIN) $(CMD_AUTH_AWS_CREDS)
	@echo "  built $(AUTHD_BIN) + $(AWS_CREDS_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

## build-linux: Cross-compile for Linux arm64 (Graviton, default)
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-linux-arm64 $(CMD_AUTHD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-aws-creds-linux-arm64 $(CMD_AUTH_AWS_CREDS)
	@echo "  built authd-linux-arm64 + auth-aws-creds-linux-arm64"

## build-linux-amd64: Cross-compile for Linux amd64
build-linux-amd64: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-linux-amd64 $(CMD_AUTHD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-aws-creds-linux-amd64 $(CMD_AUTH_AWS_CREDS)
	@echo "  built authd-linux-amd64 + auth-aws-creds-linux-amd64"

## build-darwin: Cross-compile for macOS arm64 (M-series)
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-darwin-arm64 $(CMD_AUTHD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-aws-creds-darwin-arm64 $(CMD_AUTH_AWS_CREDS)
	@echo "  built authd-darwin-arm64 + auth-aws-creds-darwin-arm64"

# ── Quality ───────────────────────────────────────────────────────────────────

## check: Full pre-commit sequence (gofmt + tidy + test + vet + staticcheck + gopls + govulncheck + deadcode)
check:
	gofmt -s -w .
	$(GO) mod tidy
	$(GO) test ./... -count=1
	$(GO) vet ./...
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...
	@out=$$(deadcode -test ./...); if [ -n "$$out" ]; then echo "$$out"; echo "deadcode: unreachable functions found (above)"; exit 1; fi

# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build the server Docker image (linux/arm64, default)
docker-build:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  --build-arg VERSION=$(VERSION) \
	  --target server \
	  -t $(IMAGE_NAME):$(IMAGE_TAG) \
	  -t $(IMAGE_NAME):latest \
	  .
	@echo "  built $(IMAGE_NAME):$(IMAGE_TAG)"

## docker-build-amd64: Build the server Docker image for linux/amd64
docker-build-amd64:
	docker build \
	  --platform linux/amd64 \
	  --build-arg TARGETARCH=amd64 \
	  --build-arg VERSION=$(VERSION) \
	  --target server \
	  -t $(IMAGE_NAME):$(IMAGE_TAG)-amd64 \
	  .

## docker-build-cli: Build a thin image containing the auth-aws-creds CLI helper
# The default server image deliberately omits it — developers `go install` it
# on their laptops rather than running in the cluster. The CLI image is offered
# for shops that prefer a containerized installation path (CI runners, dev
# containers). No ENTRYPOINT; users explicitly invoke it:
#   docker run --rm <image> auth-aws-creds login --issuer ... --client-id ...
docker-build-cli:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  --build-arg VERSION=$(VERSION) \
	  --target cli \
	  -t $(IMAGE_NAME)-cli:$(IMAGE_TAG) \
	  -t $(IMAGE_NAME)-cli:latest \
	  .
	@echo "  built $(IMAGE_NAME)-cli:$(IMAGE_TAG)"

## docker-push: Push image to registry (set IMAGE_NAME to your registry repo)
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_NAME):latest

# ── Dev rig (docker compose) ──────────────────────────────────────────────────

# Prepare shared Docker material.
_sync-shared: gen-certs
	@if [ ! -f shared/teleport/bootstrap.yml ]; then \
	    cp shared/teleport/bootstrap.yml.sample shared/teleport/bootstrap.yml; \
	    echo "  copied shared/teleport/bootstrap.yml.sample → bootstrap.yml"; \
	fi
	@if [ ! -f shared/teleport/teleport.yml ]; then \
	    cp shared/teleport/teleport.yml.sample shared/teleport/teleport.yml; \
	    echo "  copied shared/teleport/teleport.yml.sample → teleport.yml"; \
	fi
	@if [ ! -f shared/secrets/authd-master.key ]; then \
	    umask 077; \
	    mkdir -p shared/secrets; \
	    od -An -tx1 -N32 /dev/urandom | tr -d '[:space:]' > shared/secrets/authd-master.key; \
	    echo "  generated shared/secrets/authd-master.key"; \
	fi
	@docker volume create $(SHARED_VOLUME) 2>&1 >/dev/null || true
	@tar -cf - --exclude='*.sample' --exclude='gen.sh' -C shared . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "tar -xf - -C /shared && find /shared/postgres -name '*.sh' -exec chmod +x {} \;"
	@echo "  synced shared/ → /shared"

## keygen: Print a fresh random master key
keygen: build
	@$(AUTHD_BIN) keygen

## gen-certs: Generate Traefik edge cert material in shared/certs/
gen-certs:
	@bash shared/certs/gen.sh

## docker-up: Bring up the standalone Docker stack.
# Pre-creates the shared tokyo3_idp network (idempotent, same pattern as
# ../ca) so sibling stacks can reach auth.localhost when this rig is up.
docker-up: _sync-shared
	@docker network create $(TOKYO3_IDP_NETWORK) >/dev/null 2>&1 || true
	docker compose up -d --build --wait --remove-orphans
	@if [ -f shared/teleport/bootstrap.yml ] && ! grep -q 'CHANGE_ME_' shared/teleport/bootstrap.yml; then \
	    echo "  applying shared/teleport/bootstrap.yml (github connector)…"; \
	    docker compose exec -T teleport \
	        /usr/local/bin/tctl -c /shared/teleport/teleport.yml create --force -f /shared/teleport/bootstrap.yml; \
	    echo "  github connector applied — sign in at https://teleport.localhost"; \
	else \
	    echo ""; \
	    echo "  ⚠ shared/teleport/bootstrap.yml still has placeholder client credentials."; \
	    echo "    Create the Teleport OAuth client in auth, edit bootstrap.yml, then re-run 'make docker-up'."; \
	fi

## docker-up-mesh: Bring up auth against the CA-owned tokyo3 mesh.
docker-up-mesh: _sync-shared
	docker compose -f docker-compose.mesh.yml up -d --build --wait --remove-orphans
	@if [ -f shared/teleport/bootstrap.yml ] && ! grep -q 'CHANGE_ME_' shared/teleport/bootstrap.yml; then \
	    echo "  applying shared/teleport/bootstrap.yml (github connector)…"; \
	    docker compose -f docker-compose.mesh.yml exec -T teleport \
	        /usr/local/bin/tctl -c /shared/teleport/teleport.yml create --force -f /shared/teleport/bootstrap.yml; \
	    echo "  github connector applied — sign in at https://teleport.localhost"; \
	else \
	    echo ""; \
	    echo "  ⚠ shared/teleport/bootstrap.yml still has placeholder client credentials."; \
	    echo "    Create the Teleport OAuth client in auth, edit bootstrap.yml, then re-run 'make docker-up-mesh'."; \
	fi

## docker-down: Stop all compose services (safe to run in any mode)
docker-down:
	docker compose down
	docker compose -f docker-compose.mesh.yml down 2>/dev/null || true

# ── Install / Clean ───────────────────────────────────────────────────────────

## install: Install authd to GOPATH/bin (or ~/go/bin)
install:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_AUTHD)
	@echo "  installed authd"

## install-cli: Install the auth-aws-creds CLI helper to GOPATH/bin (or ~/go/bin)
install-cli:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_AUTH_AWS_CREDS)
	@echo "  installed auth-aws-creds"

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)

## clean-all: Stop compose stacks, remove volumes, binaries, and generated edge certs
clean-all: clean
	docker compose down --remove-orphans -v 2>/dev/null || true
	docker compose -f docker-compose.mesh.yml down --remove-orphans -v 2>/dev/null || true
	docker volume rm $(SHARED_VOLUME) 2>/dev/null || true
	rm -f shared/certs/traefik*.crt shared/certs/traefik*.key shared/certs/ca.crt
	@echo "  removed compose stacks, volumes, and generated Traefik edge certs"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help
help:
	@awk '/^##/ { \
	  line=$$0; sub(/^## ?/, "", line); \
	  if (line ~ /^[a-z0-9_.-]+:/) { \
	    target=line; sub(/:.*/, "", target); \
	    desc=line; sub(/^[^:]+:[[:space:]]*/, "", desc); \
	    names[++n]=target; docs[target]=desc; \
	  } else header[++h]=line; \
	} END { \
	  for (i=1; i<=h; i++) print header[i]; \
	  for (i=1; i<=n; i++) for (j=i+1; j<=n; j++) if (names[j] < names[i]) { tmp=names[i]; names[i]=names[j]; names[j]=tmp } \
	  for (i=1; i<=n; i++) printf "  %-22s %s\n", names[i], docs[names[i]]; \
	}' $(MAKEFILE_LIST)
