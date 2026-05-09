## tokyo3-auth — build targets
##
## Usage:
##   make build             Build authd + auth-audit binaries to ./bin/
##   make run               Start authd with dev defaults (starts Postgres + NATS via compose)
##   make run-mtls          Start authd with mTLS (cert auth, no password in DSN)
##   make run-audit         Start auth-audit (audit projection consumer) with dev defaults
##   make run-audit-mtls    Start auth-audit with mTLS
##   make keygen            Generate an AUTH_MASTER_KEY
##   make check             Full pre-commit sequence (fmt + test + staticcheck + gopls + govulncheck)
##   make docker-build      Build Docker image
##   make docker-up         Start with docker compose (Postgres + NATS + auth + auth-audit)
##   make docker-up-mtls    Start with docker compose + mTLS overlay (auto-generates certs)
##   make docker-down       Stop docker compose (overlay-aware; safe in any mode)
##   make docker-down-all   Stop + remove orphan containers AND named volumes (destroys DB data)
##   make gen-certs         Generate mTLS certs in certs/ (manual; auto-run by run-mtls/docker-up-mtls)
##   make clean             Remove ./bin/
##   make clean-all         Remove ./bin/, certs/*.crt, certs/*.key, certs/ca.srl, and .env
##   make test              Run tests
##   make help              Show this help

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE         := github.com/abagile/tokyo3-auth
CMD_AUTHD      := ./cmd/authd
CMD_AUTH_AUDIT := ./cmd/auth-audit

BIN_DIR         := bin
AUTHD_BIN       := $(BIN_DIR)/authd
AUTH_AUDIT_BIN  := $(BIN_DIR)/auth-audit

GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION    := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w

GO      := go
GOFLAGS :=

IMAGE_NAME    ?= abagile/tokyo3-auth
IMAGE_TAG     ?= $(VERSION)
AUTH_PORT     ?= 8443
AUTH_ADDR     ?= :$(AUTH_PORT)
POSTGRES_PORT ?= 35432
AUDIT_DB_PORT ?= 35433
NATS_PORT     ?= 34222

# Docker Compose project name (defaults to directory basename, matching Compose behaviour).
# Used to derive the shared named volume name for pre-population via tar pipe (no bind mounts).
COMPOSE_PROJECT := $(notdir $(CURDIR))
SHARED_VOLUME   := $(COMPOSE_PROJECT)_shared-data

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        run run-mtls run-audit run-audit-mtls keygen gen-certs \
        _gen-env _sync-pg-scripts _sync-certs \
        test test-verbose tidy vet lint check \
        docker-build docker-build-amd64 docker-push docker-up docker-up-mtls docker-down docker-down-all docker-logs \
        install clean clean-all help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile authd + auth-audit into ./bin/
build: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AUTHD_BIN)      $(CMD_AUTHD)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AUTH_AUDIT_BIN) $(CMD_AUTH_AUDIT)
	@echo "  built $(AUTHD_BIN) and $(AUTH_AUDIT_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

## build-linux: Cross-compile for Linux arm64 (Graviton, default)
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-linux-arm64      $(CMD_AUTHD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-audit-linux-arm64 $(CMD_AUTH_AUDIT)
	@echo "  built authd-linux-arm64 and auth-audit-linux-arm64"

## build-linux-amd64: Cross-compile for Linux amd64
build-linux-amd64: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-linux-amd64      $(CMD_AUTHD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-audit-linux-amd64 $(CMD_AUTH_AUDIT)
	@echo "  built authd-linux-amd64 and auth-audit-linux-amd64"

## build-darwin: Cross-compile for macOS arm64 (M-series)
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-darwin-arm64      $(CMD_AUTHD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/auth-audit-darwin-arm64 $(CMD_AUTH_AUDIT)
	@echo "  built authd-darwin-arm64 and auth-audit-darwin-arm64"

# ── Internal helpers ──────────────────────────────────────────────────────────

# Generate .env with dev defaults on first run. Used by run / run-mtls.
# DSNs use password auth; the mTLS run target overrides with cert-auth DSNs at process launch time.
_gen-env: build
	@if [ ! -f .env ]; then \
	    KEY=$$($(AUTHD_BIN) keygen); \
	    echo "AUTH_MASTER_KEY=$$KEY"                                                                                                            > .env; \
	    echo "AUTH_ISSUER=https://auth.localhost:$(AUTH_PORT)"                                                                                 >> .env; \
	    echo "AUTH_ADDR=$(AUTH_ADDR)"                                                                                                          >> .env; \
	    echo "POSTGRES_PORT=$(POSTGRES_PORT)"                                                                                                  >> .env; \
	    echo "AUTH_ADMIN_PASSWORD=changeme"                                                                                                    >> .env; \
	    echo "AUTH_APP_PASSWORD=changeme"                                                                                                      >> .env; \
	    echo "AUTH_AUDIT_DB_PASSWORD=changeme"                                                                                                 >> .env; \
	    echo "AUTH_ADMIN_DATABASE_URL=postgres://$${AUTH_ADMIN_DB_USERNAME:-auth_admin}:changeme@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=disable" >> .env; \
	    echo "AUTH_DATABASE_URL=postgres://$${AUTH_APP_USERNAME:-auth_app}:changeme@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=disable"        >> .env; \
	    echo "AUTH_ALLOW_REGISTRATION=true"                                                                                                    >> .env; \
	    echo "  generated .env"; \
	fi

# Push local postgres/ scripts into shared-data:/shared/pg-scripts (no bind mount needed).
# Re-runs on every invoke so changes to init scripts are always picked up.
_sync-pg-scripts:
	@docker volume create $(SHARED_VOLUME) 2>&1 >/dev/null || true
	@tar -cf - -C postgres . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "mkdir -p /shared/pg-scripts && tar -xf - -C /shared/pg-scripts && chmod +x /shared/pg-scripts/*.sh"

# Generate leaf certs if absent, then push local certs/ + mkcert's root CA
# into shared-data:/shared/certs (root CA staged as ca.crt for compose mounts;
# removed locally after the volume copy so certs/ stays free of the CA).
_sync-certs:
	@if [ ! -f certs/authd-server.crt ]; then bash certs/gen.sh; fi
	@docker volume create $(SHARED_VOLUME) 2>&1 >/dev/null || true
	@cp $$(mkcert -CAROOT)/rootCA.pem certs/ca.crt
	@tar -cf - -C certs . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "mkdir -p /shared/certs && tar -xf - -C /shared/certs"
	@rm -f certs/ca.crt

# ── Dev ───────────────────────────────────────────────────────────────────────

## run: Build and start authd with dev defaults (auto-generates .env on first run)
run: _gen-env _sync-pg-scripts
	@docker compose up -d db nats natsbox --wait 2>/dev/null || true
	@export $$(grep -v '^#' .env | xargs) && \
	    AUTH_NATS_URL=nats://nats.localhost:$(NATS_PORT) \
	    $(AUTHD_BIN) serve

## run-mtls: Build and start authd with mTLS (cert auth; overrides DSNs — no password)
run-mtls: _gen-env _sync-pg-scripts _sync-certs
	@docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d db nats natsbox --wait 2>/dev/null || true
	@CA_PEM=$$(mkcert -CAROOT)/rootCA.pem; \
	    export $$(grep -v '^#' .env | xargs) && \
	    AUTH_API_CERT=certs/authd-server.crt \
	    AUTH_API_KEY=certs/authd-server.key \
	    AUTH_ADMIN_DB_CERT=certs/authd-admin-db-client.crt \
	    AUTH_ADMIN_DB_KEY=certs/authd-admin-db-client.key \
	    AUTH_ADMIN_DB_CA=$$CA_PEM \
	    AUTH_ADMIN_DATABASE_URL=postgres://$${AUTH_ADMIN_DB_USERNAME:-auth_admin}@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=verify-full \
	    AUTH_DB_CERT=certs/authd-app-db-client.crt \
	    AUTH_DB_KEY=certs/authd-app-db-client.key \
	    AUTH_DB_CA=$$CA_PEM \
	    AUTH_DATABASE_URL=postgres://$${AUTH_APP_USERNAME:-auth_app}@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=verify-full \
	    AUTH_SCIM_CERT=certs/authd-scim-client.crt \
	    AUTH_SCIM_KEY=certs/authd-scim-client.key \
	    AUTH_SCIM_CA=$$CA_PEM \
	    AUTH_NATS_URL=tls://nats.localhost:$(NATS_PORT) \
	    AUTH_NATS_CERT=certs/authd-nats-client.crt \
	    AUTH_NATS_KEY=certs/authd-nats-client.key \
	    AUTH_NATS_CA=$$CA_PEM \
	    $(AUTHD_BIN) serve

## run-audit: Build and start auth-audit with dev defaults (uses the same .env)
run-audit: _gen-env _sync-pg-scripts
	@docker compose up -d audit-db nats natsbox --wait 2>/dev/null || true
	@export $$(grep -v '^#' .env | xargs) && \
	    AUTH_AUDIT_NATS_URL=nats://nats.localhost:$(NATS_PORT) \
	    AUTH_AUDIT_DATABASE_URL=postgres://$${AUTH_AUDIT_DB_USERNAME:-auth_audit}:$${AUTH_AUDIT_DB_PASSWORD:-changeme}@audit-db.localhost:$(AUDIT_DB_PORT)/auth_audit?sslmode=disable \
	    $(AUTH_AUDIT_BIN) consume

## run-audit-mtls: Build and start auth-audit with mTLS
run-audit-mtls: _gen-env _sync-pg-scripts _sync-certs
	@docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d audit-db nats natsbox --wait 2>/dev/null || true
	@CA_PEM=$$(mkcert -CAROOT)/rootCA.pem; \
	    export $$(grep -v '^#' .env | xargs) && \
	    AUTH_AUDIT_NATS_URL=tls://nats.localhost:$(NATS_PORT) \
	    AUTH_AUDIT_NATS_CERT=certs/auth-audit-nats-client.crt \
	    AUTH_AUDIT_NATS_KEY=certs/auth-audit-nats-client.key \
	    AUTH_AUDIT_NATS_CA=$$CA_PEM \
	    AUTH_AUDIT_DB_CERT=certs/auth-audit-db-client.crt \
	    AUTH_AUDIT_DB_KEY=certs/auth-audit-db-client.key \
	    AUTH_AUDIT_DB_CA=$$CA_PEM \
	    AUTH_AUDIT_DATABASE_URL=postgres://$${AUTH_AUDIT_DB_USERNAME:-auth_audit}@audit-db.localhost:$(AUDIT_DB_PORT)/auth_audit?sslmode=verify-full \
	    $(AUTH_AUDIT_BIN) consume

## keygen: Print a fresh random master key
keygen: build
	@$(AUTHD_BIN) keygen

## gen-certs: Generate mTLS certificates for the docker compose overlay
gen-certs:
	@bash certs/gen.sh

# ── Quality ───────────────────────────────────────────────────────────────────

## test: Run all tests
test:
	$(GO) test ./... -count=1

## test-verbose: Run all tests with verbose output
test-verbose:
	$(GO) test ./... -count=1 -v

## tidy: Run go mod tidy
tidy:
	$(GO) mod tidy

## vet: Run go vet
vet:
	$(GO) vet ./...

## lint: Run staticcheck
lint:
	staticcheck ./...

## check: Full pre-commit sequence (gofmt + test + staticcheck + gopls + govulncheck)
check:
	gofmt -s -w .
	$(GO) test ./... -count=1
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...

# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build the Docker image (linux/arm64, default)
docker-build:
	docker build \
	  --platform linux/arm64 \
	  -t $(IMAGE_NAME):$(IMAGE_TAG) \
	  -t $(IMAGE_NAME):latest \
	  .
	@echo "  built $(IMAGE_NAME):$(IMAGE_TAG)"

## docker-build-amd64: Build the Docker image for linux/amd64
docker-build-amd64:
	docker build \
	  --platform linux/amd64 \
	  -t $(IMAGE_NAME):$(IMAGE_TAG)-amd64 \
	  .

## docker-push: Push image to registry (set IMAGE_NAME to your registry repo)
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_NAME):latest

## docker-up: Start auth + Postgres with docker compose
docker-up: _sync-pg-scripts
	docker compose up -d

## docker-up-mtls: Start with docker compose + mTLS overlay (auto-generates certs on first run)
docker-up-mtls: _sync-pg-scripts _sync-certs
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d --remove-orphans

## docker-down: Stop all compose services (overlay-aware; safe to run in any mode)
docker-down:
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml down

## docker-down-all: Stop + remove orphan containers AND named volumes (destroys DB data)
docker-down-all:
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml down --remove-orphans -v

## docker-logs: Tail auth logs
docker-logs:
	docker compose logs -f auth

# ── Install ───────────────────────────────────────────────────────────────────

## install: Install authd to GOPATH/bin (or ~/go/bin)
install:
	$(GO) install -ldflags "$(LDFLAGS)" $(CMD_AUTHD)
	@echo "  installed authd"

# ── Clean ─────────────────────────────────────────────────────────────────────

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)

## clean-all: Remove binaries, generated certs/keys under certs/, and .env
clean-all: clean
	rm -f certs/*.crt certs/*.key certs/ca.srl
	rm -f .env
	@echo "  removed certs/*.{crt,key}, certs/ca.srl, and .env"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "auth Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F: '{printf "  %-24s %s\n", $$1, $$2}'
