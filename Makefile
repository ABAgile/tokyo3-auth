## tokyo3-auth — build targets
##
## Usage:
##   make build             Build authd binary to ./bin/
##   make run               Start authd with dev defaults (Postgres + NATS via compose)
##   make run-mtls          Start authd with mTLS (cert auth, no password in DSN)
##   make keygen            Generate an AUTH_MASTER_KEY
##   make check             Full pre-commit sequence (fmt + test + staticcheck + gopls + govulncheck)
##   make docker-build      Build Docker image
##   make docker-up         Bring up the full stack (Postgres + NATS + auth + Traefik + Teleport)
##   make docker-up-mtls    Bring up the full stack + mTLS overlay (auto-generates certs)
##   make docker-down       Stop the stack (overlay-aware; safe in any mode)
##   make docker-down-all   Stop + remove orphan containers AND named volumes (destroys DB data)
##   make gen-certs         Generate mTLS certs in shared/certs/ (manual; auto-run elsewhere)
##   make clean             Remove ./bin/
##   make clean-all         Remove ./bin/, shared/certs/*.{crt,key,srl}, and .env
##   make test              Run tests
##   make help              Show this help

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE     := github.com/abagile/tokyo3-auth
CMD_AUTHD  := ./cmd/authd

BIN_DIR    := bin
AUTHD_BIN  := $(BIN_DIR)/authd

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
NATS_PORT     ?= 34222

# Name of the external named volume populated via tar pipe (no bind mounts).
# Declared `external: true` in docker-compose.yml so compose neither creates
# nor destroys it — `_sync-shared` is the sole owner of its lifecycle.
SHARED_VOLUME := shared_data

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        run run-mtls keygen gen-certs \
        _gen-env _sync-shared \
        test test-verbose tidy vet lint check \
        docker-build docker-build-amd64 docker-push docker-up docker-up-mtls docker-down docker-down-all docker-logs \
        install clean clean-all help

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile authd into ./bin/
build: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AUTHD_BIN) $(CMD_AUTHD)
	@echo "  built $(AUTHD_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

## build-linux: Cross-compile for Linux arm64 (Graviton, default)
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-linux-arm64 $(CMD_AUTHD)
	@echo "  built authd-linux-arm64"

## build-linux-amd64: Cross-compile for Linux amd64
build-linux-amd64: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-linux-amd64 $(CMD_AUTHD)
	@echo "  built authd-linux-amd64"

## build-darwin: Cross-compile for macOS arm64 (M-series)
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/authd-darwin-arm64 $(CMD_AUTHD)
	@echo "  built authd-darwin-arm64"

# ── Internal helpers ──────────────────────────────────────────────────────────

# Generate .env with dev defaults on first run. Used by both run targets.
# DSNs use password auth; the mTLS run target overrides with cert-auth DSNs at process launch time.
_gen-env: build
	@if [ ! -f .env ]; then \
	    KEY=$$($(AUTHD_BIN) keygen); \
	    echo "AUTH_MASTER_KEY=$$KEY"                                                                                                                              > .env; \
	    echo "# AUTH_ADDR is NOT seeded: compose's container needs :443 (Traefik upstream)"                                                                       >> .env; \
	    echo "# while 'make run' listens on :$(AUTH_PORT) on the dev-container host. Set via"                                                                    >> .env; \
	    echo "# inline override in the run target, not here."                                                                                                     >> .env; \
	    echo "AUTH_ISSUER=https://auth.localhost"                                                                                                                >> .env; \
	    echo "POSTGRES_PORT=$(POSTGRES_PORT)"                                                                                                                    >> .env; \
	    echo "AUTH_ADMIN_DB_PASSWORD=changeme"                                                                                                                   >> .env; \
	    echo "AUTH_DB_PASSWORD=changeme"                                                                                                                         >> .env; \
	    echo "# AUTH_ADMIN_DATABASE_URL / AUTH_DATABASE_URL are deliberately NOT seeded:"                                                                        >> .env; \
	    echo "# docker compose builds the container-internal DSN (db:5432) from the"                                                                            >> .env; \
	    echo "# password vars above; make run / run-mtls construct the host-side DSN"                                                                            >> .env; \
	    echo "# (db.localhost:POSTGRES_PORT) inline. Set them here only to override both."                                                                       >> .env; \
	    echo "NATS_PORT=$(NATS_PORT)"                                                                                                                            >> .env; \
	    echo "# AUTH_NATS_URL likewise — compose defaults to nats://nats:4222 (in-cluster);"                                                                     >> .env; \
	    echo "# make run targets nats.localhost:NATS_PORT instead."                                                                                              >> .env; \
	    echo "AUTH_ALLOW_REGISTRATION=true"                                                                                                                      >> .env; \
	    echo ""                                                                                                                                                  >> .env; \
	    echo "# ── Teleport github connector ─────────────────────────────────────────"                                                                          >> .env; \
	    echo "# Fill CLIENT_ID/SECRET after registering an OAuth client; see the"                                                                                >> .env; \
	    echo "# 'First-time setup' section at the top of docker-compose.yml."                                                                                    >> .env; \
	    echo "# TELEPORT_IMAGE / TELEPORT_PUBLIC_ADDR have working defaults in"                                                                                  >> .env; \
	    echo "# docker-compose.yml and the Makefile; set them here only to override."                                                                            >> .env; \
	    echo "TELEPORT_GITHUB_CLIENT_ID="                                                                                                                         >> .env; \
	    echo "TELEPORT_GITHUB_CLIENT_SECRET="                                                                                                                    >> .env; \
	    echo "  generated .env"; \
	fi

# Render shared/{teleport,traefik}/*.tmpl using values in .env, then tar-pipe
# the entire shared/ tree into the shared_data named volume. Single source of
# truth for everything containers read under /shared (certs/, postgres/,
# teleport/, traefik/). Uses a tar pipe rather than a bind mount so it works
# when `docker compose` itself runs inside a container — the daemon would see
# the OUTER host filesystem, not ours.
#
# Templates use @@VAR@@ markers (not $VAR / ${VAR}) so sed substitution
# doesn't collide with Teleport's own config syntax. bootstrap.yaml is
# rendered only when client_id/secret are present; without it, the
# docker-up bootstrap step is skipped.
_sync-shared: _gen-env
	@if [ ! -f shared/certs/authd-server.crt ]; then bash shared/certs/gen.sh; fi
	@AUTH_ISSUER=$$(grep ^AUTH_ISSUER= .env | cut -d= -f2-); \
	 TELEPORT_PUBLIC_ADDR=$$(grep ^TELEPORT_PUBLIC_ADDR= .env | cut -d= -f2-); \
	 TELEPORT_GITHUB_CLIENT_ID=$$(grep ^TELEPORT_GITHUB_CLIENT_ID= .env | cut -d= -f2-); \
	 TELEPORT_GITHUB_CLIENT_SECRET=$$(grep ^TELEPORT_GITHUB_CLIENT_SECRET= .env | cut -d= -f2-); \
	 : "$${AUTH_ISSUER:=https://auth.localhost}"; \
	 : "$${TELEPORT_PUBLIC_ADDR:=teleport.localhost}"; \
	 AUTH_HOST=$$(echo "$$AUTH_ISSUER" | sed -E 's|^https?://([^:/]+).*|\1|'); \
	 for t in shared/teleport/*.yaml.tmpl shared/traefik/*.yml.tmpl; do \
	   out=$${t%.tmpl}; \
	   if [ "$$(basename $$t)" = "bootstrap.yaml.tmpl" ] && { [ -z "$$TELEPORT_GITHUB_CLIENT_ID" ] || [ -z "$$TELEPORT_GITHUB_CLIENT_SECRET" ]; }; then \
	     rm -f "$$out"; \
	     continue; \
	   fi; \
	   sed -e "s|@@AUTH_ISSUER@@|$$AUTH_ISSUER|g" \
	       -e "s|@@AUTH_HOST@@|$$AUTH_HOST|g" \
	       -e "s|@@TELEPORT_PUBLIC_ADDR@@|$$TELEPORT_PUBLIC_ADDR|g" \
	       -e "s|@@TELEPORT_GITHUB_CLIENT_ID@@|$$TELEPORT_GITHUB_CLIENT_ID|g" \
	       -e "s|@@TELEPORT_GITHUB_CLIENT_SECRET@@|$$TELEPORT_GITHUB_CLIENT_SECRET|g" \
	       "$$t" > "$$out"; \
	 done
	@docker volume create $(SHARED_VOLUME) 2>&1 >/dev/null || true
	@cp $$(mkcert -CAROOT)/rootCA.pem shared/certs/ca.crt
	@tar -cf - --exclude='*.tmpl' --exclude='gen.sh' -C shared . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "tar -xf - -C /shared && find /shared/postgres -name '*.sh' -exec chmod +x {} \;"
	@rm -f shared/certs/ca.crt
	@echo "  rendered + synced shared/ → /shared"

# ── Dev ───────────────────────────────────────────────────────────────────────

## run: Build and start authd with dev defaults (auto-generates .env on first run)
## DSNs, AUTH_NATS_URL, and the API cert/key paths are NOT read from .env —
## they're set inline to target host-side filesystem paths and port mappings
## (db.localhost / nats.localhost / shared/certs/...), so .env stays usable
## as the single source of truth for `docker-up` too (where the container
## sees /shared/certs/... and db:5432).
##
## Without AUTH_API_CERT/KEY here, authd would mint an ephemeral self-signed
## cert at startup instead of using the mkcert-issued one — browsers would
## then show a cert warning when hitting https://localhost:${AUTH_PORT}.
run: _gen-env _sync-shared
	@docker compose up -d db nats natsbox --wait 2>/dev/null || true
	@export $$(grep -v '^#' .env | xargs) && \
	    AUTH_ADDR=$(AUTH_ADDR) \
	    AUTH_API_CERT=shared/certs/authd-server.crt \
	    AUTH_API_KEY=shared/certs/authd-server.key \
	    AUTH_ADMIN_DATABASE_URL=postgres://$${AUTH_ADMIN_DB_USERNAME:-auth_admin}:$${AUTH_ADMIN_DB_PASSWORD}@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=disable \
	    AUTH_DATABASE_URL=postgres://$${AUTH_DB_USERNAME:-auth_app}:$${AUTH_DB_PASSWORD}@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=disable \
	    AUTH_NATS_URL=nats://nats.localhost:$(NATS_PORT) \
	    $(AUTHD_BIN) serve

## run-mtls: Build and start authd with mTLS (cert auth; overrides DSNs — no password)
run-mtls: _gen-env _sync-shared
	@docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d db nats natsbox --wait 2>/dev/null || true
	@CA_PEM=$$(mkcert -CAROOT)/rootCA.pem; \
	    export $$(grep -v '^#' .env | xargs) && \
	    AUTH_API_CERT=shared/certs/authd-server.crt \
	    AUTH_API_KEY=shared/certs/authd-server.key \
	    AUTH_WORKLOAD_CA=$$CA_PEM \
	    AUTH_ADMIN_DB_CERT=shared/certs/authd-admin-db-client.crt \
	    AUTH_ADMIN_DB_KEY=shared/certs/authd-admin-db-client.key \
	    AUTH_ADMIN_DATABASE_URL=postgres://$${AUTH_ADMIN_DB_USERNAME:-auth_admin}@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=verify-full \
	    AUTH_DB_CERT=shared/certs/authd-app-db-client.crt \
	    AUTH_DB_KEY=shared/certs/authd-app-db-client.key \
	    AUTH_DATABASE_URL=postgres://$${AUTH_DB_USERNAME:-auth_app}@db.localhost:$(POSTGRES_PORT)/authdb?sslmode=verify-full \
	    AUTH_SCIM_MTLS_CERT=shared/certs/authd-scim-client.crt \
	    AUTH_SCIM_MTLS_KEY=shared/certs/authd-scim-client.key \
	    AUTH_NATS_CERT=shared/certs/authd-nats-client.crt \
	    AUTH_NATS_KEY=shared/certs/authd-nats-client.key \
	    AUTH_NATS_URL=tls://nats.localhost:$(NATS_PORT) \
	    $(AUTHD_BIN) serve

## keygen: Print a fresh random master key
keygen: build
	@$(AUTHD_BIN) keygen

## gen-certs: Generate mTLS certificates for the docker compose overlay
gen-certs:
	@bash shared/certs/gen.sh

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

## docker-up: Bring up the full stack (Postgres + NATS + auth + Traefik + Teleport).
##
## `up --wait` blocks until each service's healthcheck passes — including the
## teleport service's `tctl status` check — so the bootstrap exec that follows
## is guaranteed to hit a running auth server. tctl runs *inside* the teleport
## container because file-based admin auth dials 127.0.0.1:3025, which only
## resolves to auth from there. `--force` makes the create idempotent so
## docker-up is safe to re-run. The bootstrap step is skipped when github
## client_id/secret are unset — see the 'First-time setup' header in
## docker-compose.yml.
docker-up: _gen-env _sync-shared
	docker compose up -d --build --wait --remove-orphans
	@if [ -f shared/teleport/bootstrap.yaml ]; then \
	    echo "  applying shared/teleport/bootstrap.yaml (github connector)…"; \
	    docker compose exec -T teleport \
	        /usr/local/bin/tctl -c /shared/teleport/teleport.yaml create --force -f /shared/teleport/bootstrap.yaml; \
	    PUBLIC_ADDR=$$(grep ^TELEPORT_PUBLIC_ADDR= .env | cut -d= -f2-); \
	    echo "  github connector applied — sign in at https://$${PUBLIC_ADDR:-teleport.localhost}"; \
	else \
	    echo ""; \
	    echo "  ⚠ TELEPORT_GITHUB_CLIENT_ID/SECRET are unset — github connector NOT created."; \
	    echo "    Stack is up; register an OAuth client (see docker-compose.yml header),"; \
	    echo "    set the values in .env, and re-run 'make docker-up' to finish wiring."; \
	fi

## docker-up-mtls: Bring up the full stack + mTLS overlay (auto-generates certs on first run)
docker-up-mtls: _gen-env _sync-shared
	docker compose -f docker-compose.yml -f docker-compose.mtls.yml up -d --build --wait --remove-orphans
	@if [ -f shared/teleport/bootstrap.yaml ]; then \
	    docker compose -f docker-compose.yml -f docker-compose.mtls.yml exec -T teleport \
	        /usr/local/bin/tctl -c /shared/teleport/teleport.yaml create --force -f /shared/teleport/bootstrap.yaml; \
	fi

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

## clean-all: Remove binaries, generated certs/keys under shared/certs/, and .env
clean-all: clean
	rm -f shared/certs/*.crt shared/certs/*.key shared/certs/ca.srl
	rm -f .env
	@echo "  removed shared/certs/*.{crt,key}, shared/certs/ca.srl, and .env"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "auth Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F: '{printf "  %-24s %s\n", $$1, $$2}'
