## tokyo3-auth — build targets
##
## Usage:
##   make build           Build authd binary to ./bin/
##   make run             Start the server with dev defaults (starts Postgres via compose)
##   make keygen          Generate an AUTH_MASTER_KEY
##   make check           Full pre-commit sequence (fmt + test + staticcheck + gopls + govulncheck)
##   make docker-build    Build Docker image
##   make docker-up       Start with docker compose (Postgres + auth)
##   make docker-down     Stop docker compose
##   make clean           Remove ./bin/
##   make test            Run tests
##   make help            Show this help

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE    := github.com/abagile/tokyo3-auth
CMD_AUTHD := ./cmd/authd

BIN_DIR   := bin
AUTHD_BIN := $(BIN_DIR)/authd

GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION    := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w

GO      := go
GOFLAGS :=

IMAGE_NAME    ?= abagile/tokyo3-auth
IMAGE_TAG     ?= $(VERSION)
POSTGRES_PORT ?= 5433

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        run keygen \
        test test-verbose tidy vet lint check \
        docker-build docker-build-amd64 docker-push docker-up docker-down docker-logs \
        install clean help

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

# ── Dev ───────────────────────────────────────────────────────────────────────

## run: Build and start authd with dev defaults (auto-generates .env on first run)
run: build
	@if [ ! -f .env ]; then \
	    KEY=$$($(AUTHD_BIN) keygen); \
	    echo "AUTH_MASTER_KEY=$$KEY"                                                            > .env; \
	    echo "AUTH_ISSUER=http://localhost:8080"                                               >> .env; \
	    echo "AUTH_PORT=8080"                                                                  >> .env; \
	    echo "POSTGRES_PORT=$(POSTGRES_PORT)"                                                          >> .env; \
	    echo "AUTH_DATABASE_URL=postgres://authuser:changeme@localhost:$(POSTGRES_PORT)/authdb?sslmode=disable" >> .env; \
	    echo "AUTH_ADMIN_DATABASE_URL=postgres://authuser:changeme@localhost:$(POSTGRES_PORT)/authdb?sslmode=disable" >> .env; \
	    echo "AUTH_ALLOW_REGISTRATION=true"                                                    >> .env; \
	    echo "  generated .env"; \
	fi
	@docker compose up -d postgres --wait 2>/dev/null || true
	@export $$(grep -v '^#' .env | xargs) && $(AUTHD_BIN) serve

## keygen: Print a fresh random master key
keygen: build
	@$(AUTHD_BIN) keygen

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
docker-up:
	docker compose up -d

## docker-down: Stop all compose services
docker-down:
	docker compose down

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

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo "auth Makefile targets:"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F: '{printf "  %-24s %s\n", $$1, $$2}'
