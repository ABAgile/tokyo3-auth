# Multi-stage build for the auth project.
#
# - Stage `builder` compiles both binaries (authd + auth-aws-creds). Building
#   them together amortises `go mod download` across a single cache layer;
#   the binaries are independent Go `main` packages whose runtime dependency
#   graphs intersect only on internal helpers and standard library (no DB
#   or AWS SDK in the helper).
#
# - Stage `cli` ships auth-aws-creds under /usr/local/bin/. No ENTRYPOINT —
#   the user invokes the binary explicitly so this image can grow more CLI
#   tools later without breaking existing invocations. Useful for CI runners
#   and dev containers that prefer a containerized helper over `go install`.
#   Reachable via `docker build --target cli .`. (The auth-ssh-creds helper
#   lives in the tokyo3-ca repo; its CLI image is ghcr.io/abagile/tokyo3-ca-cli.)
#
# - Stage `server` (default — last stage in this file) ships only the authd
#   server. The CLI helper is a developer tool — devs `go install` it on
#   their laptops, no value in bundling it into the server runtime.
#   Plain `docker build .` produces this image.
#
# All targets honour TARGETOS / TARGETARCH for cross-builds.

# ── Stage 1: Build Go binaries ────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=arm64

WORKDIR /src

# Download deps first (cached layer unless go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/authd ./cmd/authd
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/auth-aws-creds ./cmd/auth-aws-creds

# ── Stage 2: CLI image (build with --target cli) ──────────────────────────────
FROM alpine:3.21 AS cli

# ca-certificates so the helper can verify TLS to the auth issuer.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/auth-aws-creds /usr/local/bin/auth-aws-creds

# No ENTRYPOINT — users invoke the binary explicitly so this image can
# grow more CLI tools later without breaking existing invocations.
#   docker run --rm <image> auth-aws-creds login --issuer ... --client-id ...
CMD ["/bin/sh"]

# ── Stage 3: Server runtime image (default target) ────────────────────────────
FROM alpine:3.21 AS server

# ca-certificates is required for TLS connections to Postgres, NATS, and outbound SCIM.
# tini runs as PID 1 to reap orphaned children (e.g. the ssl_client that
# busybox-wget healthchecks orphan) and forward signals for clean shutdown.
# A bare Go PID 1 doesn't reap, so cgroup pids.current would climb forever.
RUN apk add --no-cache ca-certificates tini

COPY --from=builder /out/authd /usr/local/bin/authd

EXPOSE 443

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/authd"]
CMD ["serve"]
