# Multi-stage build for the auth project.
#
# - Stage `builder` compiles both binaries (authd + auth-aws-creds). Building
#   them together amortises `go mod download` across a single cache layer;
#   the binaries are independent Go `main` packages with disjoint runtime
#   dependencies (the helper's import graph contains no DB or AWS SDK).
#
# - Stage `cli` ships only auth-aws-creds. Useful for CI runners or dev
#   containers that prefer a containerized binary over `go install`.
#   Reachable via `docker build --target cli .`.
#
# - Stage `server` (default — last stage in this file) ships only the authd
#   server. The CLI helper is a developer tool — devs `go install` it on
#   their laptops, no value in bundling it into the server runtime.
#   Plain `docker build .` produces this image.
#
# Both targets honour TARGETOS / TARGETARCH for cross-builds.

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

ENTRYPOINT ["/usr/local/bin/auth-aws-creds"]

# ── Stage 3: Server runtime image (default target) ────────────────────────────
FROM alpine:3.21 AS server

# ca-certificates is required for TLS connections to Postgres, NATS, and outbound SCIM.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/authd /usr/local/bin/authd

EXPOSE 443

ENTRYPOINT ["/usr/local/bin/authd"]
CMD ["serve"]
