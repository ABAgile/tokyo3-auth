# Multi-stage build for the auth project.
#
# - Stage `builder` compiles all three binaries (authd + auth-aws-creds +
#   auth-ssh-creds). Building them together amortises `go mod download`
#   across a single cache layer; the binaries are independent Go `main`
#   packages whose runtime dependency graphs intersect only on internal
#   helpers and standard library (no DB or AWS SDK in either helper).
#
# - Stage `cli` ships both helpers (auth-aws-creds + auth-ssh-creds) under
#   /usr/local/bin/. No ENTRYPOINT — the user picks which binary to run
#   (`docker run --rm <image> auth-aws-creds login …`). Useful for CI
#   runners and dev containers that prefer a containerized helper over
#   `go install`. Reachable via `docker build --target cli .`.
#
# - Stage `server` (default — last stage in this file) ships only the authd
#   server. The CLI helpers are developer tools — devs `go install` them on
#   their laptops, no value in bundling them into the server runtime.
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
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/auth-ssh-creds ./cmd/auth-ssh-creds

# ── Stage 2: CLI image (build with --target cli) ──────────────────────────────
FROM alpine:3.21 AS cli

# ca-certificates so the helpers can verify TLS to the auth issuer.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/auth-aws-creds /usr/local/bin/auth-aws-creds
COPY --from=builder /out/auth-ssh-creds /usr/local/bin/auth-ssh-creds

# No ENTRYPOINT — users explicitly invoke the binary they want, e.g.
#   docker run --rm <image> auth-aws-creds login --issuer ... --client-id ...
#   docker run --rm <image> auth-ssh-creds login --issuer ... --client-id ...
# Default to a shell so `docker run -it <image>` lands the user somewhere
# useful for ad-hoc exploration.
CMD ["/bin/sh"]

# ── Stage 3: Server runtime image (default target) ────────────────────────────
FROM alpine:3.21 AS server

# ca-certificates is required for TLS connections to Postgres, NATS, and outbound SCIM.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/authd /usr/local/bin/authd

EXPOSE 443

ENTRYPOINT ["/usr/local/bin/authd"]
CMD ["serve"]
