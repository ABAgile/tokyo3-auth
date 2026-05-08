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
    go build -ldflags="-s -w" -o /out/auth-audit ./cmd/auth-audit

# ── Stage 2: Runtime image ─────────────────────────────────────────────────────
FROM alpine:3.21

# ca-certificates is required for TLS connections to Postgres, NATS, and outbound SCIM.
RUN apk add --no-cache ca-certificates

COPY --from=builder /out/authd      /usr/local/bin/authd
COPY --from=builder /out/auth-audit /usr/local/bin/auth-audit

EXPOSE 443

ENTRYPOINT ["/usr/local/bin/authd"]
CMD ["serve"]
