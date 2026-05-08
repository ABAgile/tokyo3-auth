FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /authd      ./cmd/authd
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /auth-audit ./cmd/auth-audit


FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /authd      /usr/local/bin/authd
COPY --from=builder /auth-audit /usr/local/bin/auth-audit

EXPOSE 8443
ENTRYPOINT ["authd"]
CMD ["serve"]
