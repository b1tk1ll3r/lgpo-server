# Compatibility copy. The canonical Dockerfile is located in the repository root.
# Build with the repository root as context:
#   docker build -f deploy/Dockerfile .
# syntax=docker/dockerfile:1

ARG GO_VERSION=1.23
ARG ALPINE_VERSION=3.21

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/gpo-server \
    ./cmd/server

FROM alpine:${ALPINE_VERSION} AS runtime
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 gpo \
    && adduser -S -D -H -u 10001 -G gpo gpo \
    && install -d -o gpo -g gpo -m 0750 /data /data/.tmp /app
COPY --from=build --chown=gpo:gpo /out/gpo-server /app/gpo-server
ENV GPO_SERVER_LISTEN=:8443 GPO_SERVER_DATA=/data TMPDIR=/data/.tmp
USER 10001:10001
WORKDIR /app
EXPOSE 8443
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD if [ -n "${GPO_SERVER_TLS_CERT:-}" ]; then \
        wget -q --no-check-certificate -O /dev/null https://127.0.0.1:8443/healthz; \
      else \
        wget -q -O /dev/null http://127.0.0.1:8443/healthz; \
      fi
ENTRYPOINT ["/app/gpo-server"]
