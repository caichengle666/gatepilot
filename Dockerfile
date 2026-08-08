# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go elevate_other.go elevate_windows.go instance_other.go instance_windows.go startup.go ./
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gatepilot .

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl iproute2 openvpn procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/gatepilot /usr/local/bin/gatepilot
COPY scripts/ml.sh /usr/local/bin/ml
RUN chmod 755 /usr/local/bin/ml

ENV VPNGATE_DATA_DIR=/var/lib/gatepilot \
    UI_HOST=0.0.0.0 \
    UI_PORT=8787 \
    LOCAL_PROXY_HOST=0.0.0.0 \
    LOCAL_PROXY_PORT=7928 \
    LOCAL_PROXY_TUNNEL_PORT_START=7929 \
    LOCAL_PROXY_BIND_TUN=true

VOLUME ["/var/lib/gatepilot"]
EXPOSE 8787 7928 7929-7936

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD curl -fsS "http://127.0.0.1:${UI_PORT:-8787}/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/gatepilot"]
