FROM golang:1.26-bookworm AS builder

# libpcap headers for gopacket/pcap (cgo); sqlite is compiled in by go-sqlite3.
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/traffic-sensor ./cmd/traffic-sensor

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap0.8 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/traffic-sensor .

# Capturing needs root (or CAP_NET_RAW/CAP_NET_ADMIN) and host networking.
VOLUME /data
CMD ["./traffic-sensor"]
