# NxtFireGuard Traffic Sensor

The **NxtFireGuard Traffic Sensor** watches the connections of the host it runs on, and the firewall/IDS logs sent to it over syslog. When one end of a connection is an IP that NxtFireGuard scores as malicious, the sensor raises an alert and recommends the IP for your blocklists in **NxtFireGuard**.

Configuration and management are handled through the [NxtFireGuard Dashboard](https://dashboard.nxtfireguard.nxtgenit.de). The dashboard decides whether the sensor captures traffic, runs the syslog listener, at which score it alerts, and which blocklists and whitelists apply. Changes arrive within seconds.

---

## Prerequisites

- **Docker** installed and running, on a Linux host (traffic capture needs host networking)
- Access to the **NxtFireGuard Dashboard** to retrieve the values below

---

## Configuration

Create a `.env` file next to your `docker-compose.yml` (see [`.env.example`](.env.example)):

```env
TRAFFIC_SENSOR_NAME=
AUTH_SECRET=
HEARTBEAT_IDENTIFIER=
SYSLOG_PORT=
```

> **Note:** If the **NxtFireGuard Threat Feed Aggregator** runs on the same host, set `SYSLOG_PORT` to a port other than `514` and `1025`-`1028`; the aggregator uses those.

| Variable | Default | Meaning |
|---|---|---|
| `TRAFFIC_SENSOR_NAME` | required | Sensor name from the dashboard |
| `AUTH_SECRET` | required | Sensor secret from the dashboard |
| `HEARTBEAT_IDENTIFIER` | empty | Heartbeat ID from the dashboard; without it no heartbeats are sent |
| `SYSLOG_LISTEN_ADDR` / `SYSLOG_PORT` | `0.0.0.0` / `514` | Syslog listener, UDP and TCP |
| `SQLITE_DB_PATH` | `/data/ip_scores.db` | Local score database and last known settings |
| `DEBUG` | `false` | Debug logging |
| `NFG_ARBITER_URL` | `https://arbiter.nxtfireguard.de` | Backend URL; the update websocket is derived from it |
| `NFG_ARBITER_HOST` | empty | Websocket host, only if it differs from `NFG_ARBITER_URL` |
| `STREAMING_SKIP_VERIFY_TLS` | `false` | Skip TLS certificate checks (test backends only) |
| `EVALUATION_WORKERS` / `EVALUATION_QUEUE_SIZE` | `8` / `4096` | Parallel evaluations and connections waiting for one |

`LOG_TO_LOKI` and `LOKI_ADDRESS` are no longer used. The sensor logs JSON lines to stdout.

---

## Running with Docker Compose

```yaml
services:
  sensor:
    image: nxtgenit/nxtfireguard-traffic-sensor:latest
    env_file:
      - .env
    volumes:
      - sensor-db:/data
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    restart: always

volumes:
  sensor-db:
```

1. Create the `.env` file.
2. Start the sensor: `docker compose up -d`
3. Follow the logs: `docker compose logs -f`

---

## How it works

- **Scores** of all IPs your license can see are downloaded at start and every hour, and kept current by live updates over a websocket. Lookups never wait on the network. A score loses half its weight every 72 hours without an update, down to 30% of the original.
- **Traffic capture** listens on every interface with an address, except loopback and Docker bridges. Each new connection (TCP SYN, or the first packet of a flow within two minutes) is evaluated once.
- **Syslog** accepts RFC 3164 and RFC 5424 messages over UDP and TCP. Source and destination are read from CEF/key-value fields (`src=`, `dst=`, `srcip=`, `dstip=`), Cisco `a(port) -> b(port)` logs, pfSense/OPNsense filterlog (IPv4 and IPv6), and JSON fields such as Suricata EVE `src_ip`/`dest_ip` or ECS `source.ip`/`destination.ip`. Otherwise the first two addresses in the message are used.
- Both ends of a connection are checked. A connection with a whitelisted end is ignored. Loopback, multicast, broadcast and link-local addresses are not checked (169.254.169.254 is).
- An **alert** is sent when an IP's score reaches the alert threshold. A **recommendation** is sent for an IP again only when its score or its matching blocklists change. If the backend is busy (HTTP 429) or unreachable, both are retried with backoff.
- The last settings received from the backend are stored, so the sensor keeps working if the backend is unreachable when it starts.
- A **heartbeat** is sent every minute while every enabled part (capture, syslog) is running.

---

## Development

```bash
# needs libpcap headers (apt install libpcap-dev / brew install libpcap)
go test -race ./...
golangci-lint run
docker build --build-arg VERSION=dev -t traffic-sensor .
```

---

## License

This project is part of the **NxtFireGuard** suite developed by **NxtGenIT**. All rights reserved.
