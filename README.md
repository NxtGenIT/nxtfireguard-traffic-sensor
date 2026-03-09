# NxtFireGuard Traffic Sensor

The **NxtFireGuard Traffic Sensor** is a security component designed to detect malicious IP addresses. Detected malicious IPs are reported to **NxtFireGuard**, where they can be added to blocklists for proactive protection.

Configuration and management are handled through the [NxtFireGuard Dashboard](https://dashboard.nxtfireguard.nxtgenit.de).

---

## Prerequisites

- **Docker** installed and running
- Access to the **NxtFireGuard Dashboard** to retrieve environment variables

---

## Configuration

To configure the Traffic Sensor, create a `.env` file in the same directory as your `docker-compose.yml` file. Include the following environment variables:

```env
TRAFFIC_SENSOR_NAME=
AUTH_SECRET=
HEARTBEAT_IDENTIFIER=
SYSLOG_PORT=
```

> **Note:** Missing environment variable values can be obtained from your **NxtFireGuard Dashboard**.

> **Note:** If you are running the **NxtFireGuard Threat Feed Aggregator** on the same host, ensure `SYSLOG_PORT` is set to a value other than `514`, `1025`, or `1026`, as these ports are reserved by the Threat Feed Aggregator.

---

## Running with Docker Compose

To deploy the sensor using Docker Compose, use the following configuration:

```yaml
services:
  sensor:
    platform: linux/amd64
    image: docker.nxtgenit.de/nfg-traffic-sensor-dev:latest
    build:
      context: .
    env_file:
      - .env
    volumes:
      - sensor-db:/data
    network_mode: host
    cap_add:
      - NET_ADMIN
    restart: always

volumes:
  sensor-db:
```

### Deployment Steps

1. Clone this repository.
2. Create a `.env` file with the required configuration.
3. Run the following command to start the service:
   ```bash
   docker compose up -d
   ```
4. Monitor logs using:
   ```bash
   docker compose logs -f
   ```

---

## Application Info

| Field   | Value                                          |
|---------|------------------------------------------------|
| Name    | NxtFireGuard Traffic Sensor                    |
| Purpose | Detect and report malicious IPs to NxtFireGuard |

---

## License

This project is part of the **NxtFireGuard** suite developed by **NxtGenIT**. All rights reserved.