# NxtFireGuard Traffic Sensor

The **NxtFireGuard Traffic Sensor** is a security component designed to detect malicious IP addresses. Detected malicious IPs are reported to **NxtFireGuard**, where they can be added to blocklists for proactive protection.

Configuration and management are handled through the [NxtFireGuard Dashboard](https://dashboard.nxtfireguard.nxtgenit.de).

---

## Configuration

To configure the Traffic Sensor, create a `.env` file in the same directory as your `docker-compose.yml` file. Include the following environment variables:

```env
DEBUG=false

TRAFFIC_SENSOR_NAME=

AUTH_SECRET=
HEARTBEAT_IDENTIFIER=

HEARTBEAT_URL=https://heartbeat.nxtfireguard.de
NFG_ARBITER_URL=https://arbiter.nxtfireguard.de
NFG_ARBITER_HOST=arbiter.nxtfireguard.de
STREAMING_SKIP_VERIFY_TLS=false
SQLITE_DB_PATH=/data/ip_scores.db
IP_SCORE_CACHE_SIZE=1000
RECOMMENDATIONS_CACHE_SIZE=100
LOG_TO_LOKI=true
LOKI_ADDRESS=https://loki.nxtfireguard.de
```

### Notes

* **TRAFFIC_SENSOR_NAME** should be a unique identifier for this sensor instance.
* **AUTH_SECRET** and **HEARTBEAT_IDENTIFIER** are used for secure communication with NxtFireGuard services.
* Logs are sent to a centralized **Loki** instance for monitoring and analysis.

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
---

## License

This project is part of the **NxtFireGuard** suite developed by **NxtGenIT**. All rights reserved.
