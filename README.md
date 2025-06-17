# SysLogger

SysLogger is a lightweight, containerized syslog server designed to receive and manage system logs from ASUS routers. Running in a Docker environment, it captures, stores and optionally forwards syslog messages for diagnostics, monitoring and auditing purposes.

## Features

- Runs as a standalone syslog server in a Docker container
- Optimized for ASUS router syslog output (e.g. RT-AX88U, RT-AC86U)
- Minimal configuration, plug-and-play setup
- Supports UDP and TCP log forwarding
- Logs are written to a file and can be forwarded to another syslog server
- Logs are also stored in a local SQLite database for easy searching
- Automatic log rotation with configurable size and retention
- Optional logging to STDOUT for debugging
- Modern web interface that highlights potential attacks and displays recent logs
- Built-in log viewer with search and download options
- Detects repeated deauthentication and authentication failures to flag possible brute-force attacks
- Flags port scans and DHCP floods with configurable thresholds
- Detection looks at recent logs within a time window for more accurate alerts
- Log viewer supports filtering by multiple keywords

## Usage

1. Build and start the container using Docker Compose. The configuration
   runs the container with host networking so the syslog and web ports are
   reachable from other devices on your LAN without additional port mapping:
   ```bash
   docker-compose up --build
   ```
   Logs will be stored in the `logs/` directory on the host.

2. Point your ASUS router's syslog settings to the IP address of the Docker
   host on the configured port (default `514`). Because SysLogger uses host
   networking, the router can send logs directly to the host IP without any
   extra port mappings.

3. Check `logs/syslog.log` or the SQLite database `logs/syslog.db` for incoming
   messages, or open the web dashboard at `http://<docker-host>:8080`.
   The log viewer is available at `http://<docker-host>:8080/logs` and offers a
   search box and download link. Enter multiple keywords separated by spaces to
   narrow the results.

### Environment Variables

- `LOG_FILE` – path to the log file inside the container (`/logs/syslog.log` by default)
- `LOG_LEVEL` – Python logging level (e.g. `INFO`, `DEBUG`)
- `FORWARD_HOST` and `FORWARD_PORT` – if set, messages will also be forwarded to another syslog server
- `MAX_BYTES` – rotate log files when they reach this size (default `10485760`)
- `BACKUP_COUNT` – number of rotated log files to keep (default `5`)
- `LOG_TO_STDOUT` – if `true`, also print logs to the console
- `BIND_HOST` – interface to bind to (default `0.0.0.0`)
- `UDP_PORT` and `TCP_PORT` – listening ports for UDP and TCP (default `514`)
- `ENABLE_UDP` and `ENABLE_TCP` – enable or disable UDP/TCP servers (default `true`)
- `ENABLE_WEB` – start the web interface (default `true`)
- `WEB_PORT` – port for the web interface (default `8080`)
- `WEB_LOG_LINES` – number of log lines to display in the web interface (default `100`)
- `DEAUTH_THRESHOLD` – number of deauthentication events from a client before an alert (default `3`)
- `AUTH_FAIL_THRESHOLD` – number of authentication failures from an IP before an alert (default `5`)
- `PORT_SCAN_THRESHOLD` – port scan events from an IP before an alert (default `10`)
- `DHCP_REQ_THRESHOLD` – DHCP requests from a client before an alert (default `20`)
- `DB_FILE` – path to the SQLite database (`/logs/syslog.db` by default)
- `DETECTION_WINDOW` – seconds of recent logs considered for attack detection (default `600`)

## Example

To forward logs to another syslog server at `192.168.1.10:514` while listening on a custom port, run:

```bash
docker-compose run \
  -e FORWARD_HOST=192.168.1.10 \
  -e FORWARD_PORT=514 \
  -e TCP_PORT=1514 \
  syslogger
```

SysLogger provides a simple way to collect and inspect your router logs without additional dependencies.
