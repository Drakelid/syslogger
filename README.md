# SysLogger

SysLogger is a lightweight, containerized syslog server designed to receive and manage system logs from ASUS routers. Running in a Docker environment, it captures, stores and optionally forwards syslog messages for diagnostics, monitoring and auditing purposes.

## Features

- Runs as a standalone syslog server in a Docker container
- Optimized for ASUS router syslog output (e.g. RT-AX88U, RT-AC86U)
- Minimal configuration, plug-and-play setup
- Supports UDP and TCP log forwarding
- Logs are written to a file and can be forwarded to another syslog server
- Automatic log rotation with configurable size and retention
- Optional logging to STDOUT for debugging
- Lightweight web interface that highlights potential attacks

## Usage

1. Build and start the container using Docker Compose:
   ```bash
   docker-compose up --build
   ```
   Logs will be stored in the `logs/` directory on the host.

2. Point your ASUS router's syslog settings to the IP address of the Docker host on the configured port (default `514`).

3. Check `logs/syslog.log` for incoming messages.

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
