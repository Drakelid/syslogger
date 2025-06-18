# SysLogger

SysLogger is a lightweight, containerized syslog server designed to receive and manage system logs from ASUS routers. Running in a Proxmox LXC container, it captures, stores and optionally forwards syslog messages for diagnostics, monitoring and auditing purposes.

## Features

- Runs as a standalone syslog server in a Proxmox LXC container
- Optimized for ASUS router syslog output (e.g. RT-AX88U, RT-AC86U)
- Minimal configuration, plug-and-play setup
- Supports UDP and TCP log forwarding
- Logs are written to a file and can be forwarded to another syslog server
- Logs are also stored in a local SQLite database for easy searching
- Automatic log rotation with configurable size and retention
- Optional logging to STDOUT for debugging
- Modern web interface that highlights potential attacks and displays recent logs
- Dashboard shows attack statistics for quick insight
- Built-in log viewer with search and download options
- Detects repeated deauthentication and authentication failures to flag possible brute-force attacks
- Flags port scans and DHCP floods with configurable thresholds
- Highlights firewall drops and possible DoS patterns with additional thresholds
- Detection looks at recent logs within a time window for more accurate alerts
- Log viewer supports filtering by multiple keywords

## Usage

1. Create an unprivileged Debian or Ubuntu LXC container in Proxmox and assign it an IP address on your LAN.

2. Log in to the container and install Python and Flask:

   ```bash
   apt update
   apt install -y python3 python3-pip
   pip3 install flask
   ```

3. Clone or copy this project into `/opt/syslogger`:

   ```bash
   git clone https://github.com/yourname/syslogger.git /opt/syslogger
   ```

4. Copy `syslogger.service` and `syslogger.env` then start SysLogger:

   ```bash
   cp /opt/syslogger/syslogger.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now syslogger
   ```
   Edit `/opt/syslogger/syslogger.env` to adjust settings.

   Logs will be written to `/opt/syslogger/logs` inside the container.

5. Point your ASUS router's syslog settings to the container IP on port `514` and open `http://<container-ip>:8080` to view the dashboard.


### Environment Variables

- `LOG_FILE` – path to the log file inside the container (`/opt/syslogger/logs/syslog.log` by default)
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
- `FIREWALL_THRESHOLD` – firewall drop messages from an IP before an alert (default `20`)
- `DOS_THRESHOLD` – DoS related messages from an IP before an alert (default `10`)
- `DB_FILE` – path to the SQLite database (`/opt/syslogger/logs/syslog.db` by default)
- `DETECTION_WINDOW` – seconds of recent logs considered for attack detection (default `600`)

## Example

To forward logs to another syslog server at `192.168.1.10:514`, edit `/opt/syslogger/syslogger.env`:

```bash
FORWARD_HOST=192.168.1.10
FORWARD_PORT=514
```

Reload the service to apply changes:

```bash
systemctl restart syslogger
```

SysLogger provides a simple way to collect and inspect your router logs without additional dependencies.
