#!/usr/bin/env python3
import os
import logging
import logging.handlers
from flask import Flask, render_template_string, request, send_file, jsonify
import socketserver
import threading
import time
import re
import sqlite3
import socket
import json
from datetime import datetime
import subprocess
import ipaddress

LOG_FILE = os.getenv('LOG_FILE', '/logs/syslog.log')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
FORWARD_HOST = os.getenv('FORWARD_HOST')
FORWARD_PORT = os.getenv('FORWARD_PORT')
MAX_BYTES = int(os.getenv('MAX_BYTES', '10485760'))  # 10 MB
BACKUP_COUNT = int(os.getenv('BACKUP_COUNT', '5'))
LOG_TO_STDOUT = os.getenv('LOG_TO_STDOUT', 'false').lower() in ('1', 'true', 'yes')
BIND_HOST = os.getenv('BIND_HOST', '0.0.0.0')
UDP_PORT = int(os.getenv('UDP_PORT', '514'))
TCP_PORT = int(os.getenv('TCP_PORT', '514'))
ENABLE_UDP = os.getenv('ENABLE_UDP', 'true').lower() in ('1', 'true', 'yes')
ENABLE_TCP = os.getenv('ENABLE_TCP', 'true').lower() in ('1', 'true', 'yes')
ENABLE_WEB = os.getenv('ENABLE_WEB', 'true').lower() in ('1', 'true', 'yes')
WEB_PORT = int(os.getenv('WEB_PORT', '8080'))
WEB_LOG_LINES = int(os.getenv('WEB_LOG_LINES', '100'))
DEAUTH_THRESHOLD = int(os.getenv('DEAUTH_THRESHOLD', '3'))
AUTH_FAIL_THRESHOLD = int(os.getenv('AUTH_FAIL_THRESHOLD', '5'))
PORT_SCAN_THRESHOLD = int(os.getenv('PORT_SCAN_THRESHOLD', '10'))
DHCP_REQ_THRESHOLD = int(os.getenv('DHCP_REQ_THRESHOLD', '20'))
FIREWALL_THRESHOLD = int(os.getenv('FIREWALL_THRESHOLD', '20'))
DOS_THRESHOLD = int(os.getenv('DOS_THRESHOLD', '10'))
DB_FILE = os.getenv('DB_FILE', '/logs/syslog.db')
DETECTION_WINDOW = int(os.getenv('DETECTION_WINDOW', '600'))  # seconds

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)

logger = logging.getLogger('syslogger')
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter('%(asctime)s %(message)s')

file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# SQLite setup
db_conn = sqlite3.connect(DB_FILE, check_same_thread=False)
db_conn.execute(
    "CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, host TEXT, message TEXT)"
)
db_conn.execute(
    """CREATE TABLE IF NOT EXISTS devices (
        ip TEXT PRIMARY KEY,
        hostname TEXT,
        mac TEXT,
        first_seen TEXT,
        last_seen TEXT,
        attack_types TEXT,
        detection_count INTEGER DEFAULT 0,
        device_info TEXT
    )"""
)

SYSLOG_RE = re.compile(r"(?:<\d+>)?(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)")


def parse_syslog_message(raw, client_host):
    match = SYSLOG_RE.match(raw)
    if match:
        ts_part, host, msg = match.groups()
        try:
            struct = time.strptime(
                f"{time.localtime().tm_year} {ts_part}", "%Y %b %d %H:%M:%S"
            )
            ts = time.strftime("%Y-%m-%d %H:%M:%S", struct)
        except Exception:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
        return ts, host, msg
    return time.strftime("%Y-%m-%d %H:%M:%S"), client_host, raw

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_device_hostname(ip):
    try:
        if not is_valid_ip(ip):
            return None
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None

def get_mac_from_arp(ip):
    try:
        if not is_valid_ip(ip):
            return None
        # Try to get MAC address from ARP table (requires privileges)
        try:
            if os.name == 'posix':  # Linux or macOS
                cmd = ['arp', '-n', ip]
                arp_output = subprocess.check_output(cmd).decode('utf-8')
                for line in arp_output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
            elif os.name == 'nt':  # Windows
                cmd = ['arp', '-a', ip]
                arp_output = subprocess.check_output(cmd).decode('utf-8')
                for line in arp_output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1].replace('-', ':')
        except (subprocess.SubprocessError, IndexError, ValueError):
            pass
        return None
    except Exception as e:
        logger.debug(f"Error getting MAC address for {ip}: {e}")
        return None

def gather_device_info(ip, attack_type=None):
    """
    Gather as much information as possible about a device given its IP address
    """
    if not is_valid_ip(ip):
        return None
    
    info = {}
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get basic network info
    hostname = get_device_hostname(ip)
    mac = get_mac_from_arp(ip)
    
    # Try to gather more advanced info
    network_info = {}
    
    try:
        # Use socket to determine if common ports are open, with short timeout
        socket.setdefaulttimeout(0.5)
        common_ports = [22, 23, 80, 443, 8080, 21, 25, 53, 3389, 5900]
        open_ports = []
        
        for port in common_ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except:
                pass
        
        if open_ports:
            network_info["open_ports"] = open_ports
    except Exception as e:
        logger.debug(f"Error checking ports for {ip}: {e}")
    
    # Put everything together
    info["network_info"] = network_info
    
    try:
        # Check if this device exists in our database
        cur = db_conn.cursor()
        cur.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
        device = cur.fetchone()
        
        if device:
            # Device exists, update information
            stored_info = json.loads(device[7]) if device[7] else {}
            stored_attack_types = json.loads(device[5]) if device[5] else []
            
            # Merge dictionaries giving precedence to new info
            for key, value in info.items():
                if key in stored_info:
                    if isinstance(value, dict) and isinstance(stored_info[key], dict):
                        stored_info[key].update(value)
                    else:
                        stored_info[key] = value
                else:
                    stored_info[key] = value
            
            # Update attack types
            if attack_type and attack_type not in stored_attack_types:
                stored_attack_types.append(attack_type)
            
            # Save updated information
            db_conn.execute(
                """UPDATE devices SET 
                hostname = ?, 
                mac = COALESCE(?, mac),
                last_seen = ?,
                attack_types = ?,
                detection_count = detection_count + 1,
                device_info = ?
                WHERE ip = ?""",
                (
                    hostname or device[1],
                    mac,
                    current_time,
                    json.dumps(stored_attack_types),
                    json.dumps(stored_info),
                    ip
                )
            )
            db_conn.commit()
            
            return stored_info
        else:
            # New device
            attack_types = [attack_type] if attack_type else []
            
            db_conn.execute(
                """INSERT INTO devices 
                (ip, hostname, mac, first_seen, last_seen, attack_types, detection_count, device_info) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ip,
                    hostname,
                    mac,
                    current_time,
                    current_time,
                    json.dumps(attack_types),
                    1,
                    json.dumps(info)
                )
            )
            db_conn.commit()
            
            return info
    except Exception as e:
        logger.error(f"Error saving device info for {ip}: {e}")
        return info

def insert_log(ts, host, message):
    try:
        db_conn.execute(
            "INSERT INTO logs (timestamp, host, message) VALUES (?, ?, ?)",
            (ts, host, message),
        )
        db_conn.commit()
    except Exception as e:
        logger.error(f"DB insert failed: {e}")

# Web interface setup
app = Flask(__name__)

INDEX_TEMPLATE = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>SysLogger Dashboard</title>
  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\">
  <style>
    body {padding-top:4rem;}
    .log-box {height:300px; overflow-y:auto; font-family:monospace;}
  </style>
</head>
<body>
  <nav class=\"navbar navbar-dark bg-dark fixed-top\">
    <div class=\"container-fluid\">
      <a class=\"navbar-brand\" href=\"/\">SysLogger</a>
      <a class=\"btn btn-secondary me-2\" href=\"/logs\">View Logs</a>
      <a class=\"btn btn-info\" href=\"/devices\">View Devices</a>
    </div>
  </nav>
  <div class=\"container mt-4\">
    <h2>Attack Statistics</h2>
    <table class=\"table table-sm\">
      <tr><th>Deauth Events</th><td>{{ stats.deauth }}</td></tr>
      <tr><th>Auth Failures</th><td>{{ stats.auth_fail }}</td></tr>
      <tr><th>Port Scans</th><td>{{ stats.port_scan }}</td></tr>
      <tr><th>DHCP Requests</th><td>{{ stats.dhcp }}</td></tr>
      <tr><th>Firewall Drops</th><td>{{ stats.firewall }}</td></tr>
      <tr><th>DoS Alerts</th><td>{{ stats.dos }}</td></tr>
    </table>

    <h2>Detected Events</h2>
    {% if alerts %}
      {% for a in alerts %}
        <div class=\"alert alert-danger mb-2\"><strong>{{ a[0] }}:</strong> {{ a[1] }}</div>
      {% endfor %}
    {% else %}
      <p>No suspicious activity detected.</p>
    {% endif %}
    
    {% if device_alerts %}
    <h2>Detected Devices</h2>
    <div class=\"table-responsive\">
      <table class=\"table table-striped table-hover\">
        <thead>
          <tr>
            <th>IP</th>
            <th>Hostname</th>
            <th>Attack Type</th>
            <th>Count</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {% for ip, info in device_alerts.items() %}
          <tr>
            <td>{{ ip }}</td>
            <td>{{ info.hostname if info.hostname else 'Unknown' }}</td>
            <td>{{ info.type }}</td>
            <td>{{ info.count }}</td>
            <td><a href=\"/device/{{ ip }}\" class=\"btn btn-sm btn-primary\">View Details</a></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}

    <h2>Recent Logs</h2>
    <div class=\"log-box border rounded p-2 bg-light\">
    {% for line in logs %}
      {{ line }}<br>
    {% endfor %}
    </div>
  </div>
</body>
</html>
"""

LOG_TEMPLATE = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>SysLogger Logs</title>
  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\">
  <style>
    body {padding-top:4rem;}
    .log-box {height:400px; overflow-y:auto; font-family:monospace;}
  </style>
</head>
<body>
  <nav class=\"navbar navbar-dark bg-dark fixed-top\">
    <div class=\"container-fluid\">
      <a class=\"navbar-brand\" href=\"/\">SysLogger</a>
    </div>
  </nav>
  <div class=\"container mt-4\">
    <form method=\"get\" action=\"/logs\" class=\"d-flex mb-3\">
      <input type=\"text\" class=\"form-control me-2\" name=\"q\" value=\"{{ q }}\" placeholder=\"Filter text\"/>
      <button type=\"submit\" class=\"btn btn-primary me-2\">Search</button>
      <a class=\"btn btn-secondary\" href=\"/download\">Download</a>
    </form>
    <div class=\"log-box border rounded p-2 bg-light\">
    {% for line in logs %}
      {{ line }}<br>
    {% endfor %}
    </div>
    <p class=\"mt-3\"><a href=\"/\">Back to Dashboard</a></p>
  </div>
</body>
</html>
"""

# Updated device info template for displaying device information
DEVICE_TEMPLATE = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>Device Information</title>
  <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\">
  <style>
    body {padding-top:4rem;}
    .device-info {font-family:monospace;}
  </style>
</head>
<body>
  <nav class=\"navbar navbar-dark bg-dark fixed-top\">
    <div class=\"container-fluid\">
      <a class=\"navbar-brand\" href=\"/\">SysLogger</a>
    </div>
  </nav>
  <div class=\"container mt-4\">
    <h2>Device Information: {{ device.ip }}</h2>
    
    <div class=\"card mb-3\">
      <div class=\"card-header\">
        <strong>Basic Information</strong>
      </div>
      <div class=\"card-body\">
        <p><strong>IP:</strong> {{ device.ip }}</p>
        <p><strong>Hostname:</strong> {{ device.hostname or 'Unknown' }}</p>
        <p><strong>MAC Address:</strong> {{ device.mac or 'Unknown' }}</p>
        <p><strong>First Seen:</strong> {{ device.first_seen }}</p>
        <p><strong>Last Seen:</strong> {{ device.last_seen }}</p>
        <p><strong>Detection Count:</strong> {{ device.detection_count }}</p>
      </div>
    </div>

    <div class=\"card mb-3\">
      <div class=\"card-header\">
        <strong>Attack History</strong>
      </div>
      <div class=\"card-body\">
        <p><strong>Attack Types:</strong></p>
        <ul>
        {% for attack_type in attack_types %}
          <li>{{ attack_type }}</li>
        {% endfor %}
        </ul>
      </div>
    </div>

    <div class=\"card mb-3\">
      <div class=\"card-header\">
        <strong>Network Information</strong>
      </div>
      <div class=\"card-body device-info\">
        <pre>{{ network_info | tojson(indent=2) }}</pre>
      </div>
    </div>

    <p class=\"mt-3\"><a href=\"/\" class=\"btn btn-primary\">Back to Dashboard</a></p>
  </div>
</body>
</html>
"""

def analyze_logs():
    alerts = []
    device_alerts = {}
    stats = {
        "deauth": 0,
        "auth_fail": 0,
        "port_scan": 0,
        "dhcp": 0,
        "firewall": 0,
        "dos": 0,
    }
    cutoff = time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(time.time() - DETECTION_WINDOW),
    )
    try:
        cur = db_conn.cursor()
        cur.execute(
            "SELECT message FROM logs WHERE timestamp >= ? ORDER BY rowid DESC",
            (cutoff,),
        )
        rows = cur.fetchall()
        lines = [r[0] for r in rows]
    except Exception:
        return alerts, stats, device_alerts

    deauth_map = {}  # MAC -> count
    auth_fail_map = {}  # IP/Client -> count
    port_scan_map = {}  # IP -> count
    dhcp_map = {}  # MAC -> count
    firewall_map = {}  # IP -> count
    dos_map = {}  # IP -> count

    for line in lines:
        if "Deauth" in line or "deauth" in line:
            match = re.search(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", line)
            if match:
                mac = match.group(1)
                deauth_map[mac] = deauth_map.get(mac, 0) + 1

        if "Auth fail" in line or "auth fail" in line:
            match = re.search(r"from ([\d\.]+|[0-9A-Fa-f:]+|[\w-]+)", line)
            if match:
                client = match.group(1)
                auth_fail_map[client] = auth_fail_map.get(client, 0) + 1

        if "scan" in line.lower():
            match = re.search(r"([\d\.]+|[0-9A-Fa-f:]+)", line)
            if match:
                ip = match.group(1)
                port_scan_map[ip] = port_scan_map.get(ip, 0) + 1

        if "DHCP request" in line or "dhcp discover" in line.lower():
            match = re.search(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})", line)
            if match:
                mac = match.group(1)
                dhcp_map[mac] = dhcp_map.get(mac, 0) + 1

        if "DROP" in line or "SYN flood" in line or "RST flood" in line:
            match = re.search(r"SRC=([\d\.]+)", line) or re.search(r"src=([\d\.]+)", line) or re.search(r"from ([\d\.]+)", line)
            if match:
                ip = match.group(1)
                firewall_map[ip] = firewall_map.get(ip, 0) + 1

        if "DoS" in line or "DDoS" in line or "dos_" in line or "flood" in line.lower():
            match = re.search(r"([\d\.]+|[0-9A-Fa-f:]+)", line)
            if match:
                ip = match.group(1)
                dos_map[ip] = dos_map.get(ip, 0) + 1

    # Process alerts and gather device information
    for mac, count in deauth_map.items():
        stats["deauth"] += count
        if count >= DEAUTH_THRESHOLD:
            # Try to find an IP for this MAC address
            ip_for_mac = None
            try:
                # Check if we have the IP for this MAC in our database
                cur = db_conn.cursor()
                cur.execute("SELECT ip FROM devices WHERE mac = ?", (mac,))
                device = cur.fetchone()
                if device:
                    ip_for_mac = device[0]
            except Exception:
                pass
            
            alert_text = f"{mac} seen {count} times"
            alerts.append(("Deauth Attack", alert_text))
            
            # Add device information
            if ip_for_mac and is_valid_ip(ip_for_mac):
                device_info = gather_device_info(ip_for_mac, "Deauth Attack")
                if device_info:
                    device_alerts[ip_for_mac] = {
                        "type": "Deauth Attack",
                        "count": count,
                        "identifier": mac,
                        "info": device_info
                    }

    for client, count in auth_fail_map.items():
        stats["auth_fail"] += count
        if count >= AUTH_FAIL_THRESHOLD:
            alert_text = f"{client} seen {count} times"
            alerts.append(("Auth Failures", alert_text))
            
            # Add device information if client is an IP
            if is_valid_ip(client):
                device_info = gather_device_info(client, "Auth Failures")
                if device_info:
                    device_alerts[client] = {
                        "type": "Auth Failures",
                        "count": count,
                        "identifier": client,
                        "info": device_info
                    }

    for ip, count in port_scan_map.items():
        stats["port_scan"] += count
        if count >= PORT_SCAN_THRESHOLD:
            alert_text = f"{ip} seen {count} times"
            alerts.append(("Port Scan", alert_text))
            
            # Add device information
            if is_valid_ip(ip):
                device_info = gather_device_info(ip, "Port Scan")
                if device_info:
                    device_alerts[ip] = {
                        "type": "Port Scan",
                        "count": count,
                        "identifier": ip,
                        "info": device_info
                    }

    for mac, count in dhcp_map.items():
        stats["dhcp"] += count
        if count >= DHCP_REQ_THRESHOLD:
            alert_text = f"{mac} seen {count} times"
            alerts.append(("DHCP Flood", alert_text))
            
            # Try to find an IP for this MAC address
            ip_for_mac = None
            try:
                # Check if we have the IP for this MAC in our database
                cur = db_conn.cursor()
                cur.execute("SELECT ip FROM devices WHERE mac = ?", (mac,))
                device = cur.fetchone()
                if device:
                    ip_for_mac = device[0]
            except Exception:
                pass
            
            # Add device information
            if ip_for_mac and is_valid_ip(ip_for_mac):
                device_info = gather_device_info(ip_for_mac, "DHCP Flood")
                if device_info:
                    device_alerts[ip_for_mac] = {
                        "type": "DHCP Flood",
                        "count": count,
                        "identifier": mac,
                        "info": device_info
                    }

    for ip, count in firewall_map.items():
        stats["firewall"] += count
        if count >= FIREWALL_THRESHOLD:
            alert_text = f"{ip} seen {count} times"
            alerts.append(("Firewall Drops", alert_text))
            
            # Add device information
            if is_valid_ip(ip):
                device_info = gather_device_info(ip, "Firewall Drops")
                if device_info:
                    device_alerts[ip] = {
                        "type": "Firewall Drops",
                        "count": count,
                        "identifier": ip,
                        "info": device_info
                    }

    for ip, count in dos_map.items():
        stats["dos"] += count
        if count >= DOS_THRESHOLD:
            alert_text = f"{ip} seen {count} times"
            alerts.append(("Possible DoS", alert_text))
            
            # Add device information
            if is_valid_ip(ip):
                device_info = gather_device_info(ip, "Possible DoS")
                if device_info:
                    device_alerts[ip] = {
                        "type": "Possible DoS",
                        "count": count,
                        "identifier": ip,
                        "info": device_info
                    }

    return alerts, stats, device_alerts

def get_recent_logs(num=WEB_LOG_LINES):
    try:
        cur = db_conn.cursor()
        cur.execute(
            "SELECT timestamp, host, message FROM logs ORDER BY rowid DESC LIMIT ?",
            (num,),
        )
        rows = cur.fetchall()
    except Exception:
        return []
    return [f"{ts} {host} {msg}" for ts, host, msg in reversed(rows)]

def get_filtered_logs(query=None, num=1000):
    try:
        cur = db_conn.cursor()
        base = "SELECT timestamp, host, message FROM logs"
        params = []
        if query:
            keywords = [kw.lower() for kw in query.split() if kw]
            if keywords:
                conditions = " AND ".join(["LOWER(message) LIKE ?"] * len(keywords))
                base += " WHERE " + conditions
                params.extend([f"%{kw}%" for kw in keywords])
        base += " ORDER BY rowid DESC LIMIT ?"
        params.append(num)
        cur.execute(base, params)
        rows = cur.fetchall()
    except Exception:
        return []
    return [f"{ts} {host} {msg}" for ts, host, msg in reversed(rows)]


def get_device_info(ip):
    """Get full device information from the database"""
    try:
        cur = db_conn.cursor()
        cur.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
        device = cur.fetchone()
        
        if device:
            return {
                "ip": device[0],
                "hostname": device[1],
                "mac": device[2],
                "first_seen": device[3],
                "last_seen": device[4],
                "attack_types": json.loads(device[5]) if device[5] else [],
                "detection_count": device[6],
                "device_info": json.loads(device[7]) if device[7] else {}
            }
        return None
    except Exception as e:
        logger.error(f"Error getting device info: {e}")
        return None

def get_all_devices():
    """Get all devices from the database"""
    try:
        cur = db_conn.cursor()
        cur.execute("SELECT * FROM devices ORDER BY detection_count DESC")
        devices = cur.fetchall()
        
        result = []
        for device in devices:
            result.append({
                "ip": device[0],
                "hostname": device[1],
                "mac": device[2],
                "first_seen": device[3],
                "last_seen": device[4],
                "attack_types": json.loads(device[5]) if device[5] else [],
                "detection_count": device[6],
                "device_info": json.loads(device[7]) if device[7] else {}
            })
        return result
    except Exception as e:
        logger.error(f"Error getting all devices: {e}")
        return []

@app.route('/')
def index():
    alerts, stats, device_alerts = analyze_logs()
    logs = get_recent_logs()
    
    # Add hostname information to device alerts
    for ip, info in device_alerts.items():
        device = get_device_info(ip)
        if device:
            info["hostname"] = device["hostname"]
    
    return render_template_string(INDEX_TEMPLATE, alerts=alerts, logs=logs, stats=stats, device_alerts=device_alerts)


@app.route('/logs')
def view_logs():
    query = request.args.get('q', '')
    logs = get_filtered_logs(query)
    return render_template_string(LOG_TEMPLATE, logs=logs, q=query)


@app.route('/download')
def download_logs():
    if os.path.exists(LOG_FILE):
        return send_file(LOG_FILE, as_attachment=True)
    return 'Log file not found', 404

@app.route('/devices')
def devices_list():
    devices = get_all_devices()
    device_count = len(devices)
    
    html = f'''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Detected Devices</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <style>
    body {{padding-top:4rem;}}
  </style>
</head>
<body>
  <nav class="navbar navbar-dark bg-dark fixed-top">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">SysLogger</a>
    </div>
  </nav>
  <div class="container mt-4">
    <h2>Detected Devices ({device_count})</h2>
    
    <div class="table-responsive">
      <table class="table table-striped table-hover">
        <thead>
          <tr>
            <th>IP</th>
            <th>Hostname</th>
            <th>MAC</th>
            <th>Detection Count</th>
            <th>Last Seen</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
'''
    
    for device in devices:
        hostname = device.get('hostname', 'Unknown')
        mac = device.get('mac', 'Unknown')
        html += f'''
          <tr>
            <td>{device['ip']}</td>
            <td>{hostname}</td>
            <td>{mac}</td>
            <td>{device['detection_count']}</td>
            <td>{device['last_seen']}</td>
            <td><a href="/device/{device['ip']}" class="btn btn-sm btn-primary">View Details</a></td>
          </tr>
'''
    
    html += '''
        </tbody>
      </table>
    </div>
    
    <p class="mt-3"><a href="/" class="btn btn-secondary">Back to Dashboard</a></p>
  </div>
</body>
</html>
'''
    
    return html

@app.route('/device/<ip>')
def device_detail(ip):
    device = get_device_info(ip)
    if not device:
        return 'Device not found', 404
    
    # Prepare device information
    attack_types = device.get('attack_types', [])
    network_info = device.get('device_info', {}).get('network_info', {})
    
    return render_template_string(
        DEVICE_TEMPLATE, 
        device=device, 
        attack_types=attack_types, 
        network_info=network_info
    )

if LOG_TO_STDOUT:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

if FORWARD_HOST and FORWARD_PORT:
    try:
        forward_handler = logging.handlers.SysLogHandler(address=(FORWARD_HOST, int(FORWARD_PORT)))
        forward_handler.setFormatter(formatter)
        logger.addHandler(forward_handler)
        logger.info(f"Forwarding enabled: {FORWARD_HOST}:{FORWARD_PORT}")
    except Exception as e:
        logger.error(f"Failed to configure forwarding: {e}")

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip(), errors="ignore")
        ts, host, msg = parse_syslog_message(data, self.client_address[0])
        insert_log(ts, host, msg)
        logger.info(f"{host} {msg}")

class SyslogTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline().strip().decode(errors="ignore")
        ts, host, msg = parse_syslog_message(data, self.client_address[0])
        insert_log(ts, host, msg)
        logger.info(f"{host} {msg}")


def run_udp_server(host=BIND_HOST, port=UDP_PORT):
    try:
        logger.info(f"Starting UDP syslog server on {host}:{port}")
        with socketserver.ThreadingUDPServer((host, port), SyslogUDPHandler) as server:
            server.serve_forever()
    except Exception as e:
        logger.error(f"UDP server failed to start: {str(e)}")
        # If permission error and port < 1024, try fallback
        if isinstance(e, PermissionError) and port < 1024:
            fallback_port = 5140  # Common unprivileged syslog alternative
            logger.warning(f"Permission error on port {port}, trying fallback port {fallback_port}")
            try:
                with socketserver.ThreadingUDPServer((host, fallback_port), SyslogUDPHandler) as server:
                    logger.info(f"UDP server started on fallback port {fallback_port}")
                    server.serve_forever()
            except Exception as e2:
                logger.error(f"UDP fallback server failed: {str(e2)}")
        raise


def run_tcp_server(host=BIND_HOST, port=TCP_PORT):
    try:
        logger.info(f"Starting TCP syslog server on {host}:{port}")
        with socketserver.ThreadingTCPServer((host, port), SyslogTCPHandler) as server:
            server.serve_forever()
    except Exception as e:
        logger.error(f"TCP server failed to start: {str(e)}")
        # If permission error and port < 1024, try fallback
        if isinstance(e, PermissionError) and port < 1024:
            fallback_port = 5140  # Common unprivileged syslog alternative
            logger.warning(f"Permission error on port {port}, trying fallback port {fallback_port}")
            try:
                with socketserver.ThreadingTCPServer((host, fallback_port), SyslogTCPHandler) as server:
                    logger.info(f"TCP server started on fallback port {fallback_port}")
                    server.serve_forever()
            except Exception as e2:
                logger.error(f"TCP fallback server failed: {str(e2)}")
        raise


def run_web_server(host=BIND_HOST, port=WEB_PORT):
    app.run(host=host, port=port, debug=False, use_reloader=False)


def main():
    threads = []
    thread_status = {}
    
    # Log environment settings
    logger.info(f"Starting SysLogger with configuration:")
    logger.info(f"  UDP: {ENABLE_UDP} (port {UDP_PORT})")
    logger.info(f"  TCP: {ENABLE_TCP} (port {TCP_PORT})")
    logger.info(f"  WEB: {ENABLE_WEB} (port {WEB_PORT})")
    logger.info(f"  BIND_HOST: {BIND_HOST}")
    logger.info(f"  LOG_FILE: {LOG_FILE}")
    logger.info(f"  DB_FILE: {DB_FILE}")
    
    # Function to wrap thread target with error reporting
    def thread_wrapper(name, target_func):
        thread_status[name] = "starting"
        try:
            logger.info(f"Thread {name} starting")
            target_func()
            thread_status[name] = "running"
        except Exception as e:
            thread_status[name] = f"error: {str(e)}"
            logger.error(f"Thread {name} failed: {str(e)}")
    
    if ENABLE_UDP:
        udp_thread = threading.Thread(
            target=lambda: thread_wrapper("UDP", run_udp_server),
            daemon=True,
            name="UDP_Server"
        )
        udp_thread.start()
        threads.append(udp_thread)
        
    if ENABLE_TCP:
        tcp_thread = threading.Thread(
            target=lambda: thread_wrapper("TCP", run_tcp_server), 
            daemon=True,
            name="TCP_Server"
        )
        tcp_thread.start()
        threads.append(tcp_thread)
        
    if ENABLE_WEB:
        web_thread = threading.Thread(
            target=lambda: thread_wrapper("WEB", run_web_server), 
            daemon=True,
            name="Web_Server"
        )
        web_thread.start()
        threads.append(web_thread)

    if not threads:
        logger.error('No services enabled. Enable UDP, TCP and/or WEB interface.')
        return

    logger.info('SysLogger startup complete')
    
    # Wait a bit and log thread status
    time.sleep(5) 
    logger.info(f"Thread status after startup:")
    for name, status in thread_status.items():
        logger.info(f"  {name}: {status}")
    
    try:
        while True:
            time.sleep(10)
            alive_count = sum(1 for t in threads if t.is_alive())
            if alive_count < len(threads):
                logger.warning(f"Only {alive_count}/{len(threads)} threads still running")
                for t in threads:
                    if not t.is_alive():
                        logger.error(f"Thread {t.name} died unexpectedly")
    except KeyboardInterrupt:
        logger.info('SysLogger stopping')


if __name__ == '__main__':
    main()
