#!/usr/bin/env python3
import os
import logging
import logging.handlers
from flask import Flask, render_template_string
import socketserver
import threading
import time

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

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logger = logging.getLogger('syslogger')
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter('%(asctime)s %(message)s')

file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT
)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Web interface setup
app = Flask(__name__)

INDEX_TEMPLATE = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <title>SysLogger Dashboard</title>
  <style>
    body {font-family: Arial, Helvetica, sans-serif; margin:0; background:#f5f5f5;}
    header {background:#2c3e50; color:#fff; padding:20px 0; text-align:center;}
    .container {max-width:800px; margin:20px auto; padding:20px; background:#fff;
        box-shadow:0 2px 4px rgba(0,0,0,0.1); border-radius:4px;}
    .alert {background:#f8d7da; border-left:4px solid #c0392b; padding:10px; margin-bottom:10px;}
    .log {background:#fafafa; padding:10px; height:300px; overflow-y:auto; font-family:monospace; border:1px solid #ddd;}
    h2 {border-bottom:1px solid #eee; padding-bottom:4px; margin-top:20px;}
  </style>
</head>
<body>
  <header>
    <h1>SysLogger Dashboard</h1>
  </header>
  <div class=\"container\">
    <h2>Detected Events</h2>
    {% if alerts %}
      {% for a in alerts %}
        <div class=\"alert\"><strong>{{ a[0] }}:</strong> {{ a[1] }}</div>
      {% endfor %}
    {% else %}
      <p>No suspicious activity detected.</p>
    {% endif %}

    <h2>Recent Logs</h2>
    <div class=\"log\">
    {% for line in logs %}
      {{ line }}<br>
    {% endfor %}
    </div>
  </div>
</body>
</html>
"""

def analyze_logs():
    alerts = []
    if not os.path.exists(LOG_FILE):
        return alerts
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()[-1000:]
    except Exception:
        return alerts
    for line in lines:
        lower = line.lower()
        if 'deauth' in lower or 'disassoc' in lower:
            alerts.append(('Deauthentication', line.strip()))
        elif 'failed password' in lower or 'authentication failure' in lower:
            alerts.append(('Authentication Failure', line.strip()))
    return alerts

def get_recent_logs(num=WEB_LOG_LINES):
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()[-num:]
    except Exception:
        return []
    return [line.strip() for line in lines]


@app.route('/')
def index():
    alerts = analyze_logs()
    logs = get_recent_logs()
    return render_template_string(INDEX_TEMPLATE, alerts=alerts, logs=logs)

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
        data = bytes.decode(self.request[0].strip())
        logger.info(f"{self.client_address[0]} {data}")

class SyslogTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline().strip().decode()
        logger.info(f"{self.client_address[0]} {data}")


def run_udp_server(host=BIND_HOST, port=UDP_PORT):
    with socketserver.ThreadingUDPServer((host, port), SyslogUDPHandler) as server:
        server.serve_forever()


def run_tcp_server(host=BIND_HOST, port=TCP_PORT):
    with socketserver.ThreadingTCPServer((host, port), SyslogTCPHandler) as server:
        server.serve_forever()


def run_web_server(host=BIND_HOST, port=WEB_PORT):
    app.run(host=host, port=port, debug=False, use_reloader=False)


def main():
    threads = []
    if ENABLE_UDP:
        udp_thread = threading.Thread(target=run_udp_server, daemon=True)
        udp_thread.start()
        threads.append(udp_thread)
    if ENABLE_TCP:
        tcp_thread = threading.Thread(target=run_tcp_server, daemon=True)
        tcp_thread.start()
        threads.append(tcp_thread)
    if ENABLE_WEB:
        web_thread = threading.Thread(target=run_web_server, daemon=True)
        web_thread.start()
        threads.append(web_thread)

    if not threads:
        logger.error('No services enabled. Enable UDP, TCP and/or WEB interface.')
        return

    logger.info('SysLogger started')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info('SysLogger stopping')


if __name__ == '__main__':
    main()
