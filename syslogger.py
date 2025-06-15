#!/usr/bin/env python3
import os
import logging
import logging.handlers
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

    if not threads:
        logger.error('No protocols enabled. Set ENABLE_UDP and/or ENABLE_TCP.')
        return

    logger.info('SysLogger started')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info('SysLogger stopping')


if __name__ == '__main__':
    main()
