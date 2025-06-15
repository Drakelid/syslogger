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

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logger = logging.getLogger('syslogger')
logger.setLevel(LOG_LEVEL)

formatter = logging.Formatter('%(asctime)s %(message)s')

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

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


def run_udp_server(host='0.0.0.0', port=514):
    server = socketserver.ThreadingUDPServer((host, port), SyslogUDPHandler)
    server.serve_forever()


def run_tcp_server(host='0.0.0.0', port=514):
    server = socketserver.ThreadingTCPServer((host, port), SyslogTCPHandler)
    server.serve_forever()


def main():
    udp_thread = threading.Thread(target=run_udp_server, daemon=True)
    tcp_thread = threading.Thread(target=run_tcp_server, daemon=True)

    udp_thread.start()
    tcp_thread.start()

    logger.info('SysLogger started')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info('SysLogger stopping')


if __name__ == '__main__':
    main()
