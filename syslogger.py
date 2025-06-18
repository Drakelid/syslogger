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
import ipaddress
import json
import datetime
import subprocess
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

# Third-party imports
try:
    import geoip2.database
    import geoip2.errors
    import dns.resolver
    import dns.exception
    import whois
    import nmap
    import requests
except ImportError:
    print("Warning: Some third-party modules are missing. Install them with:")
    print("pip install -r requirements.txt")

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
ATTACKER_INFO_DB = os.getenv('ATTACKER_INFO_DB', '/logs/attacker_info.db')
GEOIP_DB_PATH = os.getenv('GEOIP_DB_PATH', '/logs/GeoLite2-City.mmdb')
ENABLE_SCAN = os.getenv('ENABLE_SCAN', 'false').lower() in ('1', 'true', 'yes')
PORT_SCAN_TIMEOUT = int(os.getenv('PORT_SCAN_TIMEOUT', '5'))  # seconds
THREAT_INTEL_API_KEY = os.getenv('THREAT_INTEL_API_KEY', '')
THREAD_POOL_SIZE = int(os.getenv('THREAD_POOL_SIZE', '5'))

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

# Database for storing attacker information
attacker_db = sqlite3.connect(ATTACKER_INFO_DB, check_same_thread=False)
attacker_db.execute("""
    CREATE TABLE IF NOT EXISTS attackers (
        identifier TEXT PRIMARY KEY,
        ip TEXT,
        mac TEXT,
        first_seen TEXT,
        last_seen TEXT,
        attack_types TEXT,
        hostname TEXT,
        geolocation TEXT,
        open_ports TEXT,
        os_info TEXT,
        reputation TEXT,
        connections TEXT
    )
""")

SYSLOG_RE = re.compile(r"(?:<\d+>)?(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.*)")

# Thread pool for running concurrent lookups
thread_pool = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE)

class AttackerInfo:
    """Class to store and manage information about attacking devices"""
    
    def __init__(self, identifier, ip=None, mac=None):
        """
        Initialize attacker info
        
        Args:
            identifier: Unique identifier (IP or MAC)
            ip: IP address if available
            mac: MAC address if available
        """
        self.identifier = identifier
        self.ip = ip
        self.mac = mac
        self.first_seen = self.last_seen = datetime.datetime.now().isoformat()
        self.attack_types = []
        self.hostname = None
        self.geolocation = {}
        self.open_ports = {}
        self.os_info = {}
        self.reputation = {}
        self.connections = []
        
    def to_dict(self):
        """Convert to dictionary for storage"""
        return {
            'identifier': self.identifier,
            'ip': self.ip,
            'mac': self.mac,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'attack_types': self.attack_types,
            'hostname': self.hostname,
            'geolocation': self.geolocation,
            'open_ports': self.open_ports,
            'os_info': self.os_info,
            'reputation': self.reputation,
            'connections': self.connections
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create instance from dictionary"""
        instance = cls(data['identifier'], data.get('ip'), data.get('mac'))
        instance.first_seen = data.get('first_seen')
        instance.last_seen = data.get('last_seen')
        instance.attack_types = data.get('attack_types', [])
        instance.hostname = data.get('hostname')
        instance.geolocation = data.get('geolocation', {})
        instance.open_ports = data.get('open_ports', {})
        instance.os_info = data.get('os_info', {})
        instance.reputation = data.get('reputation', {})
        instance.connections = data.get('connections', [])
        return instance
    
    def update_last_seen(self):
        """Update the last seen timestamp"""
        self.last_seen = datetime.datetime.now().isoformat()
    
    def add_attack_type(self, attack_type):
        """Add an attack type to the list"""
        if attack_type not in self.attack_types:
            self.attack_types.append(attack_type)
    
    def add_connection(self, details):
        """Add connection details to history"""
        conn_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'details': details
        }
        self.connections.append(conn_entry)
        # Keep only last 100 connections
        if len(self.connections) > 100:
            self.connections = self.connections[-100:]


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

def insert_log(ts, host, message):
    try:
        db_conn.execute(
            "INSERT INTO logs (timestamp, host, message) VALUES (?, ?, ?)",
            (ts, host, message),
        )
        db_conn.commit()
    except Exception as e:
        logger.error(f"DB insert failed: {e}")


def get_or_create_attacker_info(identifier, ip=None, mac=None):
    """Get existing attacker info or create new"""
    try:
        cur = attacker_db.cursor()
        cur.execute("SELECT * FROM attackers WHERE identifier = ?", (identifier,))
        row = cur.fetchone()
        
        if row:
            # Convert stored JSON strings back to objects
            attack_types = json.loads(row[5]) if row[5] else []
            geolocation = json.loads(row[7]) if row[7] else {}
            open_ports = json.loads(row[8]) if row[8] else {}
            os_info = json.loads(row[9]) if row[9] else {}
            reputation = json.loads(row[10]) if row[10] else {}
            connections = json.loads(row[11]) if row[11] else []
            
            attacker = AttackerInfo(identifier)
            attacker.ip = row[1]
            attacker.mac = row[2]
            attacker.first_seen = row[3]
            attacker.last_seen = row[4]
            attacker.attack_types = attack_types
            attacker.hostname = row[6]
            attacker.geolocation = geolocation
            attacker.open_ports = open_ports
            attacker.os_info = os_info
            attacker.reputation = reputation
            attacker.connections = connections
            
            # Update last seen
            attacker.update_last_seen()
        else:
            # Create new attacker record
            attacker = AttackerInfo(identifier, ip, mac)
            
        return attacker
    except Exception as e:
        logger.error(f"Error getting attacker info: {e}")
        return AttackerInfo(identifier, ip, mac)


def save_attacker_info(attacker):
    """Save attacker information to database"""
    try:
        attacker_dict = attacker.to_dict()
        
        # Convert complex objects to JSON strings
        attack_types_json = json.dumps(attacker_dict['attack_types'])
        geolocation_json = json.dumps(attacker_dict['geolocation'])
        open_ports_json = json.dumps(attacker_dict['open_ports'])
        os_info_json = json.dumps(attacker_dict['os_info'])
        reputation_json = json.dumps(attacker_dict['reputation'])
        connections_json = json.dumps(attacker_dict['connections'])
        
        attacker_db.execute(
            """INSERT OR REPLACE INTO attackers 
               (identifier, ip, mac, first_seen, last_seen, attack_types, 
                hostname, geolocation, open_ports, os_info, reputation, connections) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (attacker_dict['identifier'], attacker_dict['ip'], attacker_dict['mac'],
             attacker_dict['first_seen'], attacker_dict['last_seen'], attack_types_json,
             attacker_dict['hostname'], geolocation_json, open_ports_json,
             os_info_json, reputation_json, connections_json)
        )
        attacker_db.commit()
    except Exception as e:
        logger.error(f"Error saving attacker info: {e}")


@lru_cache(maxsize=1000)
def resolve_hostname(ip):
    """Resolve hostname for IP using reverse DNS lookup"""
    try:
        if not ip or not isinstance(ip, str) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return None
            
        hostname = socket.getfqdn(ip)
        if hostname != ip:  # If no hostname found, getfqdn returns the IP
            return hostname
            
        # Try to use dnspython for more robust lookup
        try:
            addr = dns.reversename.from_address(ip)
            hostname = str(dns.resolver.resolve(addr, "PTR")[0])
            return hostname
        except (dns.exception.DNSException, IndexError):
            pass
            
        return None
    except Exception as e:
        logger.error(f"Error resolving hostname: {e}")
        return None


@lru_cache(maxsize=1000)
def get_geolocation(ip):
    """Get geolocation information for IP address"""
    geo_data = {}
    
    try:
        if not ip or not isinstance(ip, str) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return geo_data
            
        # Check if it's a private IP
        if ipaddress.ip_address(ip).is_private:
            geo_data = {"country": "Private Network", "city": "Local"}
            return geo_data
            
        # Try GeoIP database if available
        if os.path.exists(GEOIP_DB_PATH):
            try:
                with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
                    response = reader.city(ip)
                    geo_data = {
                        "country": response.country.name,
                        "country_code": response.country.iso_code,
                        "city": response.city.name,
                        "postal": response.postal.code,
                        "latitude": response.location.latitude,
                        "longitude": response.location.longitude
                    }
                    return geo_data
            except (geoip2.errors.AddressNotFoundError, FileNotFoundError):
                pass
                
        # Try free IP API as fallback
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    geo_data = {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "city": data.get("city"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org")
                    }
        except (requests.RequestException, ValueError):
            pass
            
        return geo_data
    except Exception as e:
        logger.error(f"Error getting geolocation: {e}")
        return geo_data


def scan_ports(ip):
    """Scan for open ports on target IP"""
    ports_info = {}
    
    if not ENABLE_SCAN:
        return {"status": "scan disabled"}
        
    try:
        if not ip or not isinstance(ip, str) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return {"status": "invalid IP"}
            
        # Check if it's a private IP - we can scan these
        if not ipaddress.ip_address(ip).is_private:
            # For external IPs, limit scan to avoid violating laws
            return {"status": "external IP - scan limited"}
        
        # Use python-nmap for scanning
        try:
            nm = nmap.PortScanner()
            # Quick scan of common ports
            scan_result = nm.scan(ip, '21-23,25,53,80,443,3306,3389,8080,8443', 
                                 arguments=f'-T4 --max-retries 1 --host-timeout {PORT_SCAN_TIMEOUT}s')
            
            if ip in nm.all_hosts():
                ports_info["status"] = "scanned"
                ports_info["open_ports"] = {}
                
                for port in nm[ip].get('tcp', {}):
                    service = nm[ip]['tcp'][port]
                    if service['state'] == 'open':
                        ports_info["open_ports"][str(port)] = {
                            "service": service.get('name', 'unknown'),
                            "version": service.get('product', '') + ' ' + service.get('version', ''),
                            "extra_info": service.get('extrainfo', '')
                        }
        except Exception as scan_error:
            ports_info["status"] = f"scan error: {str(scan_error)}"
        
        return ports_info
    except Exception as e:
        logger.error(f"Error scanning ports: {e}")
        return {"status": "error"}


def detect_os(ip):
    """Detect OS of target IP"""
    os_info = {}
    
    if not ENABLE_SCAN:
        return {"status": "scan disabled"}
        
    try:
        if not ip or not isinstance(ip, str) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return {"status": "invalid IP"}
            
        # Check if it's a private IP
        if not ipaddress.ip_address(ip).is_private:
            # For external IPs, limit scan to avoid violating laws
            return {"status": "external IP - scan limited"}
        
        # Use python-nmap for OS detection
        try:
            nm = nmap.PortScanner()
            # OS detection requires sudo privileges, fallback to service detection
            scan_result = nm.scan(ip, arguments=f'-O -T4 --max-retries 1 --host-timeout {PORT_SCAN_TIMEOUT}s')
            
            if ip in nm.all_hosts():
                os_matches = scan_result.get('scan', {}).get(ip, {}).get('osmatch', [])
                if os_matches:
                    os_info["os_matches"] = []
                    for os_match in os_matches[:3]:  # Get top 3 matches
                        os_info["os_matches"].append({
                            "name": os_match.get('name', 'Unknown'),
                            "accuracy": os_match.get('accuracy', '0')
                        })
                    os_info["status"] = "detected"
                else:
                    os_info["status"] = "no OS match"
        except Exception as scan_error:
            os_info["status"] = f"scan error: {str(scan_error)}"
        
        return os_info
    except Exception as e:
        logger.error(f"Error detecting OS: {e}")
        return {"status": "error"}


def check_reputation(ip):
    """Check reputation of IP using threat intelligence services"""
    reputation = {}
    
    try:
        if not ip or not isinstance(ip, str) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return reputation
            
        # Check if it's a private IP
        if ipaddress.ip_address(ip).is_private:
            reputation = {"status": "private IP"}
            return reputation
            
        # Check AbuseIPDB API if key is available
        if THREAT_INTEL_API_KEY and "ABUSEIPDB" in THREAT_INTEL_API_KEY:
            try:
                api_key = THREAT_INTEL_API_KEY.split(':')[1]
                headers = {
                    'Key': api_key,
                    'Accept': 'application/json',
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90
                }
                response = requests.get(
                    'https://api.abuseipdb.com/api/v2/check',
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json()
                    reputation["abuseipdb"] = {
                        "score": data.get('data', {}).get('abuseConfidenceScore'),
                        "reports": data.get('data', {}).get('totalReports'),
                        "last_reported": data.get('data', {}).get('lastReportedAt')
                    }
            except Exception as api_error:
                reputation["abuseipdb_error"] = str(api_error)
        
        # Use free API alternative
        try:
            response = requests.get(f"https://ipqualityscore.com/api/json/ip/test/{ip}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                reputation["ipqualityscore"] = {
                    "suspicious": data.get('suspicious'),
                    "vpn": data.get('vpn'),
                    "proxy": data.get('proxy'),
                    "tor": data.get('tor'),
                    "fraud_score": data.get('fraud_score')
                }
        except (requests.RequestException, ValueError):
            pass
        
        return reputation
    except Exception as e:
        logger.error(f"Error checking reputation: {e}")
        return {"status": "error"}

app = Flask(__name__)

INDEX_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SysLogger Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <style>
    body {padding-top:4rem;}
    .log-box {height:300px; overflow-y:auto; font-family:monospace;}
    .attacker-info {cursor:pointer; text-decoration:underline; color:blue;}
    .modal-body pre {white-space:pre-wrap; max-height:400px; overflow-y:auto;}
  </style>
  <script>
    function showAttackerDetails(identifier) {
      fetch('/api/attacker/' + encodeURIComponent(identifier))
        .then(response => response.json())
        .then(data => {
          document.getElementById('attackerModalLabel').textContent = 'Attacker: ' + identifier;
          document.getElementById('attackerModalBody').innerHTML = 
            '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
          const attackerModal = new bootstrap.Modal(document.getElementById('attackerModal'));
          attackerModal.show();
        })
        .catch(err => {
          console.error('Error fetching attacker details:', err);
          alert('Error loading attacker details');
        });
    }
  </script>
</head>
<body>
  <nav class="navbar navbar-dark bg-dark fixed-top">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">SysLogger</a>
      <div>
        <a class="btn btn-secondary" href="/logs">View Logs</a>
        <a class="btn btn-info" href="/attackers">View Attackers</a>
      </div>
    </div>
  </nav>
  
  <!-- Attacker Details Modal -->
  <div class="modal fade" id="attackerModal" tabindex="-1" aria-labelledby="attackerModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="attackerModalLabel">Attacker Details</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body" id="attackerModalBody">
          Loading...
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>
  <div class="container mt-4">
    <h2>Attack Statistics</h2>
    <table class="table table-sm">
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
        <div class="alert alert-danger mb-2"><strong>{{ a[0] }}:</strong> {{ a[1] }}</div>
      {% endfor %}
    {% else %}
      <p>No suspicious activity detected.</p>
    {% endif %}

    <h2>Recent Logs</h2>
    <div class="log-box border rounded p-2 bg-light">
    {% for line in logs %}
      {{ line }}<br>
    {% endfor %}
    </div>
  </div>
</body>
</html>
"""

ATTACKER_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SysLogger - Attackers</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <style>
    body {padding-top:4rem;}
    .attacker-info {cursor:pointer; text-decoration:underline; color:blue;}
    .modal-body pre {white-space:pre-wrap; max-height:400px; overflow-y:auto;}
  </style>
  <script>
    function showAttackerDetails(identifier) {
      fetch('/api/attacker/' + encodeURIComponent(identifier))
        .then(response => response.json())
        .then(data => {
          document.getElementById('attackerModalLabel').textContent = 'Attacker: ' + identifier;
          document.getElementById('attackerModalBody').innerHTML = 
            '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
          const attackerModal = new bootstrap.Modal(document.getElementById('attackerModal'));
          attackerModal.show();
        })
        .catch(err => {
          console.error('Error fetching attacker details:', err);
          alert('Error loading attacker details');
        });
    }
  </script>
</head>
<body>
  <nav class="navbar navbar-dark bg-dark fixed-top">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">SysLogger</a>
      <a class="btn btn-secondary" href="/logs">View Logs</a>
    </div>
  </nav>
  
  <!-- Attacker Details Modal -->
  <div class="modal fade" id="attackerModal" tabindex="-1" aria-labelledby="attackerModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="attackerModalLabel">Attacker Details</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body" id="attackerModalBody">
          Loading...
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>
  
  <div class="container mt-4">
    <h2>Detected Attackers</h2>
    
    {% if attackers %}
      <table class="table table-striped table-hover">
        <thead>
          <tr>
            <th>Identifier</th>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Attack Types</th>
            <th>Last Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {% for attacker in attackers %}
            <tr>
              <td>{{ attacker.identifier }}</td>
              <td>{{ attacker.ip }}</td>
              <td>{{ attacker.mac }}</td>
              <td>{{ attacker.attack_types|join(', ') }}</td>
              <td>{{ attacker.last_seen }}</td>
              <td>
                <button class="btn btn-sm btn-primary" 
                        onclick="showAttackerDetails('{{ attacker.identifier }}')">
                  View Details
                </button>
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <div class="alert alert-info">No attackers detected.</div>
    {% endif %}
    
    <p class="mt-3"><a href="/">Back to Dashboard</a></p>
  </div>
</body>
</html>
"""

LOG_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SysLogger Logs</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
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

def analyze_logs():
    alerts = []
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
        return alerts, stats

    deauth_map = {}
    auth_map = {}
    portscan_map = {}
    dhcp_map = {}
    firewall_map = {}
    dos_map = {}

    # Store detected attackers for enhanced info collection
    detected_attackers = {}

    deauth_re = re.compile(r"deauth\w*.*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", re.I)
    deauth_alt = re.compile(r"deauthenticated.*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", re.I)
    auth_re = re.compile(r"failed (?:login|password).*from ([0-9.]+)", re.I)
    port_re = re.compile(r"(?:syn flood|port scan).*from ([0-9.]+)", re.I)
    dhcp_re = re.compile(r"dhcp(?:discover|request).*?((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", re.I)
    firewall_re = re.compile(r"(?:DENY|DROP).*SRC=([0-9.]+)", re.I)
    dos_re = re.compile(r"(?:ddos|dos attack|syn flood).*from ([0-9.]+)", re.I)

    for line in lines:
        if deauth_re.search(line) or deauth_alt.search(line):
            m = re.search(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", line, re.I)
            mac = m.group().lower() if m else "unknown"
            deauth_map[mac] = deauth_map.get(mac, 0) + 1
            # Store attacker info by MAC
            if mac != "unknown":
                if mac not in detected_attackers:
                    detected_attackers[mac] = get_or_create_attacker_info(mac, mac=mac)
                detected_attackers[mac].add_attack_type("Deauth Attack")
                detected_attackers[mac].add_connection({"type": "deauth", "details": line})

        m = auth_re.search(line)
        if m:
            ip = m.group(1)
            auth_map[ip] = auth_map.get(ip, 0) + 1
            # Store attacker info by IP
            if ip not in detected_attackers:
                detected_attackers[ip] = get_or_create_attacker_info(ip, ip=ip)
            detected_attackers[ip].add_attack_type("Auth Brute Force")
            detected_attackers[ip].add_connection({"type": "auth_fail", "details": line})

        m = port_re.search(line)
        if m:
            ip = m.group(1)
            portscan_map[ip] = portscan_map.get(ip, 0) + 1
            alerts.append(("Possible Attack", line.strip()))
            # Store attacker info by IP
            if ip not in detected_attackers:
                detected_attackers[ip] = get_or_create_attacker_info(ip, ip=ip)
            detected_attackers[ip].add_attack_type("Port Scan")
            detected_attackers[ip].add_connection({"type": "port_scan", "details": line})

        m = dhcp_re.search(line)
        if m:
            mac = m.group(1).lower()
            dhcp_map[mac] = dhcp_map.get(mac, 0) + 1
            # Store attacker info by MAC
            if mac not in detected_attackers:
                detected_attackers[mac] = get_or_create_attacker_info(mac, mac=mac)
            detected_attackers[mac].add_attack_type("DHCP Flood")
            detected_attackers[mac].add_connection({"type": "dhcp", "details": line})

        m = firewall_re.search(line)
        if m:
            ip = m.group(1)
            firewall_map[ip] = firewall_map.get(ip, 0) + 1
            # Store attacker info by IP
            if ip not in detected_attackers:
                detected_attackers[ip] = get_or_create_attacker_info(ip, ip=ip)
            detected_attackers[ip].add_attack_type("Firewall Block")
            detected_attackers[ip].add_connection({"type": "firewall", "details": line})

        m = dos_re.search(line)
        if m:
            ip = m.group(1)
            dos_map[ip] = dos_map.get(ip, 0) + 1
            # Store attacker info by IP
            if ip not in detected_attackers:
                detected_attackers[ip] = get_or_create_attacker_info(ip, ip=ip)
            detected_attackers[ip].add_attack_type("DoS Attack")
            detected_attackers[ip].add_connection({"type": "dos", "details": line})

    # Process attackers and generate alerts
    for mac, count in deauth_map.items():
        stats["deauth"] += count
        if count >= DEAUTH_THRESHOLD:
            alert_msg = f"{mac} seen {count} times"
            alerts.append(("Deauth Flood", alert_msg))

    for ip, count in auth_map.items():
        stats["auth_fail"] += count
        if count >= AUTH_FAIL_THRESHOLD:
            alert_msg = f"{ip} failed {count} times"
            alerts.append(("Auth Brute Force", alert_msg))

    for ip, count in portscan_map.items():
        stats["port_scan"] += count
        if count >= PORT_SCAN_THRESHOLD:
            alert_msg = f"{ip} seen {count} times"
            alerts.append(("Port Scans", alert_msg))

    for mac, count in dhcp_map.items():
        stats["dhcp"] += count
        if count >= DHCP_REQ_THRESHOLD:
            alert_msg = f"{mac} seen {count} times"
            alerts.append(("DHCP Flood", alert_msg))

    for ip, count in firewall_map.items():
        stats["firewall"] += count
        if count >= FIREWALL_THRESHOLD:
            alert_msg = f"{ip} seen {count} times"
            alerts.append(("Firewall Drops", alert_msg))

    for ip, count in dos_map.items():
        stats["dos"] += count
        if count >= DOS_THRESHOLD:
            alert_msg = f"{ip} seen {count} times"
            alerts.append(("Possible DoS", alert_msg))

    # Fetch additional information about attackers
    for identifier, attacker in detected_attackers.items():
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', identifier):  # IP address
            # Only fetch additional info for concerning attackers
            is_concerning = False
            if (identifier in auth_map and auth_map[identifier] >= AUTH_FAIL_THRESHOLD) or \
               (identifier in portscan_map and portscan_map[identifier] >= PORT_SCAN_THRESHOLD) or \
               (identifier in firewall_map and firewall_map[identifier] >= FIREWALL_THRESHOLD) or \
               (identifier in dos_map and dos_map[identifier] >= DOS_THRESHOLD):
                is_concerning = True
                
            if is_concerning:
                # Fetch additional info about this IP
                future_hostname = thread_pool.submit(resolve_hostname, identifier)
                future_geo = thread_pool.submit(get_geolocation, identifier)
                future_reputation = thread_pool.submit(check_reputation, identifier)
                
                # Retrieve results from futures
                attacker.hostname = future_hostname.result()
                attacker.geolocation = future_geo.result()
                attacker.reputation = future_reputation.result()
                
                # Only scan on demand for efficiency
                if ENABLE_SCAN:
                    future_ports = thread_pool.submit(scan_ports, identifier)
                    future_os = thread_pool.submit(detect_os, identifier)
                    
                    attacker.open_ports = future_ports.result()
                    attacker.os_info = future_os.result()
                
                # Save the enhanced attacker information
                save_attacker_info(attacker)
                
                # Add enhanced information to alerts
                hostname_info = f", Hostname: {attacker.hostname}" if attacker.hostname else ""
                geo_info = ""
                if attacker.geolocation.get("country"):
                    geo_info = f", Location: {attacker.geolocation.get('city', 'Unknown')}, {attacker.geolocation.get('country', 'Unknown')}"
                
                rep_info = ""
                if attacker.reputation.get("abuseipdb", {}).get("score"):
                    rep_score = attacker.reputation["abuseipdb"]["score"]
                    rep_info = f", Threat Score: {rep_score}/100"
                
                # Append more detailed information to existing alerts
                enhanced_alerts = []
                for alert_type, alert_text in alerts:
                    if identifier in alert_text:
                        new_text = f"{alert_text}{hostname_info}{geo_info}{rep_info}"
                        enhanced_alerts.append((alert_type, new_text))
                    else:
                        enhanced_alerts.append((alert_type, alert_text))
                alerts = enhanced_alerts

    return alerts, stats

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


@app.route('/')
def index():
    alerts, stats = analyze_logs()
    logs = get_recent_logs()
    return render_template_string(INDEX_TEMPLATE, alerts=alerts, logs=logs, stats=stats)


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


@app.route('/attackers')
def view_attackers():
    """View list of attackers"""
    try:
        cur = attacker_db.cursor()
        cur.execute("SELECT identifier, ip, mac, last_seen, attack_types FROM attackers ORDER BY last_seen DESC")
        rows = cur.fetchall()
        
        attackers = []
        for row in rows:
            identifier, ip, mac, last_seen, attack_types = row
            attacker_types = json.loads(attack_types) if attack_types else []
            attackers.append({
                'identifier': identifier,
                'ip': ip or 'Unknown',
                'mac': mac or 'Unknown',
                'last_seen': last_seen,
                'attack_types': attacker_types
            })
            
        return render_template_string(ATTACKER_TEMPLATE, attackers=attackers)
    except Exception as e:
        return f"Error loading attackers: {e}", 500


@app.route('/api/attacker/<identifier>')
def get_attacker_info(identifier):
    """API endpoint to get detailed attacker information"""
    try:
        cur = attacker_db.cursor()
        cur.execute("SELECT * FROM attackers WHERE identifier = ?", (identifier,))
        row = cur.fetchone()
        
        if not row:
            return jsonify({"error": "Attacker not found"}), 404
            
        # Extract data from row
        attacker_data = {
            'identifier': row[0],
            'ip': row[1],
            'mac': row[2],
            'first_seen': row[3],
            'last_seen': row[4],
            'attack_types': json.loads(row[5]) if row[5] else [],
            'hostname': row[6],
            'geolocation': json.loads(row[7]) if row[7] else {},
            'open_ports': json.loads(row[8]) if row[8] else {},
            'os_info': json.loads(row[9]) if row[9] else {},
            'reputation': json.loads(row[10]) if row[10] else {},
            'connections': json.loads(row[11]) if row[11] else []
        }
        
        return jsonify(attacker_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
