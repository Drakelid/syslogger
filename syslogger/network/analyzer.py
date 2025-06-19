"""
Network traffic analysis module for SysLogger.
Provides PCAP processing, NetFlow support, and deep packet inspection capabilities.
"""
import os
import time
import struct
import socket
import datetime
import threading
import logging
from typing import Dict, List, Any, Optional, Tuple, Union

from syslogger.config.config import get_config
from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection

class NetworkAnalyzer:
    """
    Network traffic analyzer that processes packet captures and flow data.
    """
    def __init__(self):
        """Initialize the network analyzer."""
        self.logger = get_logger()
        self.config = get_config()
        
        # Check for required dependencies
        self.pcap_available = False
        self.netflow_available = False
        self.dpi_available = False
        
        # Try to import required libraries
        try:
            import pcapy
            self.pcap_available = True
            self.logger.info("PCAP support enabled")
        except ImportError:
            self.logger.warning("pcapy not available. PCAP processing will be disabled.")
            
        try:
            import netflow
            self.netflow_available = True
            self.logger.info("NetFlow support enabled")
        except ImportError:
            self.logger.warning("netflow not available. NetFlow processing will be disabled.")
            
        try:
            import dpkt
            self.dpi_available = True
            self.logger.info("Deep packet inspection support enabled")
        except ImportError:
            self.logger.warning("dpkt not available. Deep packet inspection will be disabled.")
        
        # Initialize storage for analyzed data
        self._init_storage()
        
        # Start threads if enabled
        self._start_capture_threads()
        
    def _init_storage(self):
        """Initialize storage for network analysis data."""
        # Create necessary directories
        log_dir = os.path.dirname(self.config.get('logging.log_file'))
        pcap_file = self.config.get('network.pcap_file', os.path.join(log_dir, 'capture.pcap'))
        os.makedirs(os.path.dirname(pcap_file), exist_ok=True)
        
        # Initialize data structures
        self.flow_data = {}  # source -> dest -> count
        self.packet_stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0,
            'start_time': time.time(),
            'protocols': {}
        }
        
        # Create tables in database if needed
        conn = get_db_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packets INTEGER,
                bytes INTEGER
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS packet_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                total_packets INTEGER,
                tcp_packets INTEGER,
                udp_packets INTEGER,
                icmp_packets INTEGER,
                other_packets INTEGER,
                duration INTEGER
            )
        """)
        
    def _start_capture_threads(self):
        """Start capture threads based on configuration."""
        # Start PCAP capture if enabled
        if self.config.get('network.enable_pcap', False) and self.pcap_available:
            pcap_thread = threading.Thread(
                target=self._run_pcap_capture,
                daemon=True
            )
            pcap_thread.start()
        
        # Start NetFlow collector if enabled
        if self.config.get('network.enable_netflow', False) and self.netflow_available:
            netflow_thread = threading.Thread(
                target=self._run_netflow_collector,
                daemon=True
            )
            netflow_thread.start()
    
    def _run_pcap_capture(self):
        """Run PCAP capture thread."""
        try:
            import pcapy
            
            interface = self.config.get('network.pcap_interface', 'eth0')
            bpf_filter = self.config.get('network.pcap_bpf_filter', '')
            snaplen = self.config.get('network.pcap_snaplen', 1500)
            timeout = self.config.get('network.pcap_timeout', 100)
            pcap_file = self.config.get('network.pcap_file')
            
            self.logger.info(f"Starting PCAP capture on interface {interface}")
            
            # Open the network interface for capturing
            pcap = pcapy.open_live(interface, snaplen, True, timeout)
            
            # Set BPF filter if specified
            if bpf_filter:
                pcap.setfilter(bpf_filter)
                
            # Open output file if specified
            pcap_dumper = None
            if pcap_file:
                pcap_dumper = pcap.dump_open(pcap_file)
                
            # Start capturing packets
            pcap.loop(0, self._packet_callback, pcap_dumper)
            
        except Exception as e:
            self.logger.error(f"Error in PCAP capture: {e}")
            
    def _run_netflow_collector(self):
        """Run NetFlow collector thread."""
        if not self.netflow_available:
            return
            
        try:
            import netflow
            from netflow.collector import ExportPacket
            
            # Get configuration
            netflow_port = self.config.get('network.netflow_port', 2055)
            netflow_host = self.config.get('network.netflow_host', '0.0.0.0')
            
            self.logger.info(f"Starting NetFlow collector on {netflow_host}:{netflow_port}")
            
            # Create a UDP socket for NetFlow collection
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((netflow_host, netflow_port))
            
            while True:
                # Receive data
                data, addr = sock.recvfrom(4096)
                
                try:
                    # Parse NetFlow data
                    export = ExportPacket(data)
                    self.logger.debug(f"Received NetFlow packet from {addr[0]}")
                    
                    # Process flows
                    for flow in export.flows:
                        self._process_netflow(flow, export.header.version)
                        
                except Exception as e:
                    self.logger.error(f"Error processing NetFlow data: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error in NetFlow collector: {e}")
            
    def _process_netflow(self, flow, version):
        """
        Process a NetFlow record.
        
        Args:
            flow: NetFlow record
            version: NetFlow version
        """
        try:
            # Extract flow information
            if version == 5:
                src_ip = socket.inet_ntoa(flow.srcaddr)
                dst_ip = socket.inet_ntoa(flow.dstaddr)
                src_port = flow.srcport
                dst_port = flow.dstport
                protocol = flow.prot
                packets = flow.dPkts
                bytes_sent = flow.dOctets
            elif version == 9 or version == 10:  # v9 or IPFIX
                src_ip = flow.data.get('IPV4_SRC_ADDR', 'unknown')
                if isinstance(src_ip, bytes):
                    src_ip = socket.inet_ntoa(src_ip)
                    
                dst_ip = flow.data.get('IPV4_DST_ADDR', 'unknown')
                if isinstance(dst_ip, bytes):
                    dst_ip = socket.inet_ntoa(dst_ip)
                    
                src_port = flow.data.get('L4_SRC_PORT', 0)
                dst_port = flow.data.get('L4_DST_PORT', 0)
                protocol = flow.data.get('PROTOCOL', 0)
                packets = flow.data.get('IN_PKTS', 0)
                bytes_sent = flow.data.get('IN_BYTES', 0)
            else:
                self.logger.warning(f"Unsupported NetFlow version: {version}")
                return
                
            # Store flow data in database
            conn = get_db_connection()
            conn.execute("""
                INSERT INTO network_flows 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.datetime.now().isoformat(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                packets,
                bytes_sent
            ))
            conn.commit()
            
            # Update flow statistics
            protocol_name = self._get_protocol_name(protocol, dst_port)
            self._increment_protocol(protocol_name)
            
            # Update flow data for visualization
            if src_ip not in self.flow_data:
                self.flow_data[src_ip] = {}
            if dst_ip not in self.flow_data[src_ip]:
                self.flow_data[src_ip][dst_ip] = 0
            self.flow_data[src_ip][dst_ip] += packets
            
        except Exception as e:
            self.logger.error(f"Error processing NetFlow record: {e}")
            
    def _packet_callback(self, header, data, pcap_dumper=None):
        """Callback function for processing captured packets."""
        # Write packet to file if dumper is available
        if pcap_dumper:
            pcap_dumper.dump(header, data)
            
        # Process packet data
        self._analyze_packet(data)
        
        # Update packet stats
        self.packet_stats['total'] += 1
        
    def _analyze_packet(self, packet_data):
        """
        Analyze a captured packet for protocol information and statistics.
        
        Args:
            packet_data: Raw packet data
        """
        if not self.dpi_available:
            return
            
        try:
            import dpkt
            import socket
            
            # Parse the packet
            eth = dpkt.ethernet.Ethernet(packet_data)
            
            # Extract IP packet if present
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                
                # Get source and destination IP addresses
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                # Update flow data
                if src_ip not in self.flow_data:
                    self.flow_data[src_ip] = {}
                if dst_ip not in self.flow_data[src_ip]:
                    self.flow_data[src_ip][dst_ip] = 0
                self.flow_data[src_ip][dst_ip] += 1
                
                # Update protocol statistics
                if isinstance(ip.data, dpkt.tcp.TCP):
                    self.packet_stats['tcp'] += 1
                    
                    # Get port information
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    
                    # Identify protocol
                    if dst_port == 80 or src_port == 80:
                        self._increment_protocol('HTTP')
                    elif dst_port == 443 or src_port == 443:
                        self._increment_protocol('HTTPS')
                    elif dst_port == 22 or src_port == 22:
                        self._increment_protocol('SSH')
                    elif dst_port == 25 or src_port == 25:
                        self._increment_protocol('SMTP')
                    else:
                        self._increment_protocol(f'TCP:{dst_port}')
                        
                elif isinstance(ip.data, dpkt.udp.UDP):
                    self.packet_stats['udp'] += 1
                    
                    # Get port information
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    
                    # Identify protocol
                    if dst_port == 53 or src_port == 53:
                        self._increment_protocol('DNS')
                    elif dst_port == 67 or dst_port == 68:
                        self._increment_protocol('DHCP')
                    else:
                        self._increment_protocol(f'UDP:{dst_port}')
                        
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    self.packet_stats['icmp'] += 1
                    self._increment_protocol('ICMP')
                    
                else:
                    self.packet_stats['other'] += 1
                    self._increment_protocol(f'IP:{ip.p}')
            else:
                self.packet_stats['other'] += 1
                
        except Exception as e:
            self.logger.debug(f"Error analyzing packet: {e}")
            self.packet_stats['other'] += 1
    
    def _increment_protocol(self, protocol):
        """
        Increment the count for a specific protocol.
        
        Args:
            protocol: Protocol identifier
        """
        if protocol not in self.packet_stats['protocols']:
            self.packet_stats['protocols'][protocol] = 0
        self.packet_stats['protocols'][protocol] += 1
        
    def _get_protocol_name(self, protocol_num, dst_port):
        """
        Get a friendly protocol name based on protocol number and destination port.
        
        Args:
            protocol_num: Protocol number (e.g., 6 for TCP)
            dst_port: Destination port
            
        Returns:
            str: Protocol name
        """
        # Common protocol numbers
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            89: 'OSPF'
        }
        
        # Common port mappings
        port_map = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3389: 'RDP'
        }
        
        # Check if it's a known port
        if dst_port in port_map:
            return port_map[dst_port]
            
        # Otherwise use protocol number if known
        if protocol_num in protocol_map:
            return f"{protocol_map[protocol_num]}:{dst_port}"
            
        # Fall back to protocol number
        return f"PROTO:{protocol_num}:{dst_port}"
    
    def get_packet_stats(self):
        """
        Get packet statistics since start.
        
        Returns:
            dict: Packet statistics
        """
        stats = dict(self.packet_stats)
        stats['duration'] = time.time() - stats['start_time']
        
        # Get top protocols by count
        protocols = stats['protocols']
        stats['top_protocols'] = sorted(
            [{"name": k, "count": v} for k, v in protocols.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:10]
        
        return stats
        
    def get_flow_data(self):
        """
        Get network flow data suitable for visualization.
        
        Returns:
            dict: Flow data with nodes and links
        """
        nodes = []
        links = []
        node_ids = {}
        node_count = 0
        
        # Build nodes and links
        for src_ip, destinations in self.flow_data.items():
            if src_ip not in node_ids:
                node_ids[src_ip] = node_count
                nodes.append({
                    "id": node_count,
                    "name": src_ip,
                    "value": sum(destinations.values())
                })
                node_count += 1
                
            for dst_ip, count in destinations.items():
                if dst_ip not in node_ids:
                    node_ids[dst_ip] = node_count
                    nodes.append({
                        "id": node_count,
                        "name": dst_ip,
                        "value": 0
                    })
                    node_count += 1
                    
                links.append({
                    "source": node_ids[src_ip],
                    "target": node_ids[dst_ip],
                    "value": count
                })
        
        return {
            "nodes": nodes,
            "links": links
        }
        
    def get_recent_flows(self, limit=100):
        """
        Get recent network flows from the database.
        
        Args:
            limit: Maximum number of flows to return
            
        Returns:
            list: Recent flows
        """
        try:
            conn = get_db_connection()
            cursor = conn.execute("""
                SELECT timestamp, src_ip, dst_ip, src_port, dst_port, 
                       protocol, packets, bytes 
                FROM network_flows 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            rows = cursor.fetchall()
            flows = []
            
            for row in rows:
                protocol_name = self._get_protocol_name(row[5], row[4])
                flows.append({
                    "timestamp": row[0],
                    "src_ip": row[1],
                    "dst_ip": row[2],
                    "src_port": row[3],
                    "dst_port": row[4],
                    "protocol": protocol_name,
                    "packets": row[6],
                    "bytes": row[7]
                })
                
            return flows
            
        except Exception as e:
            self.logger.error(f"Error getting recent flows: {e}")
            return []
            
    def save_packet_stats(self):
        """
        Save current packet statistics to the database.
        """
        try:
            stats = self.get_packet_stats()
            
            conn = get_db_connection()
            conn.execute("""
                INSERT INTO packet_stats 
                (timestamp, total_packets, tcp_packets, udp_packets, 
                 icmp_packets, other_packets, duration) 
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.datetime.now().isoformat(),
                stats['total'],
                stats['tcp'],
                stats['udp'],
                stats['icmp'],
                stats['other'],
                int(stats['duration'])
            ))
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error saving packet stats: {e}")
            
# Singleton instance
_network_analyzer = None

def get_network_analyzer():
    """
    Get a singleton instance of the NetworkAnalyzer.
    
    Returns:
        NetworkAnalyzer: The singleton network analyzer instance
    """
    global _network_analyzer
    
    if _network_analyzer is None:
        _network_analyzer = NetworkAnalyzer()
        
    return _network_analyzer
