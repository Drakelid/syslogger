"""
Event correlation engine for SysLogger.
This module provides functionality to correlate events across time and identify attack patterns.
"""
import json
import time
import datetime
import logging
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, deque

from syslogger.config.config import get_config
from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection

class EventCorrelationEngine:
    """
    Correlates security events to detect attack patterns and multi-stage attacks.
    The engine maintains an event cache and applies correlation rules to identify
    related events that may indicate more complex attack patterns.
    """
    
    # Common attack patterns and their corresponding events
    ATTACK_PATTERNS = {
        'reconnaissance': {
            'description': 'Network reconnaissance activities',
            'events': ['port_scan', 'ping_sweep', 'dns_query', 'version_probe'],
            'severity': 'low'
        },
        'brute_force': {
            'description': 'Repeated authentication attempts',
            'events': ['auth_fail', 'deauth'],
            'severity': 'medium'
        },
        'exploitation': {
            'description': 'Attempts to exploit vulnerabilities',
            'events': ['webshell', 'buffer_overflow', 'sql_injection', 'xss_attempt'],
            'severity': 'high'
        },
        'lateral_movement': {
            'description': 'Attempts to move through the network',
            'events': ['internal_scan', 'new_host_connection', 'suspicious_service'],
            'severity': 'high'
        },
        'data_exfiltration': {
            'description': 'Attempts to extract data',
            'events': ['large_upload', 'unusual_outbound', 'dns_tunneling'],
            'severity': 'high'
        },
        'dos': {
            'description': 'Denial of Service attempts',
            'events': ['syn_flood', 'http_flood', 'icmp_flood', 'resource_exhaustion'],
            'severity': 'medium'
        }
    }
    
    def __init__(self, detection_window: int = 3600):
        """
        Initialize the correlation engine.
        
        Args:
            detection_window: Time window in seconds for correlation (default: 1 hour)
        """
        self.logger = get_logger()
        self.config = get_config()
        
        # Override from config if specified
        self.detection_window = self.config.get('detection.detection_window', detection_window)
        
        # Event cache: source -> event_type -> timestamp list
        self.event_cache = defaultdict(lambda: defaultdict(list))
        
        # Attack chain cache: source -> list of correlated events
        self.attack_chains = defaultdict(list)
        
        # Register event types and handlers
        self.event_handlers = {
            'auth_fail': self._handle_auth_fail,
            'deauth': self._handle_deauth,
            'port_scan': self._handle_port_scan,
            'firewall_drop': self._handle_firewall_drop,
            'dhcp_flood': self._handle_dhcp_flood,
            'dos_attempt': self._handle_dos_attempt,
            # Add more handlers as needed
        }
        
        # Pattern matching regexes for log parsing
        self.patterns = {
            'auth_fail': re.compile(r'authentication failure|auth fail|login failed', re.IGNORECASE),
            'deauth': re.compile(r'deauth|disassociated|disconnected by ap', re.IGNORECASE),
            'port_scan': re.compile(r'port scan|scan detected|nmap|masscan', re.IGNORECASE),
            'firewall_drop': re.compile(r'firewall|drop|blocked|rejected', re.IGNORECASE),
            'dhcp_flood': re.compile(r'dhcp.*request|bootp|discover', re.IGNORECASE),
            'dos_attempt': re.compile(r'dos|ddos|flood|excessive|rate limit', re.IGNORECASE),
            'webshell': re.compile(r'shell|backdoor|command injection|remote execution', re.IGNORECASE),
            'sql_injection': re.compile(r'sql injection|sqli|select.*from|union.*select', re.IGNORECASE),
            'xss_attempt': re.compile(r'xss|cross site|script.*tag|javascript', re.IGNORECASE)
        }
        
        self.logger.info(f"Event correlation engine initialized with {self.detection_window}s window")
        
    def process_log(self, timestamp: str, host: str, message: str) -> Optional[Dict[str, Any]]:
        """
        Process a log message and correlate if it matches security patterns.
        
        Args:
            timestamp: Log timestamp
            host: Source host
            message: Log message
            
        Returns:
            Dictionary with correlation results if a pattern was detected, None otherwise
        """
        # Convert timestamp to epoch for easier time window calculations
        dt = datetime.datetime.strptime(timestamp, '%b %d %H:%M:%S')
        # Assume current year if not provided in timestamp
        current_year = datetime.datetime.now().year
        dt = dt.replace(year=current_year)
        epoch_time = dt.timestamp()
        
        # Clean up old events
        self._clean_old_events(epoch_time)
        
        # Detect event types in message
        detected_events = []
        for event_type, pattern in self.patterns.items():
            if pattern.search(message):
                detected_events.append(event_type)
                self.event_cache[host][event_type].append(epoch_time)
        
        # If no events detected, return None
        if not detected_events:
            return None
            
        # Process each detected event type
        correlation_results = []
        for event_type in detected_events:
            if event_type in self.event_handlers:
                result = self.event_handlers[event_type](host, epoch_time, message)
                if result:
                    correlation_results.append(result)
                    
                    # Update attack chain for this source
                    self.attack_chains[host].append({
                        'timestamp': epoch_time,
                        'event_type': event_type,
                        'message': message,
                        'correlation': result
                    })
        
        # Check for attack patterns
        attack_pattern = self._identify_attack_pattern(host)
        
        if correlation_results:
            return {
                'timestamp': timestamp,
                'host': host,
                'detected_events': detected_events,
                'correlation_results': correlation_results,
                'attack_pattern': attack_pattern
            }
        return None
        
    def _clean_old_events(self, current_time: float) -> None:
        """
        Remove events outside the detection window.
        
        Args:
            current_time: Current epoch time
        """
        cutoff_time = current_time - self.detection_window
        
        # Clean event cache
        hosts_to_remove = []
        for host in self.event_cache:
            event_types_to_remove = []
            for event_type in self.event_cache[host]:
                # Filter out old timestamps
                self.event_cache[host][event_type] = [
                    t for t in self.event_cache[host][event_type] if t >= cutoff_time
                ]
                
                # If no timestamps left, mark for removal
                if not self.event_cache[host][event_type]:
                    event_types_to_remove.append(event_type)
            
            # Remove empty event types
            for event_type in event_types_to_remove:
                del self.event_cache[host][event_type]
            
            # If no events left for host, mark for removal
            if not self.event_cache[host]:
                hosts_to_remove.append(host)
        
        # Remove empty hosts
        for host in hosts_to_remove:
            del self.event_cache[host]
        
        # Clean attack chains
        hosts_to_remove = []
        for host in self.attack_chains:
            # Filter out old chain events
            self.attack_chains[host] = [
                event for event in self.attack_chains[host]
                if event['timestamp'] >= cutoff_time
            ]
            
            # If no events left, mark for removal
            if not self.attack_chains[host]:
                hosts_to_remove.append(host)
        
        # Remove empty hosts from attack chains
        for host in hosts_to_remove:
            del self.attack_chains[host]
    
    def _identify_attack_pattern(self, host: str) -> Optional[Dict[str, Any]]:
        """
        Identify attack patterns based on event sequence for a host.
        
        Args:
            host: Source host
            
        Returns:
            Dictionary with attack pattern information if detected, None otherwise
        """
        if host not in self.event_cache:
            return None
        
        # Check each defined attack pattern
        matched_patterns = []
        host_event_types = set(self.event_cache[host].keys())
        
        for pattern_name, pattern_info in self.ATTACK_PATTERNS.items():
            pattern_events = set(pattern_info['events'])
            matching_events = host_event_types.intersection(pattern_events)
            
            # If we have a significant match (more than one event type from the pattern)
            if len(matching_events) > 1:
                # Calculate match percentage
                match_percent = len(matching_events) / len(pattern_events) * 100
                
                matched_patterns.append({
                    'pattern_name': pattern_name,
                    'description': pattern_info['description'],
                    'severity': pattern_info['severity'],
                    'match_percent': match_percent,
                    'matching_events': list(matching_events)
                })
        
        if matched_patterns:
            # Sort by match percentage (highest first)
            matched_patterns.sort(key=lambda x: x['match_percent'], reverse=True)
            return {
                'host': host,
                'matched_patterns': matched_patterns
            }
            
        return None
    
    def get_attack_chain(self, host: str) -> List[Dict[str, Any]]:
        """
        Get the attack chain for a specific host.
        
        Args:
            host: Source host
            
        Returns:
            List of correlated events for the host
        """
        return self.attack_chains.get(host, [])
    
    def get_all_attack_chains(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all attack chains.
        
        Returns:
            Dictionary of hosts to their attack chains
        """
        return dict(self.attack_chains)
    
    def _handle_auth_fail(self, host: str, timestamp: float, message: str) -> Dict[str, Any]:
        """Handle authentication failure events"""
        threshold = self.config.get('detection.auth_fail_threshold', 5)
        count = len(self.event_cache[host]['auth_fail'])
        
        return {
            'event_type': 'auth_fail',
            'count': count,
            'threshold': threshold,
            'alert': count >= threshold,
            'message': f"Authentication failures: {count}/{threshold}"
        }
        
    def _handle_deauth(self, host: str, timestamp: float, message: str) -> Dict[str, Any]:
        """Handle deauthentication events"""
        threshold = self.config.get('detection.deauth_threshold', 3)
        count = len(self.event_cache[host]['deauth'])
        
        return {
            'event_type': 'deauth',
            'count': count,
            'threshold': threshold,
            'alert': count >= threshold,
            'message': f"Deauthentication events: {count}/{threshold}"
        }
        
    def _handle_port_scan(self, host: str, timestamp: float, message: str) -> Dict[str, Any]:
        """Handle port scan events"""
        threshold = self.config.get('detection.port_scan_threshold', 10)
        count = len(self.event_cache[host]['port_scan'])
        
        return {
            'event_type': 'port_scan',
            'count': count,
            'threshold': threshold,
            'alert': count >= threshold,
            'message': f"Port scan events: {count}/{threshold}"
        }
        
    def _handle_firewall_drop(self, host: str, timestamp: float, message: str) -> Dict[str, Any]:
        """Handle firewall drop events"""
        threshold = self.config.get('detection.firewall_threshold', 20)
        count = len(self.event_cache[host]['firewall_drop'])
        
        return {
            'event_type': 'firewall_drop',
            'count': count,
            'threshold': threshold,
            'alert': count >= threshold,
            'message': f"Firewall drop events: {count}/{threshold}"
        }
        
    def _handle_dhcp_flood(self, host: str, timestamp: float, message: str) -> Dict[str, Any]:
        """Handle DHCP flood events"""
        threshold = self.config.get('detection.dhcp_req_threshold', 20)
        count = len(self.event_cache[host]['dhcp_flood'])
        
        return {
            'event_type': 'dhcp_flood',
            'count': count,
            'threshold': threshold,
            'alert': count >= threshold,
            'message': f"DHCP request events: {count}/{threshold}"
        }
        
    def _handle_dos_attempt(self, host: str, timestamp: float, message: str) -> Dict[str, Any]:
        """Handle DoS attempt events"""
        threshold = self.config.get('detection.dos_threshold', 10)
        count = len(self.event_cache[host]['dos_attempt'])
        
        return {
            'event_type': 'dos_attempt',
            'count': count,
            'threshold': threshold,
            'alert': count >= threshold,
            'message': f"DoS attempt events: {count}/{threshold}"
        }

# Singleton instance
_correlation_engine = None

def get_correlation_engine() -> EventCorrelationEngine:
    """
    Get the global correlation engine instance.
    
    Returns:
        The global correlation engine instance.
    """
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = EventCorrelationEngine()
    return _correlation_engine
