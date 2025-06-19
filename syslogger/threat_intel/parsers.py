"""
Threat intelligence feed parsers for SysLogger.
This module contains parsers for various threat intelligence feeds.
"""
import json
import datetime
import urllib.parse
import logging
from typing import Dict, List, Any, Optional, Set

from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection

def parse_alienvault(response):
    """
    Parse AlienVault OTX feed response.
    
    Args:
        response: Requests response object
        
    Returns:
        dict: Dictionary of IOCs by type
    """
    logger = get_logger()
    result = {
        'ip': set(),
        'domain': set(),
        'url': set(),
        'file_hash': set(),
        'email': set()
    }
    
    try:
        data = response.json()
        
        for item in data:
            indicator_type = item.get('type')
            indicator = item.get('indicator')
            
            if not indicator:
                continue
                
            # Map AlienVault types to our types
            if indicator_type in ['IPv4', 'IPv6']:
                result['ip'].add(indicator)
            elif indicator_type in ['domain', 'hostname']:
                result['domain'].add(indicator)
            elif indicator_type == 'URL':
                result['url'].add(indicator)
            elif indicator_type in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                result['file_hash'].add(indicator)
            elif indicator_type == 'email':
                result['email'].add(indicator)
                
        return result
        
    except Exception as e:
        logger.error(f"Error parsing AlienVault OTX response: {e}")
        return result
        
def parse_abuse_ch(response):
    """
    Parse Abuse.ch URLhaus feed response.
    
    Args:
        response: Requests response object
        
    Returns:
        dict: Dictionary of IOCs by type
    """
    logger = get_logger()
    result = {
        'ip': set(),
        'domain': set(),
        'url': set(),
        'file_hash': set(),
        'email': set()
    }
    
    try:
        data = response.json()
        
        # Process URLs
        if 'urls' in data and isinstance(data['urls'], list):
            for item in data['urls']:
                if 'url' in item:
                    result['url'].add(item['url'])
                if 'host' in item:
                    result['domain'].add(item['host'])
                if 'payload_hash' in item and len(item['payload_hash']) in [32, 40, 64]:  # MD5, SHA1, SHA256
                    result['file_hash'].add(item['payload_hash'])
        
        return result
        
    except Exception as e:
        logger.error(f"Error parsing Abuse.ch response: {e}")
        return result
        
def parse_phishtank(response):
    """
    Parse PhishTank feed response.
    
    Args:
        response: Requests response object
        
    Returns:
        dict: Dictionary of IOCs by type
    """
    logger = get_logger()
    result = {
        'ip': set(),
        'domain': set(),
        'url': set(),
        'file_hash': set(),
        'email': set()
    }
    
    try:
        data = response.json()
        
        for item in data:
            if 'url' in item:
                result['url'].add(item['url'])
                
                # Extract domain from URL
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(item['url'])
                    if parsed.netloc:
                        result['domain'].add(parsed.netloc)
                except Exception:
                    pass
        
        return result
        
    except Exception as e:
        logger.error(f"Error parsing PhishTank response: {e}")
        return result
        
def parse_misp(response):
    """
    Parse MISP feed response.
    
    Args:
        response: Requests response object
        
    Returns:
        dict: Dictionary of IOCs by type
    """
    logger = get_logger()
    result = {
        'ip': set(),
        'domain': set(),
        'url': set(),
        'file_hash': set(),
        'email': set()
    }
    
    try:
        data = response.json()
        
        if 'response' in data and isinstance(data['response'], list):
            for event in data['response']:
                if 'Attribute' in event and isinstance(event['Attribute'], list):
                    for attr in event['Attribute']:
                        attr_type = attr.get('type')
                        attr_value = attr.get('value')
                        
                        if not attr_value:
                            continue
                            
                        # Map MISP types to our types
                        if attr_type in ['ip-src', 'ip-dst']:
                            result['ip'].add(attr_value)
                        elif attr_type in ['domain', 'hostname']:
                            result['domain'].add(attr_value)
                        elif attr_type == 'url':
                            result['url'].add(attr_value)
                        elif attr_type in ['md5', 'sha1', 'sha256']:
                            result['file_hash'].add(attr_value)
                        elif attr_type == 'email':
                            result['email'].add(attr_value)
        
        return result
        
    except Exception as e:
        logger.error(f"Error parsing MISP response: {e}")
        return result
        
def parse_blocklist(response):
    """
    Parse Blocklist.de feed response.
    
    Args:
        response: Requests response object
        
    Returns:
        dict: Dictionary of IOCs by type
    """
    logger = get_logger()
    result = {
        'ip': set(),
        'domain': set(),
        'url': set(),
        'file_hash': set(),
        'email': set()
    }
    
    try:
        # Parse text list of IPs
        lines = response.text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                result['ip'].add(line)
        
        return result
        
    except Exception as e:
        logger.error(f"Error parsing Blocklist.de response: {e}")
        return result
        
def parse_tor_exit_nodes(response):
    """
    Parse Tor Exit Nodes feed response.
    
    Args:
        response: Requests response object
        
    Returns:
        dict: Dictionary of IOCs by type
    """
    logger = get_logger()
    result = {
        'ip': set(),
        'domain': set(),
        'url': set(),
        'file_hash': set(),
        'email': set()
    }
    
    try:
        # Parse text list of Tor exit nodes
        lines = response.text.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('ExitAddress '):
                parts = line.split(' ')
                if len(parts) >= 2:
                    result['ip'].add(parts[1])
        
        return result
        
    except Exception as e:
        logger.error(f"Error parsing Tor exit nodes response: {e}")
        return result

def store_iocs(iocs, source):
    """
    Store IOCs in the database.
    
    Args:
        iocs: Dictionary of IOCs by type
        source: Source name
    """
    logger = get_logger()
    try:
        conn = get_db_connection()
        now = datetime.datetime.now().isoformat()
        
        for ioc_type, values in iocs.items():
            for value in values:
                # Insert or update the IOC
                conn.execute("""
                    INSERT OR REPLACE INTO threat_intel_iocs
                    (ioc_type, ioc_value, source, first_seen, last_seen, confidence, metadata)
                    VALUES (?, ?, ?, 
                            COALESCE((SELECT first_seen FROM threat_intel_iocs WHERE ioc_type = ? AND ioc_value = ? AND source = ?), ?), 
                            ?, 1.0, '{}')
                """, (
                    ioc_type, value, source,
                    ioc_type, value, source, now,
                    now
                ))
                
        conn.commit()
        
    except Exception as e:
        logger.error(f"Error storing IOCs in database: {e}")
