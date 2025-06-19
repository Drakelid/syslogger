"""
Threat intelligence feed integration module for SysLogger.
Provides functionality to fetch and manage IOCs from various threat intelligence sources.
"""
import os
import json
import time
import datetime
import logging
import threading
import requests
from typing import Dict, List, Any, Optional, Set, Union

from syslogger.config.config import get_config
from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection
from syslogger.threat_intel.parsers import (
    parse_alienvault,
    parse_abuse_ch,
    parse_phishtank,
    parse_misp,
    parse_blocklist,
    parse_tor_exit_nodes,
    store_iocs
)

class ThreatFeedManager:
    """
    Manager for multiple threat intelligence feeds.
    Handles the fetching, parsing and storage of indicators of compromise (IOCs).
    """
    def __init__(self):
        """Initialize the threat feed manager."""
        self.logger = get_logger()
        self.config = get_config()
        
        # Initialize IOC storage
        self.iocs = {
            'ip': set(),
            'domain': set(),
            'url': set(),
            'file_hash': set(),
            'email': set()
        }
        
        # Feed configurations
        self.feeds = {
            'alienvault_otx': {
                'name': 'AlienVault OTX',
                'enabled': self.config.get('threat_intel.enable_alienvault', True),
                'api_key': self.config.get('threat_intel.alienvault_api_key', ''),
                'url': 'https://otx.alienvault.com/api/v1/indicators/export',
                'params': {'limit': 1000, 'types': 'domain,hostname,url,IPv4,md5,sha1,sha256'},
                'interval': 3600,  # 1 hour in seconds
                'parser': parse_alienvault
            },
            'abuse_ch': {
                'name': 'Abuse.ch',
                'enabled': self.config.get('threat_intel.enable_abuse_ch', True),
                'url': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
                'params': {},
                'interval': 3600,
                'parser': parse_abuse_ch
            },
            'phishtank': {
                'name': 'PhishTank',
                'enabled': self.config.get('threat_intel.enable_phishtank', True),
                'api_key': self.config.get('threat_intel.phishtank_api_key', ''),
                'url': 'https://data.phishtank.com/data/{api_key}/online-valid.json',
                'params': {},
                'interval': 86400,  # 24 hours in seconds
                'parser': parse_phishtank
            },
            'misp': {
                'name': 'MISP',
                'enabled': self.config.get('threat_intel.enable_misp', False),
                'api_key': self.config.get('threat_intel.misp_api_key', ''),
                'url': self.config.get('threat_intel.misp_url', ''),
                'params': {},
                'interval': 3600,
                'parser': parse_misp
            },
            'blocklist_de': {
                'name': 'Blocklist.de',
                'enabled': self.config.get('threat_intel.enable_blocklist_de', True),
                'url': 'https://lists.blocklist.de/lists/all.txt',
                'params': {},
                'interval': 86400,
                'parser': parse_blocklist
            },
            'tor_exit_nodes': {
                'name': 'Tor Exit Nodes',
                'enabled': self.config.get('threat_intel.enable_tor_exit_nodes', True),
                'url': 'https://check.torproject.org/exit-addresses',
                'params': {},
                'interval': 86400,
                'parser': parse_tor_exit_nodes
            }
        }
        
        # Initialize database tables
        self._init_database()
        
        # Load cached IOCs from database
        self._load_cached_iocs()
        
        # Start background update threads if enabled
        if self.config.get('threat_intel.enable_auto_update', True):
            self._start_update_threads()
    
    def _init_database(self):
        """Initialize database tables for storing IOCs."""
        try:
            conn = get_db_connection()
            
            # Create IOC table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT,
                    ioc_value TEXT,
                    source TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    confidence REAL,
                    metadata TEXT,
                    UNIQUE(ioc_type, ioc_value, source)
                )
            """)
            
            # Create feed status table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_feed_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_id TEXT UNIQUE,
                    last_update TEXT,
                    status TEXT,
                    ioc_count INTEGER,
                    error TEXT
                )
            """)
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error initializing threat intel database: {e}")
            
    def _load_cached_iocs(self):
        """Load previously cached IOCs from database."""
        try:
            conn = get_db_connection()
            
            for ioc_type in self.iocs.keys():
                cursor = conn.execute(
                    "SELECT ioc_value FROM threat_intel_iocs WHERE ioc_type = ?", 
                    (ioc_type,)
                )
                
                values = {row[0] for row in cursor.fetchall()}
                self.iocs[ioc_type].update(values)
                
            self.logger.info(f"Loaded cached IOCs: {sum(len(v) for v in self.iocs.values())} indicators")
            
        except Exception as e:
            self.logger.error(f"Error loading cached IOCs: {e}")
            
    def _start_update_threads(self):
        """Start background threads to update feeds at regular intervals."""
        def update_feed_thread(feed_id):
            feed = self.feeds[feed_id]
            interval = feed.get('interval', 3600)
            
            self.logger.info(f"Starting update thread for {feed['name']}")
            
            # Initial update
            self.update_feed(feed_id)
            
            while True:
                try:
                    time.sleep(interval)
                    self.update_feed(feed_id)
                except Exception as e:
                    self.logger.error(f"Error in update thread for {feed['name']}: {e}")
                    time.sleep(300)  # Wait 5 minutes before retry
        
        # Start threads for enabled feeds
        for feed_id, feed in self.feeds.items():
            if feed['enabled']:
                thread = threading.Thread(
                    target=update_feed_thread,
                    args=(feed_id,),
                    daemon=True
                )
                thread.start()

    def update_feed(self, feed_id):
        """
        Update IOCs from a specific feed.
        
        Args:
            feed_id: ID of the feed to update
            
        Returns:
            bool: Success status
        """
        if feed_id not in self.feeds:
            self.logger.error(f"Invalid feed ID: {feed_id}")
            return False
            
        feed = self.feeds[feed_id]
        
        if not feed['enabled']:
            self.logger.warning(f"Feed {feed['name']} is disabled")
            return False
            
        try:
            self.logger.info(f"Updating threat feed: {feed['name']}")
            
            # Format URL with API key if needed
            url = feed['url']
            if '{api_key}' in url and feed.get('api_key'):
                url = url.format(api_key=feed['api_key'])
            
            # Make request with parameters
            headers = {'User-Agent': 'SysLogger/1.0'}
            if feed.get('api_key') and 'X-OTX-API-KEY' not in headers:
                headers['X-OTX-API-KEY'] = feed['api_key']
                
            response = requests.get(url, params=feed['params'], headers=headers, timeout=30)
            response.raise_for_status()
            
            # Parse the response using the feed-specific parser
            parser = feed['parser']
            new_iocs = parser(response)
            
            # Store the IOCs in database
            store_iocs(new_iocs, feed_id)
            
            # Update in-memory sets
            for ioc_type, values in new_iocs.items():
                self.iocs[ioc_type].update(values)
            
            # Record feed status
            conn = get_db_connection()
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_intel_feed_status
                (feed_id, last_update, status, ioc_count, error)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    feed_id, 
                    datetime.datetime.now().isoformat(),
                    'success',
                    sum(len(iocs) for iocs in new_iocs.values()),
                    None
                )
            )
            conn.commit()
            
            self.logger.info(f"Successfully updated {feed['name']}, got {sum(len(iocs) for iocs in new_iocs.values())} IOCs")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating feed {feed['name']}: {e}")
            
            try:
                # Record error status
                conn = get_db_connection()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO threat_intel_feed_status
                    (feed_id, last_update, status, ioc_count, error)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        feed_id, 
                        datetime.datetime.now().isoformat(),
                        'error',
                        0,
                        str(e)
                    )
                )
                conn.commit()
            except Exception as db_error:
                self.logger.error(f"Error recording feed status: {db_error}")
                
            return False
            
    def check_ioc(self, value, ioc_type=None):
        """
        Check if a value is a known indicator of compromise.
        
        Args:
            value: Value to check
            ioc_type: Optional type hint (ip, domain, url, file_hash, email)
            
        Returns:
            bool: True if the value is a known IOC
        """
        # If type is specified, only check that type
        if ioc_type and ioc_type in self.iocs:
            return value in self.iocs[ioc_type]
            
        # Otherwise check all types
        for t, values in self.iocs.items():
            if value in values:
                return True
                
        return False
        
    def get_ioc_details(self, value, ioc_type=None):
        """
        Get details about a known IOC.
        
        Args:
            value: IOC value
            ioc_type: Optional type hint
            
        Returns:
            dict: IOC details or None if not found
        """
        try:
            conn = get_db_connection()
            
            if ioc_type:
                cursor = conn.execute("""
                    SELECT ioc_type, ioc_value, source, first_seen, last_seen, confidence, metadata
                    FROM threat_intel_iocs
                    WHERE ioc_type = ? AND ioc_value = ?
                """, (ioc_type, value))
            else:
                cursor = conn.execute("""
                    SELECT ioc_type, ioc_value, source, first_seen, last_seen, confidence, metadata
                    FROM threat_intel_iocs
                    WHERE ioc_value = ?
                """, (value,))
                
            rows = cursor.fetchall()
            
            if not rows:
                return None
                
            results = []
            for row in rows:
                results.append({
                    'type': row[0],
                    'value': row[1],
                    'source': row[2],
                    'first_seen': row[3],
                    'last_seen': row[4],
                    'confidence': row[5],
                    'metadata': json.loads(row[6] if row[6] else '{}')
                })
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error retrieving IOC details: {e}")
            return None
            
    def get_feed_status(self):
        """
        Get status of all feeds.
        
        Returns:
            list: Feed status information
        """
        try:
            conn = get_db_connection()
            cursor = conn.execute("""
                SELECT feed_id, last_update, status, ioc_count, error
                FROM threat_intel_feed_status
            """)
            
            rows = cursor.fetchall()
            status = {}
            
            for row in rows:
                feed_id = row[0]
                status[feed_id] = {
                    'feed_id': feed_id,
                    'name': self.feeds.get(feed_id, {}).get('name', feed_id),
                    'last_update': row[1],
                    'status': row[2],
                    'ioc_count': row[3],
                    'error': row[4]
                }
                
            # Add feeds without status
            for feed_id, feed in self.feeds.items():
                if feed_id not in status:
                    status[feed_id] = {
                        'feed_id': feed_id,
                        'name': feed.get('name', feed_id),
                        'last_update': None,
                        'status': 'not_started',
                        'ioc_count': 0,
                        'error': None
                    }
                    
            return list(status.values())
            
        except Exception as e:
            self.logger.error(f"Error getting feed status: {e}")
            return []
            
    def get_ioc_counts(self):
        """
        Get counts of IOCs by type.
        
        Returns:
            dict: Counts by IOC type
        """
        return {k: len(v) for k, v in self.iocs.items()}
        
# Singleton instance
_threat_feed_manager = None

def get_threat_feed_manager():
    """
    Get the singleton threat feed manager instance.
    
    Returns:
        ThreatFeedManager: Singleton instance
    """
    global _threat_feed_manager
    
    if _threat_feed_manager is None:
        _threat_feed_manager = ThreatFeedManager()
        
    return _threat_feed_manager
