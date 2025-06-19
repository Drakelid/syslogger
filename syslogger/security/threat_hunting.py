"""
Threat hunting module for SysLogger.
Provides functionality for IOC scanning, YARA rule support, and custom detection rules.
"""
import os
import re
import json
import datetime
import logging
import ipaddress
from typing import Dict, List, Any, Optional, Set, Union, Tuple

from syslogger.config.config import get_config
from syslogger.core.logger import get_logger

class ThreatHunting:
    """
    Threat hunting capability for SysLogger that provides proactive security monitoring.
    """
    def __init__(self):
        """Initialize the threat hunting engine."""
        self.logger = get_logger()
        self.config = get_config()
        
        # Load indicators of compromise (IOCs)
        self.iocs = {
            'ip': set(),
            'domain': set(),
            'url': set(),
            'file_hash': set(),
            'email': set()
        }
        
        # Load custom detection rules
        self.custom_rules = {}
        
        # YARA rules
        self.yara_rules = {}
        self.yara_available = False
        
        try:
            import yara
            self.yara_available = True
            self.logger.info("YARA support enabled")
        except ImportError:
            self.logger.warning("YARA not available. YARA-based threat hunting will be disabled.")
        
        # Load built-in IOCs and rules
        self._load_builtin_iocs()
        self._load_custom_rules()
        self._load_yara_rules()
        
    def _load_builtin_iocs(self):
        """Load built-in indicators of compromise."""
        # This would typically load from built-in feeds
        # For now, we'll use a small set of example IOCs
        builtin_iocs = {
            'ip': [
                '185.147.34.126',  # Example known malicious IP
                '103.35.74.74',
                '45.227.255.205'
            ],
            'domain': [
                'malicious-domain.com',
                'evil-site.org',
                'badactor.net'
            ],
            'file_hash': [
                'e5b785940fcb297db1c2ba15b162d3c0',  # Example MD5
                'aede172d8d5e02214e14505c3782f3b4e35b12fe',  # Example SHA-1
                'a1bd115736e448db9536906d420610726f2e7d85c65c25a776024a4a39837b4d'  # Example SHA-256
            ]
        }
        
        for ioc_type, values in builtin_iocs.items():
            self.iocs[ioc_type].update(values)
            
        self.logger.debug(f"Loaded {sum(len(values) for values in self.iocs.values())} built-in IOCs")
    
    def _load_custom_rules(self):
        """Load custom detection rules."""
        rules_dir = self.config.get('storage.rules_dir', '/logs/rules')
        os.makedirs(rules_dir, exist_ok=True)
        
        rules_file = os.path.join(rules_dir, 'custom_rules.json')
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    self.custom_rules = json.load(f)
                self.logger.info(f"Loaded {len(self.custom_rules)} custom rules from {rules_file}")
            except Exception as e:
                self.logger.error(f"Error loading custom rules from {rules_file}: {e}")
        else:
            # Create default rules file
            default_rules = {
                'suspicious_commands': {
                    'name': 'Suspicious Command Execution',
                    'description': 'Detects execution of potentially malicious commands',
                    'pattern': r'(?:wget|curl)\s+(?:https?|ftp)://[^\s]+\s*\|\s*(?:bash|sh|python)',
                    'severity': 'high',
                    'enabled': True,
                    'tags': ['command_injection', 'shell']
                },
                'ssh_brute_force': {
                    'name': 'SSH Brute Force',
                    'description': 'Detects SSH brute force attempts',
                    'pattern': r'Failed password for .+ from .+ port \d+',
                    'severity': 'medium',
                    'enabled': True,
                    'tags': ['brute_force', 'ssh']
                }
            }
            
            try:
                with open(rules_file, 'w') as f:
                    json.dump(default_rules, f, indent=2)
                self.custom_rules = default_rules
                self.logger.info(f"Created default custom rules file at {rules_file}")
            except Exception as e:
                self.logger.error(f"Error creating default custom rules file: {e}")
