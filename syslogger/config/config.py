"""
Configuration management for SysLogger.
Provides a centralized way to load, validate, and access configuration.
"""
import os
import yaml
import logging
import pathlib
from typing import Dict, Any, Optional, Union

# Default configuration file path
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'config.yml')

class ConfigError(Exception):
    """Exception raised for configuration errors."""
    pass

class Config:
    """Configuration manager for SysLogger that handles loading from both
    environment variables and YAML configuration files with validation."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration object.
        
        Args:
            config_path: Path to configuration file. If None, uses DEFAULT_CONFIG_PATH.
        """
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.config: Dict[str, Any] = {}
        self._load_defaults()
        
    def _load_defaults(self) -> None:
        """Load default configuration values."""
        self.config = {
            'logging': {
                'log_file': '/logs/syslog.log',
                'log_level': 'INFO',
                'max_bytes': 10485760,  # 10 MB
                'backup_count': 5,
                'log_to_stdout': False
            },
            'syslog': {
                'bind_host': '0.0.0.0',
                'udp_port': 514,
                'tcp_port': 514,
                'enable_udp': True,
                'enable_tcp': True
            },
            'web': {
                'enable_web': True,
                'web_port': 8080,
                'web_log_lines': 100
            },
            'detection': {
                'deauth_threshold': 3,
                'auth_fail_threshold': 5,
                'port_scan_threshold': 10,
                'dhcp_req_threshold': 20,
                'firewall_threshold': 20,
                'dos_threshold': 10,
                'detection_window': 600  # seconds
            },
            'storage': {
                'db_file': '/logs/syslog.db',
                'attacker_info_db': '/logs/attacker_info.db',
                'ml_models_dir': '/logs/ml_models'
            },
            'forwarding': {
                'forward_host': None,
                'forward_port': None
            },
            'scanning': {
                'enable_scan': False,
                'port_scan_timeout': 5,  # seconds
                'geoip_db_path': '/logs/GeoLite2-City.mmdb'
            },
            'threat_intel': {
                'api_key': '',
                'thread_pool_size': 5
            },
            'network': {
                'enable_pcap': False,
                'pcap_interface': 'eth0',
                'pcap_bpf_filter': 'port not 22',
                'pcap_snaplen': 1500,
                'pcap_timeout': 100,
                'pcap_file': '/logs/capture.pcap',
                'enable_netflow': False,
                'netflow_port': 2055
            }
        }
        
    def load_from_yaml(self, config_path: Optional[str] = None) -> None:
        """
        Load configuration from YAML file.
        
        Args:
            config_path: Path to configuration file. If None, uses the path provided in __init__.
            
        Raises:
            ConfigError: If the configuration file cannot be loaded.
        """
        path = config_path or self.config_path
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                self._merge_config(yaml_config)
                logging.info(f"Loaded configuration from {path}")
            else:
                logging.warning(f"Configuration file {path} not found, using defaults")
        except Exception as e:
            raise ConfigError(f"Error loading configuration from {path}: {e}")
    
    def load_from_env(self) -> None:
        """
        Load configuration from environment variables.
        Environment variables override YAML configuration.
        """
        # Mapping from environment variable names to config paths
        env_mapping = {
            'LOG_FILE': ['logging', 'log_file'],
            'LOG_LEVEL': ['logging', 'log_level'],
            'MAX_BYTES': ['logging', 'max_bytes'],
            'BACKUP_COUNT': ['logging', 'backup_count'],
            'LOG_TO_STDOUT': ['logging', 'log_to_stdout'],
            'BIND_HOST': ['syslog', 'bind_host'],
            'UDP_PORT': ['syslog', 'udp_port'],
            'TCP_PORT': ['syslog', 'tcp_port'],
            'ENABLE_UDP': ['syslog', 'enable_udp'],
            'ENABLE_TCP': ['syslog', 'enable_tcp'],
            'ENABLE_WEB': ['web', 'enable_web'],
            'WEB_PORT': ['web', 'web_port'],
            'WEB_LOG_LINES': ['web', 'web_log_lines'],
            'DEAUTH_THRESHOLD': ['detection', 'deauth_threshold'],
            'AUTH_FAIL_THRESHOLD': ['detection', 'auth_fail_threshold'],
            'PORT_SCAN_THRESHOLD': ['detection', 'port_scan_threshold'],
            'DHCP_REQ_THRESHOLD': ['detection', 'dhcp_req_threshold'],
            'FIREWALL_THRESHOLD': ['detection', 'firewall_threshold'],
            'DOS_THRESHOLD': ['detection', 'dos_threshold'],
            'DETECTION_WINDOW': ['detection', 'detection_window'],
            'DB_FILE': ['storage', 'db_file'],
            'ATTACKER_INFO_DB': ['storage', 'attacker_info_db'],
            'ML_MODELS_DIR': ['storage', 'ml_models_dir'],
            'FORWARD_HOST': ['forwarding', 'forward_host'],
            'FORWARD_PORT': ['forwarding', 'forward_port'],
            'ENABLE_SCAN': ['scanning', 'enable_scan'],
            'PORT_SCAN_TIMEOUT': ['scanning', 'port_scan_timeout'],
            'GEOIP_DB_PATH': ['scanning', 'geoip_db_path'],
            'THREAT_INTEL_API_KEY': ['threat_intel', 'api_key'],
            'THREAD_POOL_SIZE': ['threat_intel', 'thread_pool_size'],
            'ENABLE_PCAP': ['network', 'enable_pcap'],
            'PCAP_INTERFACE': ['network', 'pcap_interface'],
            'PCAP_BPF_FILTER': ['network', 'pcap_bpf_filter'],
            'PCAP_SNAPLEN': ['network', 'pcap_snaplen'],
            'PCAP_TIMEOUT': ['network', 'pcap_timeout'],
            'PCAP_FILE': ['network', 'pcap_file'],
            'ENABLE_NETFLOW': ['network', 'enable_netflow'],
            'NETFLOW_PORT': ['network', 'netflow_port']
        }
        
        for env_var, config_path in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Type conversion based on default type
                default_value = self.get_nested(self.config, config_path)
                if isinstance(default_value, bool):
                    value = value.lower() in ('1', 'true', 'yes')
                elif isinstance(default_value, int):
                    value = int(value)
                
                # Set the value
                self.set_nested(self.config, config_path, value)
    
    def _merge_config(self, new_config: Dict[str, Any]) -> None:
        """
        Merge a new configuration into the existing one.
        
        Args:
            new_config: New configuration to merge.
        """
        def _merge_dicts(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
            for key, value in update.items():
                if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                    _merge_dicts(base[key], value)
                else:
                    base[key] = value
            return base
        
        self.config = _merge_dicts(self.config, new_config)
    
    def validate(self) -> None:
        """
        Validate the configuration.
        
        Raises:
            ConfigError: If any configuration values are invalid.
        """
        # Create directories for log files and databases
        log_file = self.get('logging.log_file')
        if log_file:
            log_dir = os.path.dirname(log_file)
            if not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir, exist_ok=True)
                except Exception as e:
                    raise ConfigError(f"Cannot create log directory {log_dir}: {e}")
        
        # Check ports are valid
        for port_config_path in [
            'syslog.udp_port', 
            'syslog.tcp_port', 
            'web.web_port',
            'network.netflow_port'
        ]:
            port = self.get(port_config_path)
            if port is not None and not (0 < port < 65536):
                raise ConfigError(f"Invalid port number {port} for {port_config_path}")
            
        # Ensure database directories exist
        for db_path_config in ['storage.db_file', 'storage.attacker_info_db']:
            db_path = self.get(db_path_config)
            if db_path:
                db_dir = os.path.dirname(db_path)
                if not os.path.exists(db_dir):
                    try:
                        os.makedirs(db_dir, exist_ok=True)
                    except Exception as e:
                        raise ConfigError(f"Cannot create database directory {db_dir}: {e}")
        
        # Ensure ML models directory exists
        ml_dir = self.get('storage.ml_models_dir')
        if ml_dir:
            try:
                os.makedirs(ml_dir, exist_ok=True)
            except Exception as e:
                raise ConfigError(f"Cannot create ML models directory {ml_dir}: {e}")
                
    def get(self, path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            path: Path to the configuration value using dot notation (e.g., 'logging.log_file').
            default: Default value if the path is not found.
            
        Returns:
            The configuration value or the default.
        """
        parts = path.split('.')
        value = self.config
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value
    
    def get_nested(self, config: Dict[str, Any], path_list: list) -> Any:
        """
        Get a nested configuration value.
        
        Args:
            config: Configuration dictionary.
            path_list: List of keys to traverse.
            
        Returns:
            The nested value or None if not found.
        """
        value = config
        for key in path_list:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
    
    def set_nested(self, config: Dict[str, Any], path_list: list, value: Any) -> None:
        """
        Set a nested configuration value.
        
        Args:
            config: Configuration dictionary.
            path_list: List of keys to traverse.
            value: Value to set.
        """
        current = config
        for i, key in enumerate(path_list[:-1]):
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[path_list[-1]] = value
        
    def save_to_yaml(self, config_path: Optional[str] = None) -> None:
        """
        Save the current configuration to a YAML file.
        
        Args:
            config_path: Path to save the configuration file. If None, uses the path provided in __init__.
            
        Raises:
            ConfigError: If the configuration file cannot be saved.
        """
        path = config_path or self.config_path
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            
            with open(path, 'w') as f:
                yaml.dump(self.config, f)
            logging.info(f"Saved configuration to {path}")
        except Exception as e:
            raise ConfigError(f"Error saving configuration to {path}: {e}")

# Singleton instance
_config_instance = None

def get_config(config_path: Optional[str] = None) -> Config:
    """
    Get the global configuration instance.
    
    Args:
        config_path: Path to configuration file. Only used if the instance is not yet initialized.
        
    Returns:
        The global configuration instance.
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
        try:
            _config_instance.load_from_yaml()
        except ConfigError as e:
            logging.warning(f"Failed to load configuration from YAML: {e}")
        
        _config_instance.load_from_env()
        try:
            _config_instance.validate()
        except ConfigError as e:
            logging.error(f"Configuration validation failed: {e}")
            raise
            
    return _config_instance
