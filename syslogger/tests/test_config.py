"""
Unit tests for the configuration module.
"""
import os
import tempfile
import unittest
from unittest.mock import patch
import yaml

from syslogger.config.config import Config, ConfigError, get_config


class TestConfig(unittest.TestCase):
    """Test cases for the Config class."""
    
    def setUp(self):
        """Set up test environment before each test."""
        # Create a temporary directory for test files
        self.test_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.test_dir.name, 'test_config.yml')
        
        # Sample config data
        self.sample_config = {
            'logging': {
                'log_file': '/tmp/test.log',
                'log_level': 'DEBUG'
            },
            'syslog': {
                'udp_port': 5140
            }
        }
        
        # Write sample config to file
        with open(self.config_path, 'w') as f:
            yaml.dump(self.sample_config, f)
        
        # Reset the singleton instance
        from syslogger.config.config import _config_instance
        if '_config_instance' in globals():
            globals()['_config_instance'] = None
    
    def tearDown(self):
        """Clean up after each test."""
        self.test_dir.cleanup()
    
    def test_load_defaults(self):
        """Test that default configuration is loaded correctly."""
        config = Config()
        config._load_defaults()
        
        # Check a few default values
        self.assertEqual(config.get('logging.log_level'), 'INFO')
        self.assertEqual(config.get('syslog.udp_port'), 514)
        self.assertEqual(config.get('web.web_port'), 8080)
    
    def test_load_from_yaml(self):
        """Test loading configuration from YAML file."""
        config = Config()
        config.load_from_yaml(self.config_path)
        
        # Check values from YAML file
        self.assertEqual(config.get('logging.log_file'), '/tmp/test.log')
        self.assertEqual(config.get('logging.log_level'), 'DEBUG')
        self.assertEqual(config.get('syslog.udp_port'), 5140)
        
        # Check that default values remain for unspecified settings
        self.assertEqual(config.get('syslog.tcp_port'), 514)
    
    @patch.dict(os.environ, {
        'LOG_LEVEL': 'ERROR',
        'UDP_PORT': '9999',
        'ENABLE_WEB': 'false'
    })
    def test_load_from_env(self):
        """Test loading configuration from environment variables."""
        config = Config()
        config._load_defaults()
        config.load_from_env()
        
        # Check that environment values override defaults
        self.assertEqual(config.get('logging.log_level'), 'ERROR')
        self.assertEqual(config.get('syslog.udp_port'), 9999)
        self.assertEqual(config.get('web.enable_web'), False)
    
    @patch.dict(os.environ, {
        'LOG_LEVEL': 'ERROR',
        'UDP_PORT': '9999'
    })
    def test_env_overrides_yaml(self):
        """Test that environment variables override YAML settings."""
        config = Config()
        config.load_from_yaml(self.config_path)
        config.load_from_env()
        
        # Check that environment values override YAML values
        self.assertEqual(config.get('logging.log_level'), 'ERROR')
        self.assertEqual(config.get('syslog.udp_port'), 9999)
        
        # Check that YAML values persist for unspecified env vars
        self.assertEqual(config.get('logging.log_file'), '/tmp/test.log')
    
    def test_get_nested(self):
        """Test retrieving nested configuration values."""
        config = Config()
        config._load_defaults()
        
        # Test valid path
        self.assertEqual(
            config.get_nested(config.config, ['logging', 'log_level']), 
            'INFO'
        )
        
        # Test invalid path
        self.assertIsNone(
            config.get_nested(config.config, ['nonexistent', 'key'])
        )
    
    def test_set_nested(self):
        """Test setting nested configuration values."""
        config = Config()
        config._load_defaults()
        
        # Set existing nested value
        config.set_nested(config.config, ['logging', 'log_level'], 'DEBUG')
        self.assertEqual(config.get('logging.log_level'), 'DEBUG')
        
        # Set new nested value
        config.set_nested(config.config, ['new_section', 'new_key'], 'new_value')
        self.assertEqual(config.get('new_section.new_key'), 'new_value')
    
    def test_validate_valid_config(self):
        """Test configuration validation with valid settings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Set up a valid configuration
            config = Config()
            config._load_defaults()
            config.set_nested(config.config, ['logging', 'log_file'], 
                             os.path.join(temp_dir, 'log.txt'))
            config.set_nested(config.config, ['storage', 'db_file'], 
                             os.path.join(temp_dir, 'db.sqlite'))
            
            # Should not raise any exceptions
            config.validate()
    
    def test_validate_invalid_port(self):
        """Test configuration validation with an invalid port."""
        config = Config()
        config._load_defaults()
        config.set_nested(config.config, ['syslog', 'udp_port'], 70000)  # Invalid port
        
        # Should raise ConfigError
        with self.assertRaises(ConfigError):
            config.validate()
    
    def test_singleton_get_config(self):
        """Test that get_config returns a singleton instance."""
        # First call creates the instance
        config1 = get_config(self.config_path)
        
        # Second call should return the same instance
        config2 = get_config()
        
        self.assertIs(config1, config2)
        
        # Check that the config was loaded from YAML
        self.assertEqual(config1.get('logging.log_level'), 'DEBUG')


if __name__ == '__main__':
    unittest.main()
