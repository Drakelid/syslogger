"""
Core logging functionality for SysLogger.
Handles setup and configuration of the logging system.
"""
import os
import logging
import logging.handlers
from typing import Optional, Tuple

from syslogger.config.config import get_config

def setup_logging() -> logging.Logger:
    """
    Set up the logging system based on configuration.
    
    Returns:
        Logger instance configured according to settings.
    """
    config = get_config()
    
    # Ensure log directory exists
    log_file = config.get('logging.log_file')
    if log_file:
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)
    
    logger = logging.getLogger('syslogger')
    logger.setLevel(config.get('logging.log_level', 'INFO').upper())
    
    # Clear any existing handlers
    while logger.handlers:
        logger.removeHandler(logger.handlers[0])
    
    formatter = logging.Formatter('%(asctime)s %(message)s')
    
    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=config.get('logging.max_bytes', 10485760),
        backupCount=config.get('logging.backup_count', 5)
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Add stdout handler if requested
    if config.get('logging.log_to_stdout', False):
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)
    
    # Add forwarding handler if configured
    forward_host = config.get('forwarding.forward_host')
    forward_port = config.get('forwarding.forward_port')
    
    if forward_host and forward_port:
        try:
            forward_handler = logging.handlers.SysLogHandler(
                address=(forward_host, int(forward_port))
            )
            forward_handler.setFormatter(formatter)
            logger.addHandler(forward_handler)
            logger.info(f"Forwarding enabled: {forward_host}:{forward_port}")
        except Exception as e:
            logger.error(f"Failed to configure forwarding: {e}")
    
    return logger

# Global logger instance
_logger = None

def get_logger() -> logging.Logger:
    """
    Get the global logger instance.
    
    Returns:
        Global logger instance.
    """
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger
