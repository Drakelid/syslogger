"""
Maintenance utilities for SysLogger.

This module provides maintenance routines for the SysLogger application,
including database maintenance, log rotation, and automated cleanup tasks.
"""
import time
import threading
import datetime
import schedule
from typing import Dict, Any, Optional

from syslogger.core.logger import get_logger
from syslogger.config.config import get_config
from syslogger.core.db_optimize import optimize_database, implement_data_retention, get_table_statistics

logger = get_logger()

# Global flag to control the maintenance thread
_maintenance_running = False
_maintenance_thread = None

def get_default_retention_config():
    """
    Get the default data retention configuration.
    
    Returns:
        Dictionary with default retention configuration
    """
    # Default retention policies
    return {
        'syslog': {
            'days': 30,  # Keep logs for 30 days
            'max_rows': 1000000  # Maximum 1 million rows
        },
        'network_flows': {
            'days': 14,  # Keep network flows for 14 days
            'max_rows': 500000  # Maximum 500,000 rows
        },
        'alerts': {
            'days': 90  # Keep alerts for 90 days
        },
        'network_anomalies': {
            'days': 60  # Keep anomalies for 60 days
        },
        'threat_intel_iocs': {
            'days': 45,  # Keep IOCs for 45 days
            'expired_only': True  # Only remove expired IOCs
        }
    }

def load_retention_config():
    """
    Load data retention configuration from system config.
    
    Returns:
        Dictionary with retention configuration
    """
    config = get_config()
    retention_config = get_default_retention_config()
    
    # Override with user config if available
    if 'data_retention' in config:
        user_config = config.get('data_retention', {})
        
        # Update each table's retention settings if defined
        for table in retention_config:
            if table in user_config:
                retention_config[table].update(user_config[table])
    
    return retention_config

def run_maintenance_tasks():
    """
    Run all scheduled maintenance tasks.
    
    Returns:
        Dictionary with results of maintenance tasks
    """
    results = {}
    start_time = time.time()
    
    logger.info("Starting scheduled maintenance tasks")
    
    try:
        # Apply data retention policies
        retention_config = load_retention_config()
        deleted_counts = implement_data_retention(retention_config)
        results['data_retention'] = {
            'status': 'success' if deleted_counts else 'error',
            'deleted_counts': deleted_counts
        }
        
        # Optimize database
        db_optimize_success = optimize_database()
        results['database_optimization'] = {
            'status': 'success' if db_optimize_success else 'error'
        }
        
        # Get database statistics after maintenance
        stats = get_table_statistics()
        results['database_statistics'] = stats
        
        # Log a summary of the maintenance results
        duration = time.time() - start_time
        rows_deleted = sum(deleted_counts.values()) if deleted_counts else 0
        logger.info(f"Maintenance completed in {duration:.2f} seconds. "
                   f"Deleted {rows_deleted} rows. "
                   f"Database size: {stats.get('database', {}).get('size_mb', 0)} MB")
        
        results['status'] = 'success'
        results['duration'] = duration
        
    except Exception as e:
        logger.error(f"Error during maintenance tasks: {e}")
        results['status'] = 'error'
        results['error'] = str(e)
        
    return results

def maintenance_worker():
    """
    Background thread function for running scheduled maintenance.
    """
    global _maintenance_running
    
    logger.info("Starting maintenance scheduler thread")
    
    config = get_config()
    maintenance_time = config.get('maintenance', {}).get('time', '02:00')  # Default to 2 AM
    
    # Schedule maintenance tasks
    schedule.every().day.at(maintenance_time).do(run_maintenance_tasks)
    
    # If immediate maintenance is enabled, run once at startup
    if config.get('maintenance', {}).get('run_at_startup', False):
        logger.info("Running initial maintenance tasks at startup")
        run_maintenance_tasks()
    
    # Main loop
    while _maintenance_running:
        schedule.run_pending()
        time.sleep(60)  # Check every minute
        
    logger.info("Maintenance scheduler thread stopped")

def start_maintenance_scheduler():
    """
    Start the maintenance scheduler in a background thread.
    
    Returns:
        bool: True if started successfully, False otherwise
    """
    global _maintenance_running, _maintenance_thread
    
    if _maintenance_running:
        logger.warning("Maintenance scheduler already running")
        return False
    
    try:
        _maintenance_running = True
        _maintenance_thread = threading.Thread(target=maintenance_worker, daemon=True)
        _maintenance_thread.start()
        logger.info("Maintenance scheduler started")
        return True
    except Exception as e:
        logger.error(f"Failed to start maintenance scheduler: {e}")
        _maintenance_running = False
        return False

def stop_maintenance_scheduler():
    """
    Stop the maintenance scheduler thread.
    
    Returns:
        bool: True if stopped successfully, False otherwise
    """
    global _maintenance_running, _maintenance_thread
    
    if not _maintenance_running:
        logger.warning("Maintenance scheduler not running")
        return False
    
    try:
        _maintenance_running = False
        if _maintenance_thread:
            _maintenance_thread.join(timeout=5)
        logger.info("Maintenance scheduler stopped")
        return True
    except Exception as e:
        logger.error(f"Error stopping maintenance scheduler: {e}")
        return False

def run_immediate_maintenance():
    """
    Run maintenance tasks immediately (on-demand).
    
    Returns:
        Dictionary with results of maintenance tasks
    """
    logger.info("Running immediate maintenance")
    return run_maintenance_tasks()
