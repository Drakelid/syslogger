"""
Database optimization utilities for SysLogger.

This module provides functions to optimize database performance through indexes
and query optimizations, as well as implementing data retention policies.
"""
import time
import sqlite3
import datetime
from typing import List, Dict, Any, Optional

from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection

logger = get_logger()

def optimize_database():
    """
    Apply database optimizations including indexes, vacuum, and analyzing tables.
    
    Returns:
        bool: True if optimizations were applied successfully, False otherwise.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Start time for performance measurement
        start_time = time.time()
        
        logger.info("Starting database optimization process...")
        
        # Create indexes on commonly queried fields
        create_indexes(conn)
        
        # Vacuum the database to reclaim space and defragment
        logger.info("Vacuuming database...")
        cursor.execute("VACUUM")
        
        # Analyze tables for query optimization
        logger.info("Analyzing database for query optimization...")
        cursor.execute("ANALYZE")
        
        # Optimize database settings
        optimize_db_settings(conn)
        
        duration = time.time() - start_time
        logger.info(f"Database optimization completed in {duration:.2f} seconds")
        
        return True
        
    except Exception as e:
        logger.error(f"Error optimizing database: {e}")
        return False

def create_indexes(conn: sqlite3.Connection):
    """
    Create indexes on commonly queried fields to improve performance.
    
    Args:
        conn: SQLite database connection
    """
    logger.info("Creating and updating database indexes...")
    
    # List of indexes to create
    indexes = [
        # Syslog table indexes
        ("CREATE INDEX IF NOT EXISTS idx_syslog_timestamp ON syslog(timestamp)", 
         "Timestamp index on syslog table"),
        ("CREATE INDEX IF NOT EXISTS idx_syslog_host ON syslog(host)", 
         "Host index on syslog table"),
        ("CREATE INDEX IF NOT EXISTS idx_syslog_severity ON syslog(severity)", 
         "Severity index on syslog table"),
        ("CREATE INDEX IF NOT EXISTS idx_syslog_facility ON syslog(facility)", 
         "Facility index on syslog table"),
        ("CREATE INDEX IF NOT EXISTS idx_syslog_timestamp_host ON syslog(timestamp, host)", 
         "Composite index for timestamp and host on syslog table"),
        ("CREATE INDEX IF NOT EXISTS idx_syslog_timestamp_severity ON syslog(timestamp, severity)", 
         "Composite index for timestamp and severity on syslog table"),
        
        # Alerts table indexes
        ("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)", 
         "Timestamp index on alerts table"),
        ("CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level)", 
         "Level index on alerts table"),
        ("CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source)", 
         "Source index on alerts table"),
        ("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp_level ON alerts(timestamp, level)", 
         "Composite index for timestamp and level on alerts table"),
        
        # Network flows table indexes
        ("CREATE INDEX IF NOT EXISTS idx_network_flows_timestamp ON network_flows(timestamp)", 
         "Timestamp index on network_flows table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_flows_src_ip ON network_flows(src_ip)", 
         "Source IP index on network_flows table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_flows_dst_ip ON network_flows(dst_ip)", 
         "Destination IP index on network_flows table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_flows_protocol ON network_flows(protocol)", 
         "Protocol index on network_flows table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_flows_timestamp_src_ip ON network_flows(timestamp, src_ip)", 
         "Composite index for timestamp and source IP on network_flows table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_flows_timestamp_dst_ip ON network_flows(timestamp, dst_ip)", 
         "Composite index for timestamp and destination IP on network_flows table"),
        
        # Network anomalies table indexes
        ("CREATE INDEX IF NOT EXISTS idx_network_anomalies_timestamp ON network_anomalies(timestamp)", 
         "Timestamp index on network_anomalies table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_anomalies_score ON network_anomalies(score)", 
         "Score index on network_anomalies table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_anomalies_src_ip ON network_anomalies(src_ip)", 
         "Source IP index on network_anomalies table"),
        ("CREATE INDEX IF NOT EXISTS idx_network_anomalies_dst_ip ON network_anomalies(dst_ip)", 
         "Destination IP index on network_anomalies table"),
        
        # Threat intelligence IOCs table indexes
        ("CREATE INDEX IF NOT EXISTS idx_threat_intel_iocs_type_value ON threat_intel_iocs(ioc_type, ioc_value)", 
         "Composite index for IOC type and value on threat_intel_iocs table"),
        ("CREATE INDEX IF NOT EXISTS idx_threat_intel_iocs_source ON threat_intel_iocs(source)", 
         "Source index on threat_intel_iocs table"),
        ("CREATE INDEX IF NOT EXISTS idx_threat_intel_iocs_last_seen ON threat_intel_iocs(last_seen)", 
         "Last seen index on threat_intel_iocs table"),
    ]
    
    # Create each index
    for index_query, description in indexes:
        try:
            conn.execute(index_query)
            logger.debug(f"Created index: {description}")
        except Exception as e:
            logger.warning(f"Error creating index ({description}): {e}")
    
    # Commit changes
    conn.commit()

def optimize_db_settings(conn: sqlite3.Connection):
    """
    Optimize SQLite database settings for better performance.
    
    Args:
        conn: SQLite database connection
    """
    logger.info("Optimizing database settings...")
    
    # Set optimal pragmas for performance
    pragmas = [
        ("PRAGMA journal_mode = WAL", "Write-Ahead Logging for better concurrency"),
        ("PRAGMA synchronous = NORMAL", "Balanced durability and performance"),
        ("PRAGMA temp_store = MEMORY", "Store temporary tables in memory"),
        ("PRAGMA cache_size = 10000", "Increase cache size (in pages)"),
        ("PRAGMA mmap_size = 30000000000", "Memory-mapped I/O for faster reads"),
        ("PRAGMA foreign_keys = ON", "Enable foreign key constraints"),
    ]
    
    for pragma, description in pragmas:
        try:
            conn.execute(pragma)
            logger.debug(f"Applied setting: {description}")
        except Exception as e:
            logger.warning(f"Error applying setting ({description}): {e}")

def implement_data_retention(retention_config: Dict[str, Any]) -> Dict[str, int]:
    """
    Implement data retention policies based on the provided configuration.
    
    Args:
        retention_config: Dictionary with retention configuration.
            Example: {
                'syslog': {'days': 30, 'max_rows': 1000000},
                'network_flows': {'days': 14, 'max_rows': 500000},
                'alerts': {'days': 90},
                'network_anomalies': {'days': 60},
                'threat_intel_iocs': {'days': 45, 'expired_only': True}
            }
            
    Returns:
        Dictionary with count of deleted rows per table
    """
    try:
        conn = get_db_connection()
        logger.info("Implementing data retention policies...")
        
        deleted_counts = {}
        
        for table, config in retention_config.items():
            # Skip if table not in configuration
            if table not in retention_config:
                continue
            
            days = config.get('days')
            max_rows = config.get('max_rows')
            expired_only = config.get('expired_only', False)
            
            # Skip if no retention policy specified
            if days is None and max_rows is None:
                continue
                
            deleted = 0
            
            # Delete by age if specified
            if days is not None:
                cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
                
                # Handle special case for threat_intel_iocs where we might only want to delete expired IOCs
                if table == 'threat_intel_iocs' and expired_only:
                    query = f"DELETE FROM {table} WHERE last_seen < ?"
                else:
                    query = f"DELETE FROM {table} WHERE timestamp < ?"
                
                cursor = conn.execute(query, (cutoff_date,))
                deleted += cursor.rowcount
                logger.info(f"Deleted {cursor.rowcount} rows from {table} older than {days} days")
                
            # Delete oldest records if max_rows exceeded
            if max_rows is not None:
                # Get current row count
                row_count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                
                # If still over max_rows after date-based deletion, delete oldest records
                if row_count > max_rows:
                    excess = row_count - max_rows
                    
                    # Determine timestamp field name (default is timestamp)
                    timestamp_field = 'timestamp'
                    if table == 'threat_intel_iocs':
                        timestamp_field = 'last_seen'
                        
                    # Delete oldest records exceeding the limit
                    query = f"""
                        DELETE FROM {table} 
                        WHERE rowid IN (
                            SELECT rowid FROM {table}
                            ORDER BY {timestamp_field} ASC
                            LIMIT ?
                        )
                    """
                    cursor = conn.execute(query, (excess,))
                    deleted += cursor.rowcount
                    logger.info(f"Deleted {cursor.rowcount} oldest rows from {table} to maintain max {max_rows} records")
            
            deleted_counts[table] = deleted
            
        # Commit all changes
        conn.commit()
        
        # Vacuum database after large deletions
        conn.execute("VACUUM")
        
        return deleted_counts
        
    except Exception as e:
        logger.error(f"Error implementing data retention: {e}")
        if 'conn' in locals():
            conn.rollback()
        return {}

def get_table_statistics() -> Dict[str, Dict[str, Any]]:
    """
    Get database statistics for all main tables.
    
    Returns:
        Dictionary with table statistics including row counts, size, and oldest/newest records
    """
    try:
        conn = get_db_connection()
        stats = {}
        
        # Tables to analyze
        tables = [
            ('syslog', 'timestamp'),
            ('alerts', 'timestamp'),
            ('network_flows', 'timestamp'),
            ('network_anomalies', 'timestamp'),
            ('threat_intel_iocs', 'last_seen')
        ]
        
        for table, timestamp_field in tables:
            try:
                # Check if table exists
                result = conn.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
                if not result:
                    continue
                
                # Get row count
                row_count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                
                # Get oldest and newest record timestamps
                oldest = conn.execute(f"SELECT MIN({timestamp_field}) FROM {table}").fetchone()[0]
                newest = conn.execute(f"SELECT MAX({timestamp_field}) FROM {table}").fetchone()[0]
                
                # Get approximate size (SQLite doesn't have a direct way to get table size)
                # This is an approximation based on the rowid
                avg_row_size = conn.execute(f"""
                    SELECT AVG(LENGTH(CAST(rowid AS TEXT)) + LENGTH(*)) 
                    FROM {table} 
                    LIMIT 100
                """).fetchone()[0] or 0
                
                estimated_size = int(row_count * avg_row_size)
                
                stats[table] = {
                    'row_count': row_count,
                    'oldest_record': oldest,
                    'newest_record': newest,
                    'estimated_size_bytes': estimated_size,
                    'estimated_size_mb': round(estimated_size / (1024 * 1024), 2)
                }
                
            except Exception as e:
                logger.warning(f"Error getting statistics for table {table}: {e}")
                stats[table] = {'error': str(e)}
        
        # Get overall database statistics
        try:
            db_size = conn.execute("PRAGMA page_count").fetchone()[0] * conn.execute("PRAGMA page_size").fetchone()[0]
            stats['database'] = {
                'size_bytes': db_size,
                'size_mb': round(db_size / (1024 * 1024), 2),
                'free_pages': conn.execute("PRAGMA freelist_count").fetchone()[0],
                'page_size': conn.execute("PRAGMA page_size").fetchone()[0]
            }
        except Exception as e:
            logger.warning(f"Error getting overall database statistics: {e}")
            
        return stats
        
    except Exception as e:
        logger.error(f"Error getting table statistics: {e}")
        return {}

def analyze_query_performance(query: str, params: tuple = ()) -> Dict[str, Any]:
    """
    Analyze the performance of a specific query using SQLite EXPLAIN QUERY PLAN.
    
    Args:
        query: SQL query to analyze
        params: Query parameters
        
    Returns:
        Dictionary with query plan and execution statistics
    """
    try:
        conn = get_db_connection()
        result = {}
        
        # Get query plan
        plan = conn.execute(f"EXPLAIN QUERY PLAN {query}", params).fetchall()
        result['plan'] = [dict(row) for row in plan]
        
        # Measure execution time
        start_time = time.time()
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        duration = time.time() - start_time
        
        result['statistics'] = {
            'execution_time_ms': round(duration * 1000, 2),
            'row_count': len(rows)
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing query performance: {e}")
        return {'error': str(e)}
