"""
Database management module for SysLogger.
Handles SQLite connections and basic operations.
"""
import os
import sqlite3
import json
import threading
from typing import Dict, Any, List, Tuple, Optional, Union

from syslogger.config.config import get_config
from syslogger.core.logger import get_logger

# Thread-local storage for database connections
_local = threading.local()

def get_db_connection(db_path: str = None) -> sqlite3.Connection:
    """
    Get a thread-safe SQLite connection.
    
    Args:
        db_path: Path to the SQLite database file.
        
    Returns:
        SQLite connection object.
    """
    if db_path is None:
        db_path = get_config().get('storage.db_file')
        
    # Ensure the directory exists
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    
    # Check if we already have a connection for this thread and path
    if not hasattr(_local, 'connections'):
        _local.connections = {}
    
    if db_path not in _local.connections:
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        _local.connections[db_path] = conn
        
        # Initialize schema if needed
        initialize_schema(conn, db_path)
        
    return _local.connections[db_path]

def initialize_schema(conn: sqlite3.Connection, db_path: str) -> None:
    """
    Initialize the database schema if it doesn't already exist.
    
    Args:
        conn: SQLite connection.
        db_path: Path to the database file (used to determine which schema to initialize).
    """
    config = get_config()
    logger = get_logger()
    
    if db_path == config.get('storage.db_file'):
        # Main syslog database
        conn.execute(
            "CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, host TEXT, message TEXT)"
        )
        logger.debug("Initialized syslog database schema")
    
    elif db_path == config.get('storage.attacker_info_db'):
        # Attacker information database
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attackers (
                identifier TEXT PRIMARY KEY,
                ip TEXT,
                mac TEXT,
                first_seen TEXT,
                last_seen TEXT,
                attack_types TEXT,
                hostname TEXT,
                geolocation TEXT,
                open_ports TEXT,
                os_info TEXT,
                reputation TEXT,
                connections TEXT
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ml_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                identifier TEXT,
                model_type TEXT,       -- anomaly, classifier, etc.
                input_data TEXT,        -- serialized input data for the model
                results TEXT,           -- serialized output from the model
                model_version TEXT      -- model identifier/version used
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                report_type TEXT,       -- daily, weekly, custom, etc.
                title TEXT,
                content_path TEXT,      -- path to stored report content
                format TEXT,            -- pdf, xlsx, html, etc.
                parameters TEXT         -- JSON of parameters used to generate the report
            )
        """)
        logger.debug("Initialized attacker info database schema")

def insert_log(timestamp: str, host: str, message: str) -> None:
    """
    Insert a log entry into the database.
    
    Args:
        timestamp: Log timestamp.
        host: Host that generated the log.
        message: Log message.
    """
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO logs (timestamp, host, message) VALUES (?, ?, ?)",
            (timestamp, host, message)
        )
        conn.commit()
    except Exception as e:
        get_logger().error(f"Error inserting log: {e}")

def get_recent_logs(limit: int = 100, filter_terms: List[str] = None) -> List[Dict[str, str]]:
    """
    Get recent logs from the database.
    
    Args:
        limit: Maximum number of logs to return.
        filter_terms: Optional list of terms to filter logs by.
        
    Returns:
        List of log entries as dictionaries.
    """
    conn = get_db_connection()
    try:
        query = "SELECT timestamp, host, message FROM logs ORDER BY rowid DESC LIMIT ?"
        params = [limit]
        
        if filter_terms and len(filter_terms) > 0:
            filter_conditions = []
            for term in filter_terms:
                filter_conditions.append("message LIKE ?")
                params.append(f"%{term}%")
            
            query = f"""SELECT timestamp, host, message FROM logs 
                      WHERE {' AND '.join(filter_conditions)} 
                      ORDER BY rowid DESC LIMIT ?"""
        
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        get_logger().error(f"Error getting recent logs: {e}")
        return []

def get_or_create_attacker_info(identifier: str, ip: Optional[str] = None, 
                              mac: Optional[str] = None) -> Dict[str, Any]:
    """
    Get existing attacker info or create new entry.
    
    Args:
        identifier: Unique identifier for the attacker (IP or MAC).
        ip: IP address if available.
        mac: MAC address if available.
        
    Returns:
        Dictionary with attacker information.
    """
    conn = get_db_connection(get_config().get('storage.attacker_info_db'))
    try:
        cursor = conn.execute(
            "SELECT * FROM attackers WHERE identifier = ?", 
            (identifier,)
        )
        row = cursor.fetchone()
        
        if row:
            # Convert row to dictionary
            attacker_info = dict(row)
            
            # Parse JSON fields
            for json_field in ['attack_types', 'geolocation', 'open_ports', 'os_info', 'reputation', 'connections']:
                if json_field in attacker_info and attacker_info[json_field]:
                    try:
                        attacker_info[json_field] = json.loads(attacker_info[json_field])
                    except json.JSONDecodeError:
                        attacker_info[json_field] = {}
            
            return attacker_info
        else:
            # Create new attacker
            import datetime
            now = datetime.datetime.now().isoformat()
            
            new_attacker = {
                'identifier': identifier,
                'ip': ip or '',
                'mac': mac or '',
                'first_seen': now,
                'last_seen': now,
                'attack_types': [],
                'hostname': '',
                'geolocation': {},
                'open_ports': {},
                'os_info': {},
                'reputation': {},
                'connections': []
            }
            
            # Insert into database
            conn.execute(
                """INSERT INTO attackers 
                   (identifier, ip, mac, first_seen, last_seen, attack_types, 
                    hostname, geolocation, open_ports, os_info, reputation, connections)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    new_attacker['identifier'],
                    new_attacker['ip'],
                    new_attacker['mac'],
                    new_attacker['first_seen'],
                    new_attacker['last_seen'],
                    json.dumps(new_attacker['attack_types']),
                    new_attacker['hostname'],
                    json.dumps(new_attacker['geolocation']),
                    json.dumps(new_attacker['open_ports']),
                    json.dumps(new_attacker['os_info']),
                    json.dumps(new_attacker['reputation']),
                    json.dumps(new_attacker['connections'])
                )
            )
            conn.commit()
            
            return new_attacker
    except Exception as e:
        get_logger().error(f"Error getting/creating attacker info: {e}")
        # Return a minimal attacker info object
        return {
            'identifier': identifier,
            'ip': ip or '',
            'mac': mac or '',
            'first_seen': '',
            'last_seen': '',
            'attack_types': [],
            'hostname': '',
            'geolocation': {},
            'open_ports': {},
            'os_info': {},
            'reputation': {},
            'connections': []
        }

def save_attacker_info(attacker_info: Dict[str, Any]) -> bool:
    """
    Save attacker information to database.
    
    Args:
        attacker_info: Dictionary with attacker information.
        
    Returns:
        True if successful, False otherwise.
    """
    conn = get_db_connection(get_config().get('storage.attacker_info_db'))
    try:
        # Convert JSON fields to strings
        attacker_dict = attacker_info.copy()
        for json_field in ['attack_types', 'geolocation', 'open_ports', 'os_info', 'reputation', 'connections']:
            if json_field in attacker_dict:
                attacker_dict[json_field] = json.dumps(attacker_dict[json_field])
        
        conn.execute(
            """UPDATE attackers SET
               ip = ?, mac = ?, first_seen = ?, last_seen = ?, attack_types = ?,
               hostname = ?, geolocation = ?, open_ports = ?, os_info = ?,
               reputation = ?, connections = ?
               WHERE identifier = ?""",
            (
                attacker_dict['ip'],
                attacker_dict['mac'],
                attacker_dict['first_seen'],
                attacker_dict['last_seen'],
                attacker_dict['attack_types'],
                attacker_dict['hostname'],
                attacker_dict['geolocation'],
                attacker_dict['open_ports'],
                attacker_dict['os_info'],
                attacker_dict['reputation'],
                attacker_dict['connections'],
                attacker_dict['identifier']
            )
        )
        conn.commit()
        return True
    except Exception as e:
        get_logger().error(f"Error saving attacker info: {e}")
        return False

def get_all_attackers(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Get all attackers from the database.
    
    Args:
        limit: Maximum number of attackers to return.
        
    Returns:
        List of attacker information dictionaries.
    """
    conn = get_db_connection(get_config().get('storage.attacker_info_db'))
    try:
        cursor = conn.execute(
            """SELECT identifier, ip, mac, first_seen, last_seen, attack_types
               FROM attackers ORDER BY last_seen DESC LIMIT ?""",
            (limit,)
        )
        
        attackers = []
        for row in cursor.fetchall():
            attacker = dict(row)
            
            # Parse JSON fields
            if 'attack_types' in attacker and attacker['attack_types']:
                try:
                    attacker['attack_types'] = json.loads(attacker['attack_types'])
                except json.JSONDecodeError:
                    attacker['attack_types'] = []
            
            attackers.append(attacker)
        
        return attackers
    except Exception as e:
        get_logger().error(f"Error getting attackers: {e}")
        return []
