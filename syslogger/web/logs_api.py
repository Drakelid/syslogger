"""
Logs API endpoints for SysLogger.
Provides access to live syslog data from router with filtering and pagination.
"""
import re
import datetime
from typing import List, Dict, Any, Optional

from flask import Blueprint, request, jsonify
from syslogger.core.database import get_db_connection
from syslogger.core.logger import get_logger

# Create blueprint
logs_bp = Blueprint('logs_api', __name__)
logger = get_logger()

# Syslog severity mapping
SEVERITY_LEVELS = {
    0: 'EMERGENCY',
    1: 'ALERT',
    2: 'CRITICAL',
    3: 'ERROR',
    4: 'WARNING',
    5: 'NOTICE',
    6: 'INFO',
    7: 'DEBUG'
}

# Syslog facility mapping
FACILITY_TYPES = {
    0: 'kernel',
    1: 'user',
    2: 'mail',
    3: 'system',
    4: 'security',
    5: 'syslog',
    6: 'printer',
    7: 'network',
    8: 'UUCP',
    9: 'clock',
    10: 'security',
    11: 'FTP',
    12: 'NTP',
    13: 'log audit',
    14: 'log alert',
    15: 'clock',
    16: 'local0',
    17: 'local1',
    18: 'local2',
    19: 'local3',
    20: 'local4',
    21: 'local5',
    22: 'local6',
    23: 'local7'
}

def parse_syslog_priority(message: str) -> tuple:
    """Parse syslog priority value from message."""
    pri_match = re.match(r'<(\d+)>', message)
    if pri_match:
        priority = int(pri_match.group(1))
        # Extract facility and severity from priority
        facility = priority >> 3
        severity = priority & 0x7
        return facility, severity
    return None, None

def parse_syslog_timestamp(message: str) -> Optional[str]:
    """Extract and parse timestamp from syslog message."""
    # Common syslog timestamp patterns
    patterns = [
        # RFC3164 format: MMM DD HH:MM:SS
        r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        # ISO format: YYYY-MM-DD HH:MM:SS
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(1)
    
    # If no timestamp found, use current time
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def extract_syslog_header(message: str) -> str:
    """Extract the header portion of a syslog message."""
    # Try to extract hostname/program name
    header_match = re.search(r'<\d+>.*?\s+([^\s:]+)(?::\s|\[\d+\]:|:)', message)
    if header_match:
        return header_match.group(1)
    return ""

@logs_bp.route('/api/logs')
def get_logs():
    """
    API endpoint to get logs with advanced filtering and pagination.
    
    Query parameters:
        - page: Page number (default: 1)
        - limit: Number of logs per page (default: 25)
        - severity: Filter by severity level (all, info, warning, error, critical)
        - source: Filter by source/facility
        - timeRange: Time range to filter (1h, 12h, 24h, 7d, 30d)
        - search: Search term to filter by
    
    Returns:
        JSON with logs, total count, and pagination info
    """
    # Get query parameters
    page = request.args.get('page', default=1, type=int)
    limit = request.args.get('limit', default=25, type=int)
    severity = request.args.get('severity', default='all', type=str)
    source = request.args.get('source', default='all', type=str)
    time_range = request.args.get('timeRange', default='24h', type=str)
    search_term = request.args.get('search', default='', type=str)
    
    # Validate and sanitize inputs
    if page < 1:
        page = 1
    if limit < 1 or limit > 100:
        limit = 25
    
    # Calculate offset
    offset = (page - 1) * limit
    
    conn = get_db_connection()
    query_params = []
    where_clauses = []
    
    try:
        # Base query
        query = """
            SELECT rowid, timestamp, host, message 
            FROM logs 
        """
        
        # Add time range filter
        if time_range:
            current_time = datetime.datetime.now()
            if time_range == '1h':
                time_threshold = current_time - datetime.timedelta(hours=1)
            elif time_range == '12h':
                time_threshold = current_time - datetime.timedelta(hours=12)
            elif time_range == '24h':
                time_threshold = current_time - datetime.timedelta(hours=24)
            elif time_range == '7d':
                time_threshold = current_time - datetime.timedelta(days=7)
            elif time_range == '30d':
                time_threshold = current_time - datetime.timedelta(days=30)
            else:
                time_threshold = current_time - datetime.timedelta(hours=24)
            
            # Format for database comparison
            time_str = time_threshold.strftime('%Y-%m-%d %H:%M:%S')
            where_clauses.append("timestamp >= ?")
            query_params.append(time_str)
        
        # Add search term filter
        if search_term:
            where_clauses.append("message LIKE ?")
            query_params.append(f'%{search_term}%')
        
        # Build WHERE clause
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        # Add ordering and limits
        query += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
        query_params.extend([limit, offset])
        
        # Execute query
        cursor = conn.execute(query, query_params)
        rows = cursor.fetchall()
        
        # Get total count (without pagination)
        count_query = """
            SELECT COUNT(*) FROM logs
        """
        if where_clauses:
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        count_cursor = conn.execute(count_query, query_params[:-2] if query_params else [])
        total_count = count_cursor.fetchone()[0]
        
        # Process log entries
        logs = []
        for row in rows:
            log_entry = dict(row)
            
            # Extract message
            message = log_entry.get('message', '')
            
            # Parse facility and severity
            facility_num, severity_num = parse_syslog_priority(message)
            
            # Filter by severity if specified (post-processing filter)
            severity_text = SEVERITY_LEVELS.get(severity_num, 'INFO').lower() if severity_num is not None else 'info'
            facility_text = FACILITY_TYPES.get(facility_num, 'system') if facility_num is not None else 'system'
            
            if severity != 'all' and severity_text != severity.lower():
                continue
                
            if source != 'all' and facility_text != source.lower():
                continue
            
            # Clean up message for display
            clean_message = re.sub(r'<\d+>', '', message).strip()
            
            # Create structured log entry
            structured_entry = {
                'id': log_entry.get('rowid'),
                'timestamp': log_entry.get('timestamp'),
                'host': log_entry.get('host'),
                'severity': SEVERITY_LEVELS.get(severity_num, 'INFO') if severity_num is not None else 'INFO',
                'facility': facility_text,
                'header': extract_syslog_header(message),
                'message': clean_message
            }
            
            logs.append(structured_entry)
        
        # Return formatted response
        return jsonify({
            'status': 'success',
            'logs': logs,
            'total': total_count,
            'page': page,
            'limit': limit,
            'pages': (total_count + limit - 1) // limit,
            'isUpdate': False
        })
    
    except Exception as e:
        logger.error(f"Error retrieving logs: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@logs_bp.route('/api/logs/sources')
def get_log_sources():
    """Get available log sources/facilities."""
    try:
        # Analyze existing logs for unique sources
        conn = get_db_connection()
        cursor = conn.execute("SELECT DISTINCT message FROM logs LIMIT 1000")
        
        sources = {}
        
        for row in cursor.fetchall():
            message = row['message']
            facility_num, _ = parse_syslog_priority(message)
            facility = FACILITY_TYPES.get(facility_num, None)
            
            if facility:
                sources[facility] = sources.get(facility, 0) + 1
        
        return jsonify({
            'status': 'success',
            'sources': [
                {'name': source, 'count': count} 
                for source, count in sources.items()
            ]
        })
        
    except Exception as e:
        logger.error(f"Error retrieving log sources: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
