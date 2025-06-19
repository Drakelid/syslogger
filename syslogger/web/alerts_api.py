"""
Alerts API endpoints for SysLogger.
Provides access to live security alerts generated from router syslog data.
"""
import re
import json
import datetime
import uuid
from typing import List, Dict, Any, Optional

from flask import Blueprint, request, jsonify
from syslogger.core.database import get_db_connection
from syslogger.core.logger import get_logger
from syslogger.security.correlation import get_correlation_engine

# Create blueprint
alerts_bp = Blueprint('alerts_api', __name__)
logger = get_logger()

# Alert patterns to match in syslog messages
ALERT_PATTERNS = [
    {
        'pattern': r'authentication failure|failed login|invalid user|failed password',
        'title': 'Authentication Failure',
        'severity': 'medium',
        'type': 'auth'
    },
    {
        'pattern': r'multiple authentication failures|repeated login failures|brute force|dictionary attack',
        'title': 'Multiple Authentication Failures',
        'severity': 'high', 
        'type': 'auth'
    },
    {
        'pattern': r'port scan|nmap|scan from',
        'title': 'Port Scan Detected',
        'severity': 'high',
        'type': 'network'
    },
    {
        'pattern': r'firewall block|dropped|rejected|denied',
        'title': 'Firewall Block',
        'severity': 'medium',
        'type': 'firewall'
    },
    {
        'pattern': r'malware|virus|trojan|ransomware|spyware',
        'title': 'Malware Detection',
        'severity': 'high',
        'type': 'security'
    },
    {
        'pattern': r'disk space|low on space|running out of space|space low|capacity reached',
        'title': 'Disk Space Warning',
        'severity': 'medium',
        'type': 'system'
    },
    {
        'pattern': r'cpu usage|load high|system overload',
        'title': 'High System Load',
        'severity': 'medium',
        'type': 'system'
    },
    {
        'pattern': r'ssh|telnet|ftp|smb|rdp|vnc.*from unknown|from suspicious|from unauthorized',
        'title': 'Suspicious Connection',
        'severity': 'medium',
        'type': 'network'
    },
    {
        'pattern': r'admin login|administrator|root login|privilege|sudo|su root',
        'title': 'Administrative Login',
        'severity': 'low',
        'type': 'auth'
    },
    {
        'pattern': r'config changed|configuration|modified settings',
        'title': 'Configuration Change',
        'severity': 'low',
        'type': 'system'
    }
]

# Cache for alerts to avoid duplicates
alert_cache = {}
# Store for active alerts
active_alerts = []

def generate_alert_id() -> str:
    """Generate a unique ID for an alert."""
    timestamp = datetime.datetime.now().strftime('%y%m%d')
    random_part = uuid.uuid4().hex[:6]
    return f"ALT-{timestamp}-{random_part}"

def extract_ip_addresses(message: str) -> List[str]:
    """Extract IP addresses from a message."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, message)

def extract_usernames(message: str) -> List[str]:
    """Extract usernames from a message."""
    # Common patterns for usernames in logs
    patterns = [
        r'user[=:\s]+([a-zA-Z0-9_.-]+)',
        r'username[=:\s]+([a-zA-Z0-9_.-]+)',
        r'account[=:\s]+([a-zA-Z0-9_.-]+)',
        r'login[=:\s]+([a-zA-Z0-9_.-]+)'
    ]
    
    results = []
    for pattern in patterns:
        matches = re.findall(pattern, message, re.IGNORECASE)
        results.extend(matches)
    
    return results

def analyze_logs_for_alerts(timeframe_hours: int = 24) -> List[Dict[str, Any]]:
    """
    Analyze logs within a specific timeframe for security alerts.
    
    Args:
        timeframe_hours: Number of hours to look back in logs
        
    Returns:
        List of alert dictionaries
    """
    # Clear old cached alerts (older than the timeframe)
    current_time = datetime.datetime.now()
    cutoff_time = current_time - datetime.timedelta(hours=timeframe_hours)
    cutoff_str = cutoff_time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Remove old alerts from cache
    global alert_cache
    for key in list(alert_cache.keys()):
        if alert_cache[key]['timestamp'] < cutoff_str:
            del alert_cache[key]
    
    conn = get_db_connection()
    new_alerts = []
    
    try:
        # Get logs within timeframe
        query = """
            SELECT rowid, timestamp, host, message 
            FROM logs
            WHERE timestamp >= ?
            ORDER BY rowid DESC
        """
        
        cursor = conn.execute(query, (cutoff_str,))
        logs = cursor.fetchall()
        
        # Process logs for alert patterns
        for log in logs:
            log_entry = dict(log)
            message = log_entry.get('message', '')
            timestamp = log_entry.get('timestamp', '')
            host = log_entry.get('host', '')
            
            # Check each alert pattern
            for alert_def in ALERT_PATTERNS:
                pattern = alert_def['pattern']
                
                if re.search(pattern, message, re.IGNORECASE):
                    # Found a match - create alert if not already in cache
                    
                    # Create a cache key based on pattern and part of the message
                    message_hash = hash(f"{pattern}:{message[:50]}")
                    
                    if message_hash not in alert_cache:
                        # Extract relevant details
                        ip_addresses = extract_ip_addresses(message)
                        usernames = extract_usernames(message)
                        
                        alert_id = generate_alert_id()
                        
                        # Format alert message
                        alert_message = message
                        if ip_addresses:
                            ip_str = ', '.join(ip_addresses)
                            if not re.search(ip_str, alert_message):
                                alert_message += f" [IP(s): {ip_str}]"
                        
                        if usernames:
                            user_str = ', '.join(usernames)
                            if not re.search(user_str, alert_message):
                                alert_message += f" [User(s): {user_str}]"
                        
                        # Create alert
                        alert = {
                            'id': alert_id,
                            'timestamp': timestamp,
                            'host': host,
                            'title': alert_def['title'],
                            'message': alert_message,
                            'severity': alert_def['severity'],
                            'type': alert_def['type'],
                            'source_log_id': log_entry.get('rowid'),
                            'status': 'active',
                            'related_ips': ip_addresses,
                            'related_users': usernames
                        }
                        
                        # Add to cache and results
                        alert_cache[message_hash] = alert
                        new_alerts.append(alert)
        
        # Perform event correlation for more complex alerts
        # Get the correlation engine singleton
        correlation_engine = get_correlation_engine()
        
        # Process each log entry for correlation
        correlated_alerts = []
        for log in logs:
            log_entry = dict(log)
            timestamp = log_entry.get('timestamp', '')
            host = log_entry.get('host', '')
            message = log_entry.get('message', '')
            
            # Use the correlation engine to process this log
            result = correlation_engine.process_log(timestamp, host, message)
            if result and isinstance(result, dict) and result.get('alert', False):
                # Convert correlation result to alert format
                alert_id = generate_alert_id()
                correlated_alert = {
                    'id': alert_id,
                    'timestamp': timestamp,
                    'host': host,
                    'title': f"Correlated Event: {result.get('event_type', 'unknown').title()}",
                    'message': result.get('message', 'Correlated event detected'),
                    'severity': 'high',
                    'type': 'correlation',
                    'source_log_id': log_entry.get('rowid'),
                    'status': 'active',
                    'related_ips': [],
                    'related_users': []
                }
                correlated_alerts.append(correlated_alert)
        
        # Add correlated alerts to the main alerts list
        for alert in correlated_alerts:
            if not any(a.get('id') == alert.get('id') for a in new_alerts):
                new_alerts.append(alert)
        
        # Update global active alerts
        global active_alerts
        active_alerts = [alert for alert in active_alerts 
                        if alert.get('timestamp', '') >= cutoff_str 
                        and alert.get('status', '') == 'active']
        
        # Add new alerts to active alerts if not already present
        for new_alert in new_alerts:
            if not any(a.get('id') == new_alert.get('id') for a in active_alerts):
                active_alerts.append(new_alert)
                
        return active_alerts
        
    except Exception as e:
        logger.error(f"Error analyzing logs for alerts: {e}")
        return []

@alerts_bp.route('/api/alerts')
def get_alerts():
    """
    API endpoint to get active alerts.
    
    Query parameters:
        - severity: Filter by severity (all, high, medium, low)
        - type: Filter by alert type
        - timeRange: Hours to look back (default: 24)
    
    Returns:
        JSON with alerts and counts
    """
    try:
        # Get query parameters
        severity = request.args.get('severity', default='all', type=str)
        alert_type = request.args.get('type', default='all', type=str)
        time_range = request.args.get('timeRange', default='24', type=str)
        
        # Convert time range to hours
        hours = 24
        if time_range == '1h':
            hours = 1
        elif time_range == '12h':
            hours = 12
        elif time_range == '24h':
            hours = 24
        elif time_range == '7d':
            hours = 24 * 7
        elif time_range == '30d':
            hours = 24 * 30
        
        # Get alerts from logs
        alerts = analyze_logs_for_alerts(hours)
        
        # Filter by severity if requested
        if severity != 'all':
            alerts = [a for a in alerts if a.get('severity') == severity]
        
        # Filter by type if requested
        if alert_type != 'all':
            alerts = [a for a in alerts if a.get('type') == alert_type]
        
        # Count by severity
        high_count = sum(1 for a in alerts if a.get('severity') == 'high')
        medium_count = sum(1 for a in alerts if a.get('severity') == 'medium')
        low_count = sum(1 for a in alerts if a.get('severity') == 'low')
        
        return jsonify({
            'status': 'success',
            'alerts': alerts,
            'total': len(alerts),
            'highCount': high_count,
            'mediumCount': medium_count,
            'lowCount': low_count
        })
        
    except Exception as e:
        logger.error(f"Error retrieving alerts: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@alerts_bp.route('/api/alerts/counts')
def get_alert_counts():
    """Get counts of active alerts by severity."""
    try:
        # Get alerts for the last 24 hours
        alerts = analyze_logs_for_alerts(24)
        
        # Count by severity
        high_count = sum(1 for a in alerts if a.get('severity') == 'high')
        medium_count = sum(1 for a in alerts if a.get('severity') == 'medium')
        low_count = sum(1 for a in alerts if a.get('severity') == 'low')
        
        return jsonify({
            'status': 'success',
            'total': len(alerts),
            'highCount': high_count,
            'mediumCount': medium_count,
            'lowCount': low_count
        })
        
    except Exception as e:
        logger.error(f"Error retrieving alert counts: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@alerts_bp.route('/api/alerts/<alert_id>/investigate')
def investigate_alert(alert_id):
    """
    Investigate a specific alert.
    
    Args:
        alert_id: Alert ID to investigate
        
    Returns:
        JSON with detailed alert information
    """
    try:
        # Find alert in active alerts
        alert = next((a for a in active_alerts if a.get('id') == alert_id), None)
        
        if not alert:
            return jsonify({
                'status': 'error',
                'message': f"Alert with ID {alert_id} not found"
            }), 404
            
        # Get related logs for investigation
        conn = get_db_connection()
        related_logs = []
        
        # If alert has related IPs, get logs containing those IPs
        if alert.get('related_ips'):
            for ip in alert.get('related_ips'):
                query = """
                    SELECT timestamp, host, message
                    FROM logs
                    WHERE message LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT 20
                """
                cursor = conn.execute(query, (f"%{ip}%",))
                related_logs.extend([dict(row) for row in cursor.fetchall()])
        
        # If alert has related users, get logs containing those users
        if alert.get('related_users'):
            for user in alert.get('related_users'):
                query = """
                    SELECT timestamp, host, message
                    FROM logs
                    WHERE message LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT 20
                """
                cursor = conn.execute(query, (f"%{user}%",))
                related_logs.extend([dict(row) for row in cursor.fetchall()])
        
        # Deduplicate logs based on timestamp and message
        seen = set()
        unique_logs = []
        for log in related_logs:
            key = f"{log.get('timestamp')}:{log.get('message')[:50]}"
            if key not in seen:
                seen.add(key)
                unique_logs.append(log)
        
        # Get source log that triggered the alert
        source_log = None
        if alert.get('source_log_id'):
            query = """
                SELECT timestamp, host, message
                FROM logs
                WHERE rowid = ?
            """
            cursor = conn.execute(query, (alert.get('source_log_id'),))
            source_log = dict(cursor.fetchone()) if cursor.fetchone() else None
        
        # Return investigation results
        return jsonify({
            'status': 'success',
            'alert': alert,
            'sourceLog': source_log,
            'relatedLogs': unique_logs[:20],  # Limit to 20 related logs
            'recommendations': get_recommendations(alert)
        })
        
    except Exception as e:
        logger.error(f"Error investigating alert: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@alerts_bp.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """
    Mark an alert as resolved.
    
    Args:
        alert_id: Alert ID to resolve
        
    Returns:
        JSON with status
    """
    try:
        # Find alert in active alerts
        global active_alerts
        alert = next((a for a in active_alerts if a.get('id') == alert_id), None)
        
        if not alert:
            return jsonify({
                'status': 'error',
                'message': f"Alert with ID {alert_id} not found"
            }), 404
        
        # Mark alert as resolved
        alert['status'] = 'resolved'
        alert['resolved_at'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Remove from active alerts list
        active_alerts = [a for a in active_alerts if a.get('id') != alert_id]
        
        # Store in database for historical records
        conn = get_db_connection()
        try:
            # Check if alerts table exists, create if not
            conn.execute("""
                CREATE TABLE IF NOT EXISTS resolved_alerts (
                    id TEXT PRIMARY KEY,
                    alert_data TEXT,
                    resolved_at TEXT
                )
            """)
            
            # Store resolved alert
            conn.execute(
                "INSERT OR REPLACE INTO resolved_alerts (id, alert_data, resolved_at) VALUES (?, ?, ?)",
                (alert_id, json.dumps(alert), alert['resolved_at'])
            )
            conn.commit()
        except Exception as e:
            logger.error(f"Error storing resolved alert: {e}")
        
        return jsonify({
            'status': 'success',
            'message': f"Alert {alert_id} marked as resolved"
        })
        
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def get_recommendations(alert: Dict[str, Any]) -> List[str]:
    """
    Generate recommendations based on alert type.
    
    Args:
        alert: Alert dictionary
        
    Returns:
        List of recommendation strings
    """
    recommendations = []
    alert_type = alert.get('type')
    severity = alert.get('severity')
    
    # Common recommendations by alert type
    if alert_type == 'auth':
        recommendations.extend([
            "Review authentication logs for patterns of suspicious activity",
            "Verify that strong password policies are enforced",
            "Consider implementing multi-factor authentication",
            "Check for unauthorized access to user accounts"
        ])
        
        if severity == 'high':
            recommendations.append("Lock the account temporarily after multiple failures")
            recommendations.append("Block the source IP address if failures persist")
    
    elif alert_type == 'network':
        recommendations.extend([
            "Review firewall rules to ensure they are properly configured",
            "Check for unauthorized services listening on open ports",
            "Monitor network traffic for unusual patterns"
        ])
        
        if severity == 'high':
            recommendations.append("Consider temporarily blocking the suspicious IP address")
            recommendations.append("Run a vulnerability scan to identify potential security gaps")
    
    elif alert_type == 'firewall':
        recommendations.extend([
            "Review firewall logs to understand the reason for the block",
            "Ensure firewall rules are properly configured",
            "Check for persistent connection attempts from blocked IPs"
        ])
    
    elif alert_type == 'security':
        recommendations.extend([
            "Run a full system security scan",
            "Update antivirus/anti-malware definitions",
            "Check system integrity"
        ])
        
        if severity == 'high':
            recommendations.append("Consider isolating the affected system from the network")
            recommendations.append("Perform a thorough analysis of affected files and processes")
    
    elif alert_type == 'system':
        recommendations.extend([
            "Check system resource utilization",
            "Review scheduled tasks and running services",
            "Monitor for resource-intensive processes"
        ])
    
    # Add general recommendations
    recommendations.extend([
        "Document the incident and resolution steps taken",
        "Update security policies if needed"
    ])
    
    return recommendations
