"""
API endpoints for ML-based anomaly detection visualization.
"""
import json
import datetime
from flask import Blueprint, jsonify, request

from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection
from syslogger.ml.anomaly_detection import get_anomaly_detector

# Create Blueprint
anomaly_bp = Blueprint('anomaly', __name__)
logger = get_logger()

@anomaly_bp.route('/api/anomalies/recent', methods=['GET'])
def get_recent_anomalies():
    """Get recent network anomalies."""
    try:
        limit = int(request.args.get('limit', 100))
        detector = get_anomaly_detector()
        anomalies = detector.get_recent_anomalies(limit)
        return jsonify({
            'status': 'success',
            'count': len(anomalies),
            'anomalies': anomalies
        })
    except Exception as e:
        logger.error(f"Error getting recent anomalies: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@anomaly_bp.route('/api/anomalies/stats', methods=['GET'])
def get_anomaly_stats():
    """Get statistics about detected anomalies."""
    try:
        # Time range parameters
        days = int(request.args.get('days', 7))
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.datetime.timedelta(days=days)

        conn = get_db_connection()
        
        # Get total count
        total = conn.execute(
            "SELECT COUNT(*) FROM network_anomalies"
        ).fetchone()[0]
        
        # Get counts by day
        daily_counts = conn.execute("""
            SELECT 
                substr(timestamp, 1, 10) as day,
                COUNT(*) as count
            FROM network_anomalies
            WHERE timestamp >= ?
            GROUP BY day
            ORDER BY day
        """, (start_date.isoformat(),)).fetchall()
        
        # Get top source IPs
        top_sources = conn.execute("""
            SELECT 
                src_ip,
                COUNT(*) as count
            FROM network_anomalies
            WHERE timestamp >= ?
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
        """, (start_date.isoformat(),)).fetchall()
        
        # Get top destination IPs
        top_destinations = conn.execute("""
            SELECT 
                dst_ip,
                COUNT(*) as count
            FROM network_anomalies
            WHERE timestamp >= ?
            GROUP BY dst_ip
            ORDER BY count DESC
            LIMIT 10
        """, (start_date.isoformat(),)).fetchall()
        
        # Get average scores
        avg_score = conn.execute("""
            SELECT 
                AVG(score) as avg_score
            FROM network_anomalies
            WHERE timestamp >= ?
        """, (start_date.isoformat(),)).fetchone()[0] or 0
        
        # Format results
        result = {
            'status': 'success',
            'total_anomalies': total,
            'daily_counts': [{'day': row[0], 'count': row[1]} for row in daily_counts],
            'top_sources': [{'ip': row[0], 'count': row[1]} for row in top_sources],
            'top_destinations': [{'ip': row[0], 'count': row[1]} for row in top_destinations],
            'avg_score': float(avg_score),
            'time_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat(),
                'days': days
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting anomaly stats: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@anomaly_bp.route('/api/anomalies/details/<int:anomaly_id>', methods=['GET'])
def get_anomaly_details(anomaly_id):
    """Get details for a specific anomaly."""
    try:
        conn = get_db_connection()
        anomaly = conn.execute("""
            SELECT 
                id, timestamp, src_ip, dst_ip, score, features
            FROM network_anomalies
            WHERE id = ?
        """, (anomaly_id,)).fetchone()
        
        if not anomaly:
            return jsonify({
                'status': 'error',
                'message': f"Anomaly with ID {anomaly_id} not found"
            }), 404
            
        # Parse features
        features = json.loads(anomaly[5])
        
        result = {
            'status': 'success',
            'anomaly': {
                'id': anomaly[0],
                'timestamp': anomaly[1],
                'src_ip': anomaly[2],
                'dst_ip': anomaly[3],
                'score': float(anomaly[4]),
                'features': features
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting anomaly details: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@anomaly_bp.route('/api/anomalies/search', methods=['GET'])
def search_anomalies():
    """Search anomalies with filters."""
    try:
        # Parse filter parameters
        src_ip = request.args.get('src_ip')
        dst_ip = request.args.get('dst_ip')
        min_score = request.args.get('min_score')
        max_score = request.args.get('max_score')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = "SELECT id, timestamp, src_ip, dst_ip, score FROM network_anomalies WHERE 1=1"
        params = []
        
        if src_ip:
            query += " AND src_ip LIKE ?"
            params.append(f"%{src_ip}%")
            
        if dst_ip:
            query += " AND dst_ip LIKE ?"
            params.append(f"%{dst_ip}%")
            
        if min_score:
            query += " AND score >= ?"
            params.append(float(min_score))
            
        if max_score:
            query += " AND score <= ?"
            params.append(float(max_score))
            
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
            
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
            
        # Add sorting and pagination
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        # Execute query
        conn = get_db_connection()
        rows = conn.execute(query, params).fetchall()
        
        # Count total matches
        count_query = f"SELECT COUNT(*) FROM ({query.split(' LIMIT')[0]})"
        total = conn.execute(count_query, params[:-2]).fetchone()[0]
        
        # Format results
        anomalies = []
        for row in rows:
            anomalies.append({
                'id': row[0],
                'timestamp': row[1],
                'src_ip': row[2],
                'dst_ip': row[3],
                'score': float(row[4])
            })
            
        return jsonify({
            'status': 'success',
            'total': total,
            'limit': limit,
            'offset': offset,
            'anomalies': anomalies
        })
        
    except Exception as e:
        logger.error(f"Error searching anomalies: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
