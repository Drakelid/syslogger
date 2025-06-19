"""
API endpoints for threat intelligence feed management.
"""
import json
import datetime
from flask import Blueprint, jsonify, request

from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection
from syslogger.threat_intel.feeds import get_threat_feed_manager

# Create Blueprint
threat_intel_bp = Blueprint('threat_intel', __name__)
logger = get_logger()

@threat_intel_bp.route('/api/threat_intel/feeds', methods=['GET'])
def get_feeds():
    """Get status of all configured threat intelligence feeds."""
    try:
        manager = get_threat_feed_manager()
        feeds = manager.get_feed_status()
        
        return jsonify({
            'status': 'success',
            'feeds': feeds
        })
    except Exception as e:
        logger.error(f"Error getting feed status: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@threat_intel_bp.route('/api/threat_intel/feeds/<feed_id>/update', methods=['POST'])
def update_feed(feed_id):
    """Manually trigger update of a specific threat intelligence feed."""
    try:
        manager = get_threat_feed_manager()
        
        # Check if feed exists
        if feed_id not in manager.feeds:
            return jsonify({
                'status': 'error',
                'message': f"Feed '{feed_id}' not found"
            }), 404
        
        # Attempt to update the feed
        success = manager.update_feed(feed_id)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f"Successfully updated feed '{feed_id}'"
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f"Failed to update feed '{feed_id}'"
            }), 500
            
    except Exception as e:
        logger.error(f"Error updating feed: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@threat_intel_bp.route('/api/threat_intel/iocs/counts', methods=['GET'])
def get_ioc_counts():
    """Get count of IOCs by type."""
    try:
        manager = get_threat_feed_manager()
        counts = manager.get_ioc_counts()
        
        return jsonify({
            'status': 'success',
            'counts': counts
        })
    except Exception as e:
        logger.error(f"Error getting IOC counts: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@threat_intel_bp.route('/api/threat_intel/iocs/search', methods=['GET'])
def search_iocs():
    """Search for IOCs with filters."""
    try:
        # Parse parameters
        ioc_type = request.args.get('type')
        value = request.args.get('value', '')
        source = request.args.get('source')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = "SELECT ioc_type, ioc_value, source, first_seen, last_seen FROM threat_intel_iocs WHERE 1=1"
        params = []
        
        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)
            
        if value:
            query += " AND ioc_value LIKE ?"
            params.append(f"%{value}%")
            
        if source:
            query += " AND source = ?"
            params.append(source)
            
        # Add sorting and pagination
        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        # Execute query
        conn = get_db_connection()
        rows = conn.execute(query, params).fetchall()
        
        # Count total matches (without pagination)
        count_query = f"SELECT COUNT(*) FROM ({query.split(' LIMIT')[0]})"
        total = conn.execute(count_query, params[:-2]).fetchone()[0]
        
        # Format results
        results = []
        for row in rows:
            results.append({
                'type': row[0],
                'value': row[1],
                'source': row[2],
                'first_seen': row[3],
                'last_seen': row[4]
            })
            
        return jsonify({
            'status': 'success',
            'total': total,
            'limit': limit,
            'offset': offset,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error searching IOCs: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@threat_intel_bp.route('/api/threat_intel/iocs/check', methods=['POST'])
def check_ioc():
    """Check if a value is a known IOC."""
    try:
        data = request.get_json()
        if not data or 'value' not in data:
            return jsonify({
                'status': 'error',
                'message': "Missing required field 'value'"
            }), 400
            
        value = data['value']
        ioc_type = data.get('type')
        
        manager = get_threat_feed_manager()
        is_ioc = manager.check_ioc(value, ioc_type)
        
        result = {
            'status': 'success',
            'value': value,
            'is_ioc': is_ioc
        }
        
        # If it's an IOC, get additional details
        if is_ioc:
            details = manager.get_ioc_details(value, ioc_type)
            if details:
                result['details'] = details
                
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error checking IOC: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@threat_intel_bp.route('/api/threat_intel/config', methods=['GET'])
def get_config():
    """Get threat intelligence configuration settings."""
    try:
        manager = get_threat_feed_manager()
        
        # Extract relevant config settings
        config = {}
        for feed_id, feed in manager.feeds.items():
            config[feed_id] = {
                'name': feed.get('name'),
                'enabled': feed.get('enabled', False),
                'url': feed.get('url', ''),
                'interval': feed.get('interval', 3600),
                'has_api_key': bool(feed.get('api_key'))
            }
            
        return jsonify({
            'status': 'success',
            'config': config
        })
        
    except Exception as e:
        logger.error(f"Error getting config: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@threat_intel_bp.route('/api/threat_intel/config', methods=['PUT'])
def update_config():
    """Update threat intelligence configuration settings."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'status': 'error',
                'message': "No configuration data provided"
            }), 400
            
        manager = get_threat_feed_manager()
        
        # Update feed configurations
        for feed_id, settings in data.items():
            if feed_id in manager.feeds:
                feed = manager.feeds[feed_id]
                
                # Update enabled status if provided
                if 'enabled' in settings:
                    feed['enabled'] = bool(settings['enabled'])
                    
                # Update interval if provided
                if 'interval' in settings:
                    feed['interval'] = int(settings['interval'])
                    
                # Update API key if provided and not empty
                if 'api_key' in settings and settings['api_key']:
                    feed['api_key'] = settings['api_key']
                    
        # TODO: In a real implementation, we would persist these changes
        # to the configuration storage
                    
        return jsonify({
            'status': 'success',
            'message': 'Configuration updated'
        })
        
    except Exception as e:
        logger.error(f"Error updating config: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
