"""
API endpoints for database maintenance operations.
"""
from flask import Blueprint, jsonify, request

from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection
from syslogger.core.maintenance import run_immediate_maintenance, load_retention_config, get_table_statistics

# Create Blueprint
maintenance_bp = Blueprint('maintenance', __name__)
logger = get_logger()

@maintenance_bp.route('/api/maintenance/run', methods=['POST'])
def trigger_maintenance():
    """Manually trigger maintenance tasks."""
    try:
        # Run maintenance tasks
        results = run_immediate_maintenance()
        
        return jsonify({
            'status': 'success',
            'results': results
        })
    except Exception as e:
        logger.error(f"Error running maintenance tasks: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@maintenance_bp.route('/api/maintenance/retention/config', methods=['GET'])
def get_retention_config():
    """Get current data retention configuration."""
    try:
        config = load_retention_config()
        return jsonify({
            'status': 'success',
            'config': config
        })
    except Exception as e:
        logger.error(f"Error getting retention config: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@maintenance_bp.route('/api/maintenance/stats', methods=['GET'])
def get_stats():
    """Get database statistics."""
    try:
        stats = get_table_statistics()
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
    except Exception as e:
        logger.error(f"Error getting database statistics: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
