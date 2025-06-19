"""
Network traffic analysis API endpoints for the SysLogger web interface.
"""
import logging
from flask import Blueprint, jsonify, request

from syslogger.network.analyzer import get_network_analyzer
from syslogger.core.logger import get_logger

# Create a Blueprint for network API routes
network_api = Blueprint('network_api', __name__)
logger = get_logger()

@network_api.route('/api/network/stats', methods=['GET'])
def get_network_stats():
    """Get current network statistics."""
    try:
        analyzer = get_network_analyzer()
        stats = analyzer.get_packet_stats()
        
        return jsonify({
            'status': 'success',
            'stats': stats
        })
    except Exception as e:
        logger.error(f"Error retrieving network stats: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@network_api.route('/api/network/flows', methods=['GET'])
def get_network_flows():
    """Get recent network flows."""
    try:
        limit = request.args.get('limit', default=100, type=int)
        
        analyzer = get_network_analyzer()
        flows = analyzer.get_recent_flows(limit)
        
        return jsonify({
            'status': 'success',
            'flows': flows,
            'count': len(flows)
        })
    except Exception as e:
        logger.error(f"Error retrieving network flows: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@network_api.route('/api/network/graph', methods=['GET'])
def get_network_graph():
    """Get network flow graph data for visualization."""
    try:
        analyzer = get_network_analyzer()
        graph_data = analyzer.get_flow_data()
        
        return jsonify({
            'status': 'success',
            'graph': graph_data
        })
    except Exception as e:
        logger.error(f"Error retrieving network graph data: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def register_network_api(app):
    """
    Register network API Blueprint with the Flask application.
    
    Args:
        app: Flask application instance
    """
    app.register_blueprint(network_api)
