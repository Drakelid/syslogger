"""
Enhanced web dashboard for SysLogger with real-time updates.
"""
import os
import logging
import json
import datetime
from typing import List, Dict, Any, Optional

from flask import Flask, render_template_string, request, jsonify, Response
from flask_socketio import SocketIO, emit

from syslogger.config.config import get_config
from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection, get_recent_logs, get_all_attackers
from syslogger.security.correlation import get_correlation_engine

# Initialize Flask application
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
logger = get_logger()
config = get_config()

# Store custom alert rules
custom_alert_rules = []

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/logs')
def logs():
    """Log viewer page."""
    return render_template_string(LOGS_TEMPLATE)

@app.route('/attackers')
def attackers():
    """Attackers page."""
    return render_template_string(ATTACKERS_TEMPLATE)

@app.route('/alerts')
def alerts():
    """Alerts configuration page."""
    return render_template_string(ALERTS_TEMPLATE)

@app.route('/api/logs')
def api_logs():
    """API endpoint to get recent logs."""
    limit = request.args.get('limit', default=100, type=int)
    offset = request.args.get('offset', default=0, type=int)
    filter_terms = request.args.get('filter', default='', type=str).split(',')
    
    # Remove empty strings from filter terms
    filter_terms = [term for term in filter_terms if term]
    
    try:
        logs = get_recent_logs(limit + offset, filter_terms)
        if offset > 0:
            logs = logs[offset:]
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        logger.error(f"Error retrieving logs: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/attackers')
def api_attackers():
    """API endpoint to get attacker information."""
    limit = request.args.get('limit', default=100, type=int)
    
    try:
        attackers = get_all_attackers(limit)
        return jsonify({
            'status': 'success',
            'attackers': attackers,
            'count': len(attackers)
        })
    except Exception as e:
        logger.error(f"Error retrieving attackers: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/attack-chains')
def api_attack_chains():
    """API endpoint to get attack chains."""
    host = request.args.get('host', default=None, type=str)
    
    try:
        correlation_engine = get_correlation_engine()
        
        if host:
            attack_chain = correlation_engine.get_attack_chain(host)
            return jsonify({
                'status': 'success',
                'host': host,
                'attack_chain': attack_chain
            })
        else:
            attack_chains = correlation_engine.get_all_attack_chains()
            return jsonify({
                'status': 'success',
                'attack_chains': attack_chains
            })
    except Exception as e:
        logger.error(f"Error retrieving attack chains: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/alert-rules', methods=['GET'])
def get_alert_rules():
    """Get custom alert rules."""
    return jsonify({
        'status': 'success',
        'rules': custom_alert_rules
    })

@app.route('/api/alert-rules', methods=['POST'])
def add_alert_rule():
    """Add a custom alert rule."""
    try:
        rule = request.json
        
        # Validate rule
        if not rule.get('name') or not rule.get('pattern'):
            return jsonify({
                'status': 'error',
                'message': 'Rule must have a name and pattern'
            }), 400
        
        # Add rule ID if not provided
        if not rule.get('id'):
            rule['id'] = f"rule_{len(custom_alert_rules) + 1}"
        
        # Set default values if not provided
        rule.setdefault('severity', 'medium')
        rule.setdefault('enabled', True)
        rule.setdefault('description', '')
        
        custom_alert_rules.append(rule)
        
        return jsonify({
            'status': 'success',
            'rule': rule
        })
    except Exception as e:
        logger.error(f"Error adding alert rule: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/alert-rules/<rule_id>', methods=['PUT'])
def update_alert_rule(rule_id):
    """Update a custom alert rule."""
    try:
        rule = request.json
        
        for i, existing_rule in enumerate(custom_alert_rules):
            if existing_rule['id'] == rule_id:
                custom_alert_rules[i].update(rule)
                return jsonify({
                    'status': 'success',
                    'rule': custom_alert_rules[i]
                })
        
        return jsonify({
            'status': 'error',
            'message': f'Rule with ID {rule_id} not found'
        }), 404
    except Exception as e:
        logger.error(f"Error updating alert rule: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/alert-rules/<rule_id>', methods=['DELETE'])
def delete_alert_rule(rule_id):
    """Delete a custom alert rule."""
    try:
        for i, rule in enumerate(custom_alert_rules):
            if rule['id'] == rule_id:
                del custom_alert_rules[i]
                return jsonify({
                    'status': 'success'
                })
        
        return jsonify({
            'status': 'error',
            'message': f'Rule with ID {rule_id} not found'
        }), 404
    except Exception as e:
        logger.error(f"Error deleting alert rule: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Socket.IO event handlers for real-time updates
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    logger.debug(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    logger.debug(f"Client disconnected: {request.sid}")

@socketio.on('subscribe')
def handle_subscribe(data):
    """Handle subscription to real-time updates."""
    channel = data.get('channel')
    if channel:
        logger.debug(f"Client {request.sid} subscribed to {channel}")

def emit_new_log(log_data):
    """Emit a new log entry to connected clients."""
    socketio.emit('new_log', log_data, namespace='/')

def emit_new_alert(alert_data):
    """Emit a new alert to connected clients."""
    socketio.emit('new_alert', alert_data, namespace='/')

def emit_attack_chain_update(attack_chain_data):
    """Emit attack chain updates to connected clients."""
    socketio.emit('attack_chain_update', attack_chain_data, namespace='/')

# Export functions to be used by other modules
__all__ = ['app', 'socketio', 'emit_new_log', 'emit_new_alert', 'emit_attack_chain_update']
