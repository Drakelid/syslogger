"""
Main Flask web application for SysLogger
"""
import os
from flask import Flask, render_template, redirect, url_for
from flask_socketio import SocketIO

from syslogger.core.logger import get_logger
from syslogger.config.config import get_config
# Temporarily bypassing maintenance scheduler until 'schedule' package issue is resolved
# from syslogger.core.maintenance import start_maintenance_scheduler

# Import API blueprints
# These are the only blueprint modules available in our modular codebase
from syslogger.web.network_api import network_api
from syslogger.web.anomaly_api import anomaly_bp
from syslogger.web.threat_intel_api import threat_intel_bp
from syslogger.web.maintenance_api import maintenance_bp
from syslogger.web.logs_api import logs_bp
from syslogger.web.alerts_api import alerts_bp

logger = get_logger()

def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    config = get_config()
    
    # Set up app config
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev_key_for_testing_only'),
        DEBUG=config.get('web', {}).get('debug', False)
    )
    
    # Register only available blueprints
    app.register_blueprint(network_api)
    app.register_blueprint(anomaly_bp)
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(maintenance_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(alerts_bp)
    
    # Set up Socket.IO for real-time updates
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    # Temporarily bypassing maintenance scheduler until 'schedule' package issue is resolved
    # if config.get('maintenance', {}).get('enabled', True):
    #     start_maintenance_scheduler()
    
    # Main routes
    @app.route('/')
    def index():
        """Render the main dashboard."""
        return render_template('dashboard.html')
        
    @app.route('/logs')
    def logs():
        """Render the logs view."""
        return render_template('logs.html')
        
    @app.route('/alerts')
    def alerts():
        """Render the alerts view."""
        return render_template('alerts.html')
        
    @app.route('/network')
    def network():
        """Render the network traffic view."""
        return render_template('network.html')
        
    @app.route('/anomalies')
    def anomalies():
        """Render the ML anomaly detection dashboard."""
        return render_template('anomaly_dashboard.html')
        
    @app.route('/threat-intel')
    def threat_intel():
        """Render the threat intelligence admin panel."""
        return render_template('threat_intel_admin.html')
        
    @app.route('/maintenance')
    def maintenance():
        """Render the database maintenance admin panel."""
        return render_template('maintenance_admin.html')
    
    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    return app, socketio

def run_app():
    """Run the Flask application."""
    app, socketio = create_app()
    
    # Get web server configuration
    config = get_config()
    web_config = config.get('web', {})
    host = web_config.get('host', '0.0.0.0')
    # Use WEB_PORT from environment variable or fall back to config/default
    port = int(os.environ.get('WEB_PORT', web_config.get('port', 5000)))
    
    logger.info(f"Starting web server on {host}:{port}")
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)
    
if __name__ == '__main__':
    run_app()
