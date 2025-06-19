"""
Machine learning module for network traffic anomaly detection.
"""
import os
import time
import datetime
import logging
import numpy as np
import pandas as pd
import threading
from typing import Dict, List, Any, Optional, Tuple, Union
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

from syslogger.config.config import get_config
from syslogger.core.logger import get_logger
from syslogger.core.database import get_db_connection
from syslogger.network.analyzer import get_network_analyzer

class NetworkAnomalyDetector:
    """
    Machine learning-based network traffic anomaly detector using Isolation Forest.
    """
    def __init__(self):
        """Initialize the network anomaly detector."""
        self.logger = get_logger()
        self.config = get_config()
        
        # Load or create model
        self.model = None
        self.scaler = None
        self.model_path = os.path.join(
            self.config.get('storage.model_dir', '/logs/models'),
            'network_anomaly_model.joblib'
        )
        self.scaler_path = os.path.join(
            self.config.get('storage.model_dir', '/logs/models'),
            'network_anomaly_scaler.joblib'
        )
        
        # Create the model directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Features for anomaly detection
        self.features = [
            'packets', 'bytes', 'duration', 'packets_per_second', 
            'bytes_per_packet', 'unique_ports', 'unique_ips'
        ]
        
        # Data storage for training
        self.training_data = []
        self.anomalies = []
        self.baseline_established = False
        
        # Initialize model
        self._load_or_create_model()
        
        # Set up the detection thread if enabled
        if self.config.get('ml.enable_anomaly_detection', True):
            self._start_detection_thread()
            
    def _load_or_create_model(self):
        """Load existing model or create a new one if not found."""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.logger.info(f"Loading existing anomaly detection model from {self.model_path}")
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.baseline_established = True
            else:
                self.logger.info("Creating new anomaly detection model")
                # Initialize with default parameters
                self.model = IsolationForest(
                    n_estimators=100,  # Number of trees
                    max_samples='auto',  # Maximum samples to draw
                    contamination=0.05,  # Expected proportion of outliers
                    random_state=42  # For reproducibility
                )
                self.scaler = StandardScaler()
                self.baseline_established = False
        except Exception as e:
            self.logger.error(f"Error loading or creating model: {e}")
            # Create a new model as fallback
            self.model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.05,
                random_state=42
            )
            self.scaler = StandardScaler()
            self.baseline_established = False
            
    def _save_model(self):
        """Save the current model to disk."""
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            self.logger.info(f"Saved anomaly detection model to {self.model_path}")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            
    def _extract_features(self, flows):
        """Extract features from network flows for anomaly detection.
        
        Args:
            flows: List of network flow dictionaries
            
        Returns:
            DataFrame: Features for anomaly detection
        """
        if not flows:
            return pd.DataFrame(columns=self.features)
            
        df_list = []
        
        # Group flows by source-destination pair
        flow_groups = {}
        for flow in flows:
            key = f"{flow['src_ip']}:{flow['dst_ip']}"
            if key not in flow_groups:
                flow_groups[key] = []
            flow_groups[key].append(flow)
            
        for key, group in flow_groups.items():
            src_ip, dst_ip = key.split(':')
            
            # Extract basic features
            total_packets = sum(flow['packets'] for flow in group)
            total_bytes = sum(flow['bytes'] for flow in group)
            
            # Calculate time-based features
            timestamps = [datetime.datetime.fromisoformat(flow['timestamp']) for flow in group]
            if len(timestamps) > 1:
                duration = (max(timestamps) - min(timestamps)).total_seconds()
                if duration == 0:
                    duration = 0.1  # Avoid division by zero
            else:
                duration = 0.1  # Default for single flow
                
            packets_per_second = total_packets / duration
            
            # Calculate statistical features
            bytes_per_packet = total_bytes / total_packets if total_packets > 0 else 0
            
            # Calculate diversity features
            unique_ports = len(set(flow['dst_port'] for flow in group))
            
            # Find unique IPs communicated with
            unique_ips = len(set(flow['dst_ip'] for flow in group))
            
            # Create a feature dictionary
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'packets': total_packets,
                'bytes': total_bytes,
                'duration': duration,
                'packets_per_second': packets_per_second,
                'bytes_per_packet': bytes_per_packet,
                'unique_ports': unique_ports,
                'unique_ips': unique_ips
            }
            
            df_list.append(features)
            
        # Convert to DataFrame
        df = pd.DataFrame(df_list)
        
        return df
        
    def train_model(self, flows=None):
        """Train the anomaly detection model on network flows.
        
        Args:
            flows: Optional list of flows to train on. If None, recent flows are used.
        """
        try:
            # Get flows if not provided
            if flows is None:
                self.logger.info("Getting recent flows for training")
                network_analyzer = get_network_analyzer()
                flows = network_analyzer.get_recent_flows(limit=1000)
                
            if not flows:
                self.logger.warning("No flows available for training")
                return False
                
            # Extract features
            self.logger.info(f"Extracting features from {len(flows)} flows")
            df = self._extract_features(flows)
            
            if len(df) < 10:
                self.logger.warning("Not enough samples to train model")
                return False
                
            # Save original identifiers
            id_cols = df[['src_ip', 'dst_ip']].copy() if 'src_ip' in df.columns else None
            
            # Get feature matrix
            X = df[self.features].fillna(0)
            
            # Scale the features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model
            self.logger.info("Training anomaly detection model")
            self.model.fit(X_scaled)
            
            # Save the model
            self._save_model()
            
            self.baseline_established = True
            self.logger.info("Successfully trained anomaly detection model")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            return False
            
    def detect_anomalies(self, flows):
        """Detect anomalies in network flows.
        
        Args:
            flows: List of network flows to analyze
            
        Returns:
            list: Detected anomalies with scores
        """
        if not self.baseline_established:
            self.logger.warning("No baseline established yet, training model first")
            if not self.train_model(flows):
                return []
                
        try:
            # Extract features
            df = self._extract_features(flows)
            
            if len(df) == 0:
                return []
                
            # Save original identifiers
            id_cols = df[['src_ip', 'dst_ip']].copy()
            
            # Get feature matrix
            X = df[self.features].fillna(0)
            
            # Scale the features
            X_scaled = self.scaler.transform(X)
            
            # Predict anomalies
            scores = self.model.decision_function(X_scaled)
            predictions = self.model.predict(X_scaled)
            
            # Prepare results
            results = []
            for i in range(len(df)):
                # Isolation Forest returns -1 for outliers and 1 for inliers
                if predictions[i] == -1:
                    anomaly = {
                        'src_ip': id_cols.iloc[i]['src_ip'],
                        'dst_ip': id_cols.iloc[i]['dst_ip'],
                        'score': float(scores[i]),  # Lower scores indicate stronger anomalies
                        'features': {feature: float(df.iloc[i][feature]) for feature in self.features}
                    }
                    results.append(anomaly)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error detecting anomalies: {e}")
            return []
            
    def _start_detection_thread(self):
        """Start background thread for anomaly detection."""
        detection_interval = self.config.get('ml.detection_interval_seconds', 300)
        
        def run_detection():
            self.logger.info(f"Starting anomaly detection thread with interval {detection_interval} seconds")
            
            # Initial delay to allow system to collect some data
            time.sleep(60)
            
            # Train initial model
            if not self.baseline_established:
                self.train_model()
            
            while True:
                try:
                    # Get recent flows
                    network_analyzer = get_network_analyzer()
                    flows = network_analyzer.get_recent_flows(limit=100)
                    
                    if flows:
                        # Detect anomalies
                        anomalies = self.detect_anomalies(flows)
                        
                        # Store and report anomalies
                        if anomalies:
                            self.logger.info(f"Detected {len(anomalies)} network anomalies")
                            self._store_anomalies(anomalies)
                            self._report_anomalies(anomalies)
                    
                    # Retrain model periodically
                    retraining_hours = self.config.get('ml.retraining_hours', 24)
                    should_retrain = self.config.get('ml.enable_retraining', True) and \
                                     (not hasattr(self, 'last_training_time') or \
                                      (datetime.datetime.now() - self.last_training_time).total_seconds() > retraining_hours * 3600)
                    
                    if should_retrain:
                        self.logger.info("Retraining anomaly detection model with recent data")
                        larger_dataset = network_analyzer.get_recent_flows(limit=5000)
                        if larger_dataset:
                            self.train_model(larger_dataset)
                            self.last_training_time = datetime.datetime.now()
                            
                except Exception as e:
                    self.logger.error(f"Error in anomaly detection thread: {e}")
                
                # Sleep until next detection cycle
                time.sleep(detection_interval)
        
        # Start the thread
        thread = threading.Thread(target=run_detection, daemon=True)
        thread.start()
        
    def _store_anomalies(self, anomalies):
        """Store detected anomalies in the database.
        
        Args:
            anomalies: List of anomaly dictionaries
        """
        try:
            conn = get_db_connection()
            
            # Create table if it doesn't exist
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    score REAL,
                    features TEXT
                )
            """)
            
            # Insert anomalies
            for anomaly in anomalies:
                conn.execute("""
                    INSERT INTO network_anomalies
                    (timestamp, src_ip, dst_ip, score, features)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    datetime.datetime.now().isoformat(),
                    anomaly['src_ip'],
                    anomaly['dst_ip'],
                    anomaly['score'],
                    json.dumps(anomaly['features'])
                ))
                
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Error storing anomalies: {e}")
            
    def _report_anomalies(self, anomalies):
        """Report anomalies for alerting.
        
        Args:
            anomalies: List of anomaly dictionaries
        """
        try:
            # In a real implementation, this would integrate with an alerting system
            # For now, we'll just log the anomalies
            for anomaly in anomalies:
                self.logger.warning(
                    f"Network anomaly detected: {anomaly['src_ip']} -> {anomaly['dst_ip']} "
                    f"(score: {anomaly['score']:.4f})"
                )
                
            # Store in memory for API access
            self.anomalies.extend(anomalies)
            
            # Trim to keep only recent anomalies
            max_anomalies = self.config.get('ml.max_stored_anomalies', 1000)
            if len(self.anomalies) > max_anomalies:
                self.anomalies = self.anomalies[-max_anomalies:]
                
        except Exception as e:
            self.logger.error(f"Error reporting anomalies: {e}")
            
    def get_recent_anomalies(self, limit=100):
        """Get recent anomalies for API access.
        
        Args:
            limit: Maximum number of anomalies to return
            
        Returns:
            list: Recent anomalies
        """
        try:
            # Return most recent anomalies up to the limit
            return self.anomalies[-limit:] if self.anomalies else []
            
        except Exception as e:
            self.logger.error(f"Error getting recent anomalies: {e}")
            return []

# Singleton instance
_anomaly_detector = None

def get_anomaly_detector():
    """Get the singleton anomaly detector instance.
    
    Returns:
        NetworkAnomalyDetector: Singleton instance
    """
    global _anomaly_detector
    
    if _anomaly_detector is None:
        _anomaly_detector = NetworkAnomalyDetector()
        
    return _anomaly_detector
