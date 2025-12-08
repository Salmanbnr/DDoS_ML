import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from collections import deque
import threading
import json

class DDoSDetector:
    """Real-time DDoS detection using trained ML model"""
    
    def __init__(self, model_path='model/best_model.pkl', scaler_path='model/scaler.pkl'):
        print("Loading ML model and scaler...")
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            print("Model and scaler loaded successfully")
        except Exception as e:
            print(f"Error loading model: {e}")
            raise
        
        # Detection history
        self.detections = deque(maxlen=1000)
        self.lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_predictions': 0,
            'benign_count': 0,
            'ddos_count': 0,
            'detection_rate': 0.0,
            'last_detection': None,
            'active_threats': []
        }
        
        # Alert threshold
        self.alert_threshold = 0.7  # 70% probability for alert
    
    def predict(self, features_df, flow_id, packet_info):
        """Make prediction on network flow"""
        try:
            # Ensure features are in correct order
            if features_df is None or features_df.empty:
                return None
            
            # Debug: Print first prediction
            if self.stats['total_predictions'] == 0:
                print(f"\n[DEBUG] First prediction attempt:")
                print(f"  - Features shape: {features_df.shape}")
                print(f"  - Flow ID: {flow_id}")
            
            # Handle any remaining NaN or inf values
            features_df = features_df.replace([np.inf, -np.inf], 0)
            features_df = features_df.fillna(0)
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Make prediction
            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0]
            
            # Debug: Print first few predictions
            if self.stats['total_predictions'] < 5:
                print(f"  - Prediction: {prediction} ({'DDoS' if prediction == 1 else 'Benign'})")
                print(f"  - Probability: {probability[1]:.2%}")
            
            # Store detection result
            result = {
                'timestamp': datetime.now().isoformat(),
                'flow_id': flow_id,
                'prediction': int(prediction),
                'prediction_label': 'DDoS' if prediction == 1 else 'Benign',
                'probability': float(probability[1]),  # Probability of DDoS
                'src_ip': packet_info.get('src_ip', 'Unknown'),
                'dst_ip': packet_info.get('dst_ip', 'Unknown'),
                'severity': self._calculate_severity(probability[1])
            }
            
            with self.lock:
                self.detections.append(result)
                self.stats['total_predictions'] += 1
                
                if prediction == 1:
                    self.stats['ddos_count'] += 1
                    self.stats['last_detection'] = result
                    
                    # Add to active threats if high confidence
                    if probability[1] >= self.alert_threshold:
                        self._add_active_threat(result)
                else:
                    self.stats['benign_count'] += 1
                
                # Update detection rate
                if self.stats['total_predictions'] > 0:
                    self.stats['detection_rate'] = (
                        self.stats['ddos_count'] / self.stats['total_predictions']
                    )
            
            return result
            
        except Exception as e:
            print(f"Error in prediction: {e}")
            return None
    
    def _calculate_severity(self, probability):
        """Calculate threat severity based on probability"""
        if probability < 0.3:
            return 'low'
        elif probability < 0.7:
            return 'medium'
        elif probability < 0.9:
            return 'high'
        else:
            return 'critical'
    
    def _add_active_threat(self, result):
        """Add or update active threat"""
        src_ip = result['src_ip']
        
        # Check if threat already exists
        threat_exists = False
        for threat in self.stats['active_threats']:
            if threat['src_ip'] == src_ip:
                threat['count'] += 1
                threat['last_seen'] = result['timestamp']
                threat['max_probability'] = max(
                    threat['max_probability'], 
                    result['probability']
                )
                threat_exists = True
                break
        
        if not threat_exists:
            self.stats['active_threats'].append({
                'src_ip': src_ip,
                'dst_ip': result['dst_ip'],
                'flow_id': result['flow_id'],
                'first_seen': result['timestamp'],
                'last_seen': result['timestamp'],
                'count': 1,
                'max_probability': result['probability'],
                'severity': result['severity']
            })
        
        # Keep only recent threats (last 5 minutes)
        self.stats['active_threats'] = [
            t for t in self.stats['active_threats']
            if (datetime.now() - datetime.fromisoformat(t['last_seen'])).total_seconds() < 300
        ]
    
    def get_recent_detections(self, n=20):
        """Get recent detections"""
        with self.lock:
            return list(self.detections)[-n:]
    
    def get_stats(self):
        """Get detection statistics"""
        with self.lock:
            return self.stats.copy()
    
    def get_active_threats(self):
        """Get currently active threats"""
        with self.lock:
            return self.stats['active_threats'].copy()
    
    def get_timeline_data(self, minutes=10):
        """Get detection timeline data for charts"""
        with self.lock:
            cutoff_time = datetime.now().timestamp() - (minutes * 60)
            
            timeline = []
            for detection in self.detections:
                det_time = datetime.fromisoformat(detection['timestamp']).timestamp()
                if det_time >= cutoff_time:
                    timeline.append({
                        'timestamp': detection['timestamp'],
                        'type': detection['prediction_label'],
                        'probability': detection['probability']
                    })
            
            return timeline
    
    def reset_stats(self):
        """Reset statistics"""
        with self.lock:
            self.stats = {
                'total_predictions': 0,
                'benign_count': 0,
                'ddos_count': 0,
                'detection_rate': 0.0,
                'last_detection': None,
                'active_threats': []
            }
            self.detections.clear()