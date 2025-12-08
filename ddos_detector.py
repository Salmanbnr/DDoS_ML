import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from collections import deque
import threading
import json

class DDoSDetector:
    """Real-time DDoS detection using trained ML model with custom thresholds"""
    
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
        
        # Alert threshold updated to 80% as requested
        self.alert_threshold = 0.8  
    
    def predict(self, features_df, flow_id, packet_info):
        """Make prediction on network flow using 80% threshold"""
        try:
            if features_df is None or features_df.empty:
                return None
            
            # Handle any remaining NaN or inf values
            features_df = features_df.replace([np.inf, -np.inf], 0)
            features_df = features_df.fillna(0)
            
            # Scale features
            features_scaled = self.scaler.transform(features_df)
            
            # Get probabilities instead of raw labels
            probability = self.model.predict_proba(features_scaled)[0]
            ddos_prob = float(probability[1])  # Probability of DDoS class 
            
            # CUSTOM LOGIC: Classify as DDoS only if probability >= 80%
            custom_prediction = 1 if ddos_prob >= self.alert_threshold else 0
            
            # Store detection result
            result = {
                'timestamp': datetime.now().isoformat(),
                'flow_id': flow_id,
                'prediction': custom_prediction,
                'prediction_label': 'DDoS' if custom_prediction == 1 else 'Benign',
                'probability': ddos_prob, 
                'src_ip': packet_info.get('src_ip', 'Unknown'),
                'dst_ip': packet_info.get('dst_ip', 'Unknown'),
                'severity': self._calculate_severity(ddos_prob)
            }
            
            with self.lock:
                self.detections.append(result)
                self.stats['total_predictions'] += 1
                
                if custom_prediction == 1:
                    self.stats['ddos_count'] += 1
                    self.stats['last_detection'] = result
                    self._add_active_threat(result)
                else:
                    self.stats['benign_count'] += 1
                
                # Update detection rate based on custom classification
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
        elif probability < 0.6:
            return 'medium'
        elif probability < 0.85:
            return 'high'
        else:
            return 'critical'
    
    def _add_active_threat(self, result):
        """Add or update active threat"""
        src_ip = result['src_ip']
        threat_exists = False
        
        for threat in self.stats['active_threats']:
            if threat['src_ip'] == src_ip:
                threat['count'] += 1
                threat['last_seen'] = result['timestamp']
                threat['max_probability'] = max(threat['max_probability'], result['probability'])
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
        
        # Keep recent threats (last 5 mins)
        self.stats['active_threats'] = [
            t for t in self.stats['active_threats']
            if (datetime.now() - datetime.fromisoformat(t['last_seen'])).total_seconds() < 300
        ]
    
    def get_recent_detections(self, n=20):
        with self.lock:
            return list(self.detections)[-n:]
    
    def get_stats(self):
        with self.lock:
            return self.stats.copy()
    
    def get_active_threats(self):
        with self.lock:
            return self.stats['active_threats'].copy()
    
    def get_timeline_data(self, minutes=10):
        """Get timeline data for charts"""
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
