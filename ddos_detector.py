import joblib
import pandas as pd
import numpy as np
from datetime import datetime
import threading
import time
import os
import logging
from collections import deque
from flow_extractor import FlowExtractor 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DDoSDetector:
    def __init__(self, model_path='model/best_model.pkl', scaler_path='model/scaler.pkl', alert_threshold=0.7):  # Adjusted threshold to 0.7 for higher confidence
        self.model = None
        self.scaler = None
        self.alert_threshold = alert_threshold
        self.lock = threading.Lock()
        
        self._load_models(model_path, scaler_path)

        self.extractor = FlowExtractor() 
        self.stats = self._create_initial_stats()
        
        # Optimized deques for history and rate calculation
        self.detection_history = deque(maxlen=3000) 
        self.recent_ddos_times = deque()           
        
        self.threat_timeline = deque(maxlen=60 * 60) 
        self.last_stats_update = time.time()
        
        self.running = True
        self.stats_thread = threading.Thread(target=self._stats_update_loop, daemon=True)
        self.stats_thread.start()

    def _create_initial_stats(self):
        return {
            'total_packets': 0,
            'total_flows': 0,
            'packets_per_second': 0.0,
            'total_predictions': 0,
            'ddos_count': 0,
            'benign_count': 0,
            'alert_status': 'OK',
            'last_ddos_time': None
        }

    def _load_models(self, model_path, scaler_path):
        """Loads the pre-trained ML model and StandardScaler."""
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            logging.error(f"Required model or scaler file missing. Please ensure 'model/best_model.pkl' and 'model/scaler.pkl' exist.")
            raise FileNotFoundError("Missing model or scaler files. Cannot initialize detector.")
            
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            logging.info(f"Successfully loaded model and scaler.")
        except Exception as e:
            logging.error(f"Error loading models: {e}")
            raise

    def predict(self, features_df, flow_id, packet_info):
        """Scales input features and uses the loaded model to predict the class."""
        with self.lock:
            try:
                
                # 1. Prepare data for model: ensure float64 and check non-finite values
                
                # Check for infinite/NaN values using the DataFrame's underlying NumPy array
                if not np.all(np.isfinite(features_df.values)):
                     logging.warning(f"Flow {flow_id} contains non-finite values. Skipping prediction.")
                     return {'is_ddos': False, 'confidence': 0.0, 'flow_id': flow_id, 'reason': 'Non-finite features'}

                # FIX FOR WARNING: Pass the DataFrame directly to the scaler. 
                X_scaled = self.scaler.transform(features_df.astype(np.float64))
                
                # 2. Get model prediction class (0=Benign, 1=DDoS) - for reference only
                model_class = self.model.predict(X_scaled)[0]
                
                # 3. Get confidence (probability of DDoS)
                if hasattr(self.model, 'predict_proba'):
                    # The model expects X_scaled to be an array, which it is.
                    confidence = self.model.predict_proba(X_scaled)[0][1] 
                else:
                    confidence = 1.0 if model_class == 1 else 0.0

                # 4. Determine is_ddos based solely on confidence threshold
                # This allows tuning the sensitivity without relying on the model's internal threshold (usually 0.5)
                # If confidence >= alert_threshold, flag as DDoS. This is more flexible for false positive/negative control.
                is_ddos = confidence >= self.alert_threshold

                # Added logging: Always log prediction result
                logging.info(f"Prediction for flow {flow_id}: is_ddos={is_ddos}, model_class={model_class}, confidence (prob DDoS)={confidence:.4f}")

                # 5. Update stats (Lock is held by this function)
                self._update_stats(is_ddos, confidence, flow_id, packet_info)
                
                return {
                    'is_ddos': is_ddos,
                    'model_class': int(model_class),  # Renamed from 'prediction' to clarify it's the model's raw class
                    'confidence': float(confidence),
                    'flow_id': flow_id,
                    'timestamp': datetime.now().isoformat()
                }

            except ValueError as e:
                logging.warning(f"Prediction failed for flow {flow_id}: Feature mismatch or ValueError: {e}.")
                return {'is_ddos': False, 'confidence': 0.0, 'flow_id': flow_id, 'reason': f'Feature mismatch: {e}'}
            except Exception as e:
                logging.error(f"Prediction failed for flow {flow_id}: General Error: {e}")
                return {'is_ddos': False, 'confidence': 0.0, 'flow_id': flow_id, 'reason': f'General Error: {e}'}

    # === Statistical Update Methods ===
    def _update_stats(self, is_ddos, confidence, flow_id, packet_info):
        """Internal method to update statistics based on a single prediction. Assumes lock is held by caller."""
        current_time = time.time()
        
        self.stats['total_predictions'] += 1
        
        if is_ddos:
            self.stats['ddos_count'] += 1
            self.stats['last_ddos_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Optimization: Add time to the dedicated DDoS rate deque
            self.recent_ddos_times.append(current_time)
        else:
            self.stats['benign_count'] += 1
        
        self.detection_history.append({
            'time': current_time,
            'is_ddos': is_ddos,
            'confidence': confidence,
            'src_ip': packet_info.get('src_ip', 'N/A'),
            'dst_ip': packet_info.get('dst_ip', 'N/A'),
            'flow_id': flow_id,
            'size': packet_info.get('size', 0)
        })

    def _stats_update_loop(self):
        """Threaded loop to update time-based stats."""
        while self.running:
            time.sleep(1) 
            self.extractor.cleanup_old_flows()
            self._update_time_based_stats()

    def _update_time_based_stats(self):
        """Calculate packets per second and update overall alert status."""
        current_time = time.time()
        time_diff = current_time - self.last_stats_update
        
        current_packets = self.extractor.get_total_packets_seen()
        
        with self.lock:
            if time_diff > 0:
                packets_since_last_update = current_packets - self.stats['total_packets']
                self.stats['packets_per_second'] = packets_since_last_update / time_diff
                self.stats['total_packets'] = current_packets
                self.stats['total_flows'] = len(self.extractor.flows)
            
            self.last_stats_update = current_time
            
            # Simplified Alert Status based on PPS
            if self.stats['packets_per_second'] > 500:
                self.stats['alert_status'] = 'HIGH TRAFFIC'
            elif self.stats['packets_per_second'] > 100:
                self.stats['alert_status'] = 'ELEVATED'
            else:
                self.stats['alert_status'] = 'OK'

            # Optimized DDoS Rate Calculation
            ddos_rate_window = 10 
            
            # Remove timestamps older than the window from the front of the deque (O(1) amortized)
            while self.recent_ddos_times and self.recent_ddos_times[0] < current_time - ddos_rate_window:
                self.recent_ddos_times.popleft()
                
            ddos_rate = len(self.recent_ddos_times) / ddos_rate_window
            
            self.threat_timeline.append({
                'time': current_time, 
                'rate': ddos_rate,
                'total_pps': self.stats['packets_per_second']
            })
            
            if self.stats['total_predictions'] > 0 and self.stats['total_predictions'] % 5 == 0:
                logging.info(f"📊 PPS: {self.stats['packets_per_second']:.2f}, DDoS Rate (10s): {ddos_rate:.2f}, Total Detections: {self.stats['total_predictions']}, DDoS: {self.stats['ddos_count']}, Alert: {self.stats['alert_status']}")


    def get_stats(self):
        """Get current statistics (Used by dashboard)."""
        with self.lock:
            return self.stats.copy()

    def get_recent_detections(self, n=20):
        """Get the most recent N detection records (Used by dashboard)."""
        with self.lock:
            return list(reversed(list(self.detection_history)))[:n]
            
    def get_timeline_data(self):
        """Get timeline data for plotting (Used by dashboard)."""
        with self.lock:
            return list(self.threat_timeline)

    def stop(self):
        """Cleanly stop the internal threads."""
        self.running = False
        self.stats_thread.join()
        logging.info("DDoSDetector stopped.")