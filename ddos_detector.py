import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from collections import deque, defaultdict
import threading


class DDoSDetector:
    """Real-time DDoS detection using ONLY the trained ML model with temporal smoothing of model probabilities."""

    def __init__(self,
                 model_path='model/best_model.pkl',
                 scaler_path='model/scaler.pkl',
                 alert_threshold=0.7,          # default lowered from 0.9 for practical detection
                 smoothing_window=5,           # how many recent probabilities to average
                 min_history_for_detection=2   # min items required before smoothing considered
                 ):
        print("Loading ML model and scaler...")
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            print("Model and scaler loaded successfully")
        except Exception as e:
            print(f"Error loading model or scaler: {e}")
            raise

        # Detection history (store results)
        self.detections = deque(maxlen=2000)
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

        # Thresholds and smoothing parameters
        self.alert_threshold = alert_threshold
        self.smoothing_window = max(1, smoothing_window)
        self.min_history_for_detection = max(1, min_history_for_detection)

        # Keep per-source and per-destination recent probability history (deques)
        self.prob_history_src = defaultdict(lambda: deque(maxlen=self.smoothing_window))
        self.prob_history_dst = defaultdict(lambda: deque(maxlen=self.smoothing_window))

    def _safe_dataframe(self, features_df):
        """Ensure numeric and no inf/nans (used before scaling)."""
        df = features_df.copy()
        df = df.replace([np.inf, -np.inf], 0)
        df = df.fillna(0)
        # Ensure dtypes are numeric
        for c in df.columns:
            if not np.issubdtype(df[c].dtype, np.number):
                try:
                    df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
                except:
                    df[c] = 0
        return df

    def predict(self, features_df, flow_id, packet_info):
        """
        Make ML-only prediction. Uses moving average of recent probabilities per-src and per-dst
        to reduce noise on short flows (still ML-only).
        """
        try:
            if features_df is None or features_df.empty:
                return None

            df_clean = self._safe_dataframe(features_df)

            # Scale features; protect against scaler errors
            try:
                features_scaled = self.scaler.transform(df_clean)
            except Exception as e:
                print(f"Scaler transform error: {e}. Returning None.")
                return None

            # Get ML model probabilities
            try:
                probs = self.model.predict_proba(features_scaled)[0]
            except Exception as e:
                print(f"Model predict_proba error: {e}. Returning None.")
                return None

            ddos_prob = float(probs[1])  # Probability for DDoS class

            src_ip = packet_info.get('src_ip', 'unknown_src')
            dst_ip = packet_info.get('dst_ip', 'unknown_dst')

            # Update history
            with self.lock:
                self.prob_history_src[src_ip].append(ddos_prob)
                self.prob_history_dst[dst_ip].append(ddos_prob)

                # Moving average (prefer source-based smoothing; fallback to dst)
                avg_src = float(np.mean(self.prob_history_src[src_ip])) if len(self.prob_history_src[src_ip]) >= self.min_history_for_detection else None
                avg_dst = float(np.mean(self.prob_history_dst[dst_ip])) if len(self.prob_history_dst[dst_ip]) >= self.min_history_for_detection else None

            # Decide final probability using available smoothed values
            # Priority: avg_src (if available) -> avg_dst -> instantaneous prob
            if avg_src is not None:
                final_prob = max(ddos_prob, avg_src)
            elif avg_dst is not None:
                final_prob = max(ddos_prob, avg_dst)
            else:
                final_prob = ddos_prob

            final_prediction = 1 if final_prob >= self.alert_threshold else 0

            print(f"Flow {flow_id}: instant_prob={ddos_prob:.3f}, smoothed_prob={final_prob:.3f}, final={final_prediction} ({'DDoS' if final_prediction else 'Benign'})")

            # Build result
            result = {
                'timestamp': datetime.now().isoformat(),
                'flow_id': flow_id,
                'prediction': final_prediction,
                'prediction_label': 'DDoS' if final_prediction == 1 else 'Benign',
                'probability': final_prob,
                'instant_probability': ddos_prob,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': packet_info.get('dst_port', 0),
                'packet_info': packet_info,
                'severity': self._calculate_severity(final_prob)
            }

            # Update stored detections and stats
            with self.lock:
                self.detections.append(result)
                self.stats['total_predictions'] += 1

                if final_prediction == 1:
                    self.stats['ddos_count'] += 1
                    self.stats['last_detection'] = result
                    self._add_active_threat(result)
                else:
                    self.stats['benign_count'] += 1

                if self.stats['total_predictions'] > 0:
                    self.stats['detection_rate'] = (self.stats['ddos_count'] / self.stats['total_predictions'])

            return result

        except Exception as e:
            print(f"Error in prediction: {e}")
            return None

    def _calculate_severity(self, probability):
        if probability < 0.3:
            return 'low'
        elif probability < 0.6:
            return 'medium'
        elif probability < 0.85:
            return 'high'
        else:
            return 'critical'

    def _add_active_threat(self, result):
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

        # Keep recent threats within 5 minutes
        cutoff_seconds = 300
        self.stats['active_threats'] = [
            t for t in self.stats['active_threats']
            if (datetime.now() - datetime.fromisoformat(t['last_seen'])).total_seconds() < cutoff_seconds
        ]

    # ----- helpers to expose info -----
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
        with self.lock:
            cutoff = datetime.now().timestamp() - (minutes * 60)
            timeline = []
            for d in self.detections:
                ts = datetime.fromisoformat(d['timestamp']).timestamp()
                if ts >= cutoff:
                    timeline.append({
                        'timestamp': d['timestamp'],
                        'type': d['prediction_label'],
                        'probability': d['probability']
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
            self.prob_history_src.clear()
            self.prob_history_dst.clear()
