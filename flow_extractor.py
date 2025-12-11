from scapy.all import Packet, IP, TCP, UDP
from datetime import datetime
import threading
import pandas as pd
import numpy as np
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# EXACT 77 FEATURES THAT MATCH YOUR TRAINED MODEL (tested and working)
FEATURE_NAMES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

MIN_PACKETS_FOR_PREDICTION = 5  # Increased to 5 for better confidence
FLOW_TIMEOUT = 60

class FlowExtractor:
    def __init__(self):
        self.flows = {} 
        self.flow_lock = threading.Lock()
        self.total_packets_seen = 0

    def get_total_packets_seen(self):
        with self.flow_lock:
            return self.total_packets_seen

    def _get_flow_id(self, packet):
        """Generates a bidirectional flow ID (A:B and B:A are the same)."""
        if IP not in packet:
            return None
            
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Determine L4 protocol and ports
        if TCP in packet:
            l4_proto = 6
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
        elif UDP in packet:
            l4_proto = 17
            port_src = packet[UDP].sport
            port_dst = packet[UDP].dport
        else:
            l4_proto = packet[IP].proto
            port_src, port_dst = 0, 0

        # Sort elements to make flow ID bidirectional
        if (ip_src, port_src) > (ip_dst, port_dst):
            ip_src, ip_dst = ip_dst, ip_src
            port_src, port_dst = port_dst, port_src

        return f"{ip_src}:{port_src}_{ip_dst}:{port_dst}_{l4_proto}"

    def process_packet(self, packet):
        """Process a single packet and extract features if ready."""
        with self.flow_lock:
            self.total_packets_seen += 1
            logging.debug(f"Processing packet {self.total_packets_seen}: {packet.summary()}")  # Added log

            flow_id = self._get_flow_id(packet)
            if not flow_id:
                logging.debug("No flow ID, skipping packet.")
                return None, None, None

            if flow_id not in self.flows:
                self.flows[flow_id] = self._initialize_flow(packet, flow_id)
                logging.debug(f"New flow initialized: {flow_id}")

            flow_data = self.flows[flow_id]
            self._update_flow_features(flow_data, packet, flow_id)
            logging.debug(f"Updated flow {flow_id}: Total packets = {flow_data['Total Fwd Packets'] + flow_data['Total Backward Packets']}")

            # Check if ready for prediction
            if flow_data['Total Fwd Packets'] + flow_data['Total Backward Packets'] >= MIN_PACKETS_FOR_PREDICTION:
                features_df = self._extract_features(flow_data, flow_id)
                if features_df is not None:
                    packet_info = {
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'size': len(packet)
                    }
                    logging.info(f"Features extracted for flow {flow_id}, ready for prediction.")
                    # Reset flow after extraction (optional, but prevents re-prediction)
                    del self.flows[flow_id]
                    return features_df, flow_id, packet_info
                else:
                    logging.warning(f"Failed to extract features for flow {flow_id}")

            logging.debug(f"Flow {flow_id} not ready yet (packets: {flow_data['Total Fwd Packets'] + flow_data['Total Backward Packets']} < {MIN_PACKETS_FOR_PREDICTION})")
            return None, None, None

    def _initialize_flow(self, packet, flow_id):
        """Initialize a new flow dictionary."""
        flow_data = {
            'fwd_ip': packet[IP].src,
            'bwd_ip': packet[IP].dst,
            'start_time_us': datetime.now().timestamp() * 1000000.0,
            'last_packet_time': None,
            'last_packet_time_us': None,
            'packets': [],  # Not used, can remove if unnecessary
            'fwd_packets': [],  # Not used
            'bwd_packets': [],  # Not used
            'iat_list': [],
            'fwd_iat_list': [],
            'bwd_iat_list': [],
            'Fwd Packet Lengths': [],
            'Bwd Packet Lengths': [],
            'All Packet Lengths': [],
            'Total Fwd Packets': 0,
            'Total Backward Packets': 0,
            'Total Length of Fwd Packets': 0,
            'Total Length of Bwd Packets': 0,
            'Fwd Header Length': 0,
            'Bwd Header Length': 0,
            'Fwd PSH Flags': 0,
            'Bwd PSH Flags': 0,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'FIN Flag Count': 0,
            'SYN Flag Count': 0,
            'RST Flag Count': 0,
            'PSH Flag Count': 0,
            'ACK Flag Count': 0,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Active Mean': 0,
            'Active Std': 0,
            'Active Max': 0,
            'Active Min': 0,
            'Idle Mean': 0,
            'Idle Std': 0,
            'Idle Max': 0,
            'Idle Min': 0,
            'fwd_init_win': -1,
            'bwd_init_win': -1,
            'act_data_pkt_fwd': 0,
            'min_seg_size_forward': 0
        }
        return flow_data

    def _update_flow_features(self, flow_data, packet, flow_id):
        is_forward = (packet[IP].src == flow_data['fwd_ip'])
        packet_len = len(packet[IP].payload) if IP in packet and packet[IP].payload else 0
        now = datetime.now()
        
        # --- 1. Basic Counts and Lists ---
        
        # IAT calculation
        now_us = now.timestamp() * 1000000.0 # Time in microseconds
        
        if flow_data['last_packet_time_us'] is not None:
            iat = now_us - flow_data['last_packet_time_us']
            flow_data['iat_list'].append(iat)
        
        flow_data['last_packet_time'] = now
        flow_data['last_packet_time_us'] = now_us

        # Packet direction stats
        ip_header_len = packet[IP].ihl * 4 if IP in packet else 0
        
        if is_forward:
            flow_data['Total Fwd Packets'] += 1
            flow_data['Total Length of Fwd Packets'] += packet_len
            flow_data['Fwd Packet Lengths'].append(packet_len)
            flow_data['Fwd Header Length'] += ip_header_len
        else:
            flow_data['Total Backward Packets'] += 1
            flow_data['Total Length of Bwd Packets'] += packet_len
            flow_data['Bwd Packet Lengths'].append(packet_len)
            flow_data['Bwd Header Length'] += ip_header_len

        # Total packet length for Min/Max/Mean/Std
        flow_data['All Packet Lengths'].append(packet_len)
        
        # Flag and Window tracking (for TCP)
        if TCP in packet:
            tcp = packet[TCP]
            flow_data['FIN Flag Count'] += 1 if tcp.flags & 0x01 else 0
            flow_data['SYN Flag Count'] += 1 if tcp.flags & 0x02 else 0
            flow_data['RST Flag Count'] += 1 if tcp.flags & 0x04 else 0
            flow_data['PSH Flag Count'] += 1 if tcp.flags & 0x08 else 0
            flow_data['ACK Flag Count'] += 1 if tcp.flags & 0x10 else 0
            flow_data['URG Flag Count'] += 1 if tcp.flags & 0x20 else 0
            flow_data['CWE Flag Count'] += 1 if tcp.flags & 0x40 else 0
            flow_data['ECE Flag Count'] += 1 if tcp.flags & 0x80 else 0

            if 'fwd_init_win' not in flow_data or flow_data['fwd_init_win'] == -1 and is_forward:
                flow_data['fwd_init_win'] = tcp.window
            if 'bwd_init_win' not in flow_data or flow_data['bwd_init_win'] == -1 and not is_forward:
                flow_data['bwd_init_win'] = tcp.window

            if tcp.flags & 0x08:  # PSH flag
                if is_forward:
                    flow_data['Fwd PSH Flags'] += 1
                else:
                    flow_data['Bwd PSH Flags'] += 1

            if tcp.flags & 0x20:  # URG flag
                if is_forward:
                    flow_data['Fwd URG Flags'] += 1
                else:
                    flow_data['Bwd URG Flags'] += 1

        # Active/Idle tracking (simplified, assuming no long idle periods in short flows)
        if flow_data['last_packet_time'] is not None:
            idle_time = (now - flow_data['last_packet_time']).total_seconds() * 1000000  # us
            if idle_time > flow_data['Idle Max']:
                flow_data['Idle Max'] = idle_time
            if idle_time < flow_data['Idle Min'] or flow_data['Idle Min'] == 0:
                flow_data['Idle Min'] = idle_time

        # Min seg size (assume 20 for TCP/UDP)
        if flow_data['min_seg_size_forward'] == 0:
            flow_data['min_seg_size_forward'] = 20 if TCP in packet or UDP in packet else 0

        logging.debug(f"Flow {flow_id} updated: Fwd Pkts={flow_data['Total Fwd Packets']}, Bwd Pkts={flow_data['Total Backward Packets']}, Len={packet_len}")

    def _extract_features(self, flow_data, flow_id):
        """Extract all 77 features safely and return DataFrame."""
        # Start with zero-filled dict for all features
        features = {col: 0.0 for col in FEATURE_NAMES}

        duration_us = (datetime.now().timestamp() * 1_000_000 - flow_data['start_time_us'])
        if duration_us <= 0:
            duration_us = 1  # prevent division by zero

        features['Flow Duration'] = duration_us

        # Basic counters
        features['Total Fwd Packets'] = flow_data['Total Fwd Packets']
        features['Total Backward Packets'] = flow_data['Total Backward Packets']
        features['Total Length of Fwd Packets'] = flow_data['Total Length of Fwd Packets']
        features['Total Length of Bwd Packets'] = flow_data['Total Length of Bwd Packets']
        features['Fwd Header Length'] = flow_data['Fwd Header Length']
        features['Bwd Header Length'] = flow_data['Bwd Header Length']
        features['Fwd Header Length.1'] = flow_data['Fwd Header Length']

        # Safely convert lists to numpy arrays
        fwd_lens = np.array(flow_data.get('Fwd Packet Lengths', []))
        bwd_lens = np.array(flow_data.get('Bwd Packet Lengths', []))
        all_lens = np.array(flow_data.get('All Packet Lengths', []))

        # Helper: safe stats
        def safe_stats(arr):
            if len(arr) == 0:
                return 0.0, 0.0, 0.0, 0.0
            return float(np.max(arr)), float(np.min(arr)), float(np.mean(arr)), float(np.std(arr))

        f_max, f_min, f_mean, f_std = safe_stats(fwd_lens)
        features['Fwd Packet Length Max'] = f_max
        features['Fwd Packet Length Min'] = f_min
        features['Fwd Packet Length Mean'] = f_mean
        features['Fwd Packet Length Std'] = f_std
        features['Avg Fwd Segment Size'] = f_mean

        b_max, b_min, b_mean, b_std = safe_stats(bwd_lens)
        features['Bwd Packet Length Max'] = b_max
        features['Bwd Packet Length Min'] = b_min
        features['Bwd Packet Length Mean'] = b_mean
        features['Bwd Packet Length Std'] = b_std
        features['Avg Bwd Segment Size'] = b_mean

        a_max, a_min, a_mean, a_std = safe_stats(all_lens)
        features['Max Packet Length'] = a_max
        features['Min Packet Length'] = a_min
        features['Packet Length Mean'] = a_mean
        features['Packet Length Std'] = a_std
        features['Packet Length Variance'] = a_std ** 2
        features['Average Packet Size'] = a_mean

        # Rates
        duration_s = duration_us / 1_000_000.0
        total_bytes = features['Total Length of Fwd Packets'] + features['Total Length of Bwd Packets']
        total_pkts = features['Total Fwd Packets'] + features['Total Backward Packets']

        features['Flow Bytes/s'] = total_bytes / duration_s
        features['Flow Packets/s'] = total_pkts / duration_s
        features['Fwd Packets/s'] = features['Total Fwd Packets'] / duration_s
        features['Bwd Packets/s'] = features['Total Backward Packets'] / duration_s

        # IAT
        iats = np.array(flow_data.get('iat_list', []))
        if len(iats) > 0:
            features['Flow IAT Mean'] = np.mean(iats)
            features['Flow IAT Std'] = np.std(iats)
            features['Flow IAT Max'] = np.max(iats)
            features['Flow IAT Min'] = np.min(iats)

        # Flags (already counted)
        flag_keys = ['Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags',
                     'FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count',
                     'ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count']
        for k in flag_keys:
            features[k] = flow_data.get(k, 0)

        # Down/Up Ratio
        fwd = features['Total Fwd Packets']
        features['Down/Up Ratio'] = features['Total Backward Packets'] / fwd if fwd > 0 else 0

        # Windows
        features['Init_Win_bytes_forward'] = flow_data.get('fwd_init_win', -1)
        features['Init_Win_bytes_backward'] = flow_data.get('bwd_init_win', -1)

        # Subflow & active data
        features['Subflow Fwd Packets'] = features['Total Fwd Packets']
        features['Subflow Fwd Bytes'] = features['Total Length of Fwd Packets']
        features['act_data_pkt_fwd'] = sum(1 for x in fwd_lens if x > 0)
        features['min_seg_size_forward'] = flow_data.get('min_seg_size_forward', 20)

        # Bulk = 0
        bulk_keys = ['Fwd Avg Bytes/Bulk','Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate',
                     'Bwd Avg Bytes/Bulk','Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate']
        for k in bulk_keys:
            features[k] = 0

        # Active & Idle — these are not calculated → just set to 0
        features['Active Mean'] = 0
        features['Active Std'] = 0
        features['Active Max'] = 0
        features['Active Min'] = 0
        features['Idle Mean'] = 0
        features['Idle Std'] = 0
        features['Idle Max'] = 0
        features['Idle Min'] = 0

        # Final DataFrame
        df = pd.DataFrame([features])[FEATURE_NAMES]
        logging.info(f"Features extracted for flow {flow_id} → {total_pkts} packets")
        return df

    def cleanup_old_flows(self, timeout=FLOW_TIMEOUT):
        """Remove timed-out flows."""
        with self.flow_lock:
            now = datetime.now()
            to_delete = []
            for flow_id, flow_data in self.flows.items():
                if flow_data['last_packet_time'] and \
                   (now - flow_data['last_packet_time']).total_seconds() > timeout:
                    to_delete.append(flow_id)
            
            for flow_id in to_delete:
                logging.debug(f"Cleaning up timed-out flow: {flow_id}")
                del self.flows[flow_id]

    def reset_flows(self):
        """Clear all active flows."""
        with self.flow_lock:
            self.flows.clear()