# packet_processor.py
import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP

class FlowFeatureExtractor:
    """Extract features from network flows for DDoS detection"""
    
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'timestamps': [],
            'fwd_packets': [],
            'bwd_packets': [],
            'start_time': None,
            'flags': defaultdict(int)
        })

        # Features used for model training
        self.feature_names = [
            'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
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
            'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
            'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
    
    def get_flow_id(self, packet):
        """Generate unique flow ID from packet"""
        if IP not in packet:
            return None
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = 'TCP'
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = 'UDP'
        else:
            return None
        
        if src_ip < dst_ip:
            flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            direction = 'fwd'
        else:
            flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            direction = 'bwd'
        
        return flow_id, direction, dst_port
    
    def add_packet(self, packet):
        """Add packet to flow"""
        flow_info = self.get_flow_id(packet)
        if not flow_info:
            return None
        
        flow_id, direction, dst_port = flow_info
        flow = self.flows[flow_id]
        
        timestamp = datetime.now()
        if flow['start_time'] is None:
            flow['start_time'] = timestamp
            flow['dst_port'] = dst_port
        
        packet_len = len(packet)
        flow['packets'].append(packet_len)
        flow['timestamps'].append(timestamp)
        
        if direction == 'fwd':
            flow['fwd_packets'].append(packet_len)
        else:
            flow['bwd_packets'].append(packet_len)
        
        if TCP in packet:
            tcp_flags = packet[TCP].flags
            if tcp_flags & 0x01: flow['flags']['FIN'] += 1
            if tcp_flags & 0x02: flow['flags']['SYN'] += 1
            if tcp_flags & 0x04: flow['flags']['RST'] += 1
            if tcp_flags & 0x08: flow['flags']['PSH'] += 1
            if tcp_flags & 0x10: flow['flags']['ACK'] += 1
            if tcp_flags & 0x20: flow['flags']['URG'] += 1
            if tcp_flags & 0x40: flow['flags']['ECE'] += 1
            if tcp_flags & 0x80: flow['flags']['CWR'] += 1
        
        return flow_id
    
    def calculate_iat(self, timestamps):
        """Calculate Inter-Arrival Time statistics"""
        if len(timestamps) < 2:
            return 0, 0, 0, 0, 0
        
        iats = [(timestamps[i+1] - timestamps[i]).total_seconds() * 1000000
                for i in range(len(timestamps)-1)]
        
        if not iats:
            return 0, 0, 0, 0, 0
        
        return (
            sum(iats),
            np.mean(iats) if iats else 0,
            np.std(iats) if len(iats) > 1 else 0,
            max(iats) if iats else 0,
            min(iats) if iats else 0
        )
    
    def extract_features(self, flow_id):
        """Extract all features for a flow"""
        flow = self.flows[flow_id]
        
        if len(flow['packets']) < 2:
            return None
        
        duration = (flow['timestamps'][-1] - flow['start_time']).total_seconds()
        if duration == 0:
            duration = 0.000001
        
        fwd_packets = flow['fwd_packets']
        bwd_packets = flow['bwd_packets']
        all_packets = flow['packets']
        
        features = {}
        
        # Basic flow features
        features['Destination Port'] = flow['dst_port']
        features['Flow Duration'] = duration * 1000000
        features['Total Fwd Packets'] = len(fwd_packets)
        features['Total Backward Packets'] = len(bwd_packets)
        features['Total Length of Fwd Packets'] = sum(fwd_packets) if fwd_packets else 0
        features['Total Length of Bwd Packets'] = sum(bwd_packets) if bwd_packets else 0
        features['Fwd Packet Length Max'] = max(fwd_packets) if fwd_packets else 0
        features['Fwd Packet Length Min'] = min(fwd_packets) if fwd_packets else 0
        features['Fwd Packet Length Mean'] = np.mean(fwd_packets) if fwd_packets else 0
        features['Fwd Packet Length Std'] = np.std(fwd_packets) if len(fwd_packets) > 1 else 0
        features['Bwd Packet Length Max'] = max(bwd_packets) if bwd_packets else 0
        features['Bwd Packet Length Min'] = min(bwd_packets) if bwd_packets else 0
        features['Bwd Packet Length Mean'] = np.mean(bwd_packets) if bwd_packets else 0
        features['Bwd Packet Length Std'] = np.std(bwd_packets) if len(bwd_packets) > 1 else 0
        
        total_bytes = sum(all_packets)
        features['Flow Bytes/s'] = total_bytes / duration if duration > 0 else 0
        features['Flow Packets/s'] = len(all_packets) / duration if duration > 0 else 0
        
        # Inter-arrival times
        flow_iat = self.calculate_iat(flow['timestamps'])
        features['Flow IAT Mean'], features['Flow IAT Std'], features['Flow IAT Max'], features['Flow IAT Min'] = flow_iat[1], flow_iat[2], flow_iat[3], flow_iat[4]
        
        fwd_timestamps = flow['timestamps'][:len(fwd_packets)]
        fwd_iat = self.calculate_iat(fwd_timestamps)
        features['Fwd IAT Total'], features['Fwd IAT Mean'], features['Fwd IAT Std'], features['Fwd IAT Max'], features['Fwd IAT Min'] = fwd_iat
        
        bwd_timestamps = flow['timestamps'][len(fwd_packets):]
        bwd_iat = self.calculate_iat(bwd_timestamps)
        features['Bwd IAT Total'], features['Bwd IAT Mean'], features['Bwd IAT Std'], features['Bwd IAT Max'], features['Bwd IAT Min'] = bwd_iat
        
        # Flags
        features['FIN Flag Count'] = flow['flags'].get('FIN', 0)
        features['SYN Flag Count'] = flow['flags'].get('SYN', 0)
        features['RST Flag Count'] = flow['flags'].get('RST', 0)
        features['PSH Flag Count'] = flow['flags'].get('PSH', 0)
        features['ACK Flag Count'] = flow['flags'].get('ACK', 0)
        features['URG Flag Count'] = flow['flags'].get('URG', 0)
        features['CWE Flag Count'] = flow['flags'].get('CWR', 0)
        features['ECE Flag Count'] = flow['flags'].get('ECE', 0)
        
        # Header lengths
        header_val = len(fwd_packets) * 40
        features['Fwd Header Length'] = header_val
        features['Fwd Header Length.1'] = header_val  # MUST EXIST for scaler
        features['Bwd Header Length'] = len(bwd_packets) * 40
        
        # Rates and sizes
        features['Fwd Packets/s'] = len(fwd_packets) / duration if duration > 0 else 0
        features['Bwd Packets/s'] = len(bwd_packets) / duration if duration > 0 else 0
        features['Min Packet Length'] = min(all_packets) if all_packets else 0
        features['Max Packet Length'] = max(all_packets) if all_packets else 0
        features['Packet Length Mean'] = np.mean(all_packets) if all_packets else 0
        features['Packet Length Std'] = np.std(all_packets) if len(all_packets) > 1 else 0
        features['Packet Length Variance'] = np.var(all_packets) if len(all_packets) > 1 else 0
        
        features['Down/Up Ratio'] = (len(bwd_packets) / len(fwd_packets) if fwd_packets else 0)
        features['Average Packet Size'] = np.mean(all_packets) if all_packets else 0
        features['Avg Fwd Segment Size'] = np.mean(fwd_packets) if fwd_packets else 0
        features['Avg Bwd Segment Size'] = np.mean(bwd_packets) if bwd_packets else 0
        
        # Bulk placeholders
        for key in ['Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 
                    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']:
            features[key] = 0
        
        # Subflows
        features['Subflow Fwd Packets'], features['Subflow Fwd Bytes'] = len(fwd_packets), sum(fwd_packets)
        features['Subflow Bwd Packets'], features['Subflow Bwd Bytes'] = len(bwd_packets), sum(bwd_packets)
        features['Init_Win_bytes_forward'], features['Init_Win_bytes_backward'] = 65535, 65535
        features['act_data_pkt_fwd'] = len(fwd_packets)
        features['min_seg_size_forward'] = min(fwd_packets) if fwd_packets else 0
        features['Active Mean'], features['Active Std'], features['Active Max'], features['Active Min'] = duration * 500000, 0, duration * 1000000, 0
        features['Idle Mean'], features['Idle Std'], features['Idle Max'], features['Idle Min'] = 0, 0, 0, 0

        # Ensure all columns exist and in correct order for scaler
        df = pd.DataFrame([features])
        df = df.reindex(columns=self.feature_names, fill_value=0)
        return df
    
    def cleanup_old_flows(self, timeout=30):
        """Remove flows older than timeout seconds"""
        current_time = datetime.now()
        flows_to_remove = [fid for fid, f in self.flows.items() if f['start_time'] and (current_time - f['start_time']).total_seconds() > timeout]
        for flow_id in flows_to_remove:
            del self.flows[flow_id]
        return len(flows_to_remove)
