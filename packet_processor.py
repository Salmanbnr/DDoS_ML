#packet_processor.py
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
            'flags': defaultdict(int),
            'dst_port': 0
        })

        # Features used for model training (MUST match training exactly)
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
        
        # Use bidirectional flow (same flow for both directions)
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
        """Calculate Inter-Arrival Time statistics in MICROSECONDS"""
        if len(timestamps) < 2:
            return 0, 0, 0, 0, 0
        
        # Convert to microseconds (to match training data)
        iats = [(timestamps[i+1] - timestamps[i]).total_seconds() * 1_000_000
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
        """Extract all features for a flow - MUST match training data format"""
        flow = self.flows[flow_id]
        
        # Need at least a few packets
        if len(flow['packets']) < 2:
            return None
        
        # Duration in MICROSECONDS (critical for matching training data)
        duration = (flow['timestamps'][-1] - flow['start_time']).total_seconds()
        if duration == 0:
            duration = 0.000001  # Avoid division by zero
        
        duration_microsec = duration * 1_000_000  # Convert to microseconds
        
        fwd_packets = flow['fwd_packets']
        bwd_packets = flow['bwd_packets']
        all_packets = flow['packets']
        
        features = {}
        
        # Basic flow features
        features['Destination Port'] = flow['dst_port']
        features['Flow Duration'] = duration_microsec  # In microseconds
        features['Total Fwd Packets'] = len(fwd_packets)
        features['Total Backward Packets'] = len(bwd_packets)
        features['Total Length of Fwd Packets'] = sum(fwd_packets) if fwd_packets else 0
        features['Total Length of Bwd Packets'] = sum(bwd_packets) if bwd_packets else 0
        
        # Packet length stats
        features['Fwd Packet Length Max'] = max(fwd_packets) if fwd_packets else 0
        features['Fwd Packet Length Min'] = min(fwd_packets) if fwd_packets else 0
        features['Fwd Packet Length Mean'] = np.mean(fwd_packets) if fwd_packets else 0
        features['Fwd Packet Length Std'] = np.std(fwd_packets) if len(fwd_packets) > 1 else 0
        features['Bwd Packet Length Max'] = max(bwd_packets) if bwd_packets else 0
        features['Bwd Packet Length Min'] = min(bwd_packets) if bwd_packets else 0
        features['Bwd Packet Length Mean'] = np.mean(bwd_packets) if bwd_packets else 0
        features['Bwd Packet Length Std'] = np.std(bwd_packets) if len(bwd_packets) > 1 else 0
        
        # Flow rates (bytes and packets per SECOND)
        total_bytes = sum(all_packets)
        features['Flow Bytes/s'] = total_bytes / duration if duration > 0 else 0
        features['Flow Packets/s'] = len(all_packets) / duration if duration > 0 else 0
        
        # Inter-arrival times (in MICROSECONDS)
        flow_iat = self.calculate_iat(flow['timestamps'])
        features['Flow IAT Mean'] = flow_iat[1]
        features['Flow IAT Std'] = flow_iat[2]
        features['Flow IAT Max'] = flow_iat[3]
        features['Flow IAT Min'] = flow_iat[4]
        
        # Forward IAT
        fwd_timestamps = [flow['timestamps'][i] for i in range(len(flow['timestamps'])) 
                         if i < len(fwd_packets)]
        fwd_iat = self.calculate_iat(fwd_timestamps)
        features['Fwd IAT Total'] = fwd_iat[0]
        features['Fwd IAT Mean'] = fwd_iat[1]
        features['Fwd IAT Std'] = fwd_iat[2]
        features['Fwd IAT Max'] = fwd_iat[3]
        features['Fwd IAT Min'] = fwd_iat[4]
        
        # Backward IAT
        bwd_timestamps = [flow['timestamps'][i] for i in range(len(flow['timestamps'])) 
                         if i >= len(fwd_packets)]
        bwd_iat = self.calculate_iat(bwd_timestamps)
        features['Bwd IAT Total'] = bwd_iat[0]
        features['Bwd IAT Mean'] = bwd_iat[1]
        features['Bwd IAT Std'] = bwd_iat[2]
        features['Bwd IAT Max'] = bwd_iat[3]
        features['Bwd IAT Min'] = bwd_iat[4]
        
        # PSH and URG flags (not implemented in basic version - set to 0)
        features['Fwd PSH Flags'] = 0
        features['Bwd PSH Flags'] = 0
        features['Fwd URG Flags'] = 0
        features['Bwd URG Flags'] = 0
        
        # Header lengths (20 bytes for IP, 20 for TCP, 8 for UDP)
        fwd_header_len = len(fwd_packets) * 40  # Simplified: IP(20) + TCP/UDP(20)
        bwd_header_len = len(bwd_packets) * 40
        features['Fwd Header Length'] = fwd_header_len
        features['Bwd Header Length'] = bwd_header_len
        features['Fwd Header Length.1'] = fwd_header_len  # Duplicate column in dataset
        
        # Packet rates
        features['Fwd Packets/s'] = len(fwd_packets) / duration if duration > 0 else 0
        features['Bwd Packets/s'] = len(bwd_packets) / duration if duration > 0 else 0
        
        # Packet length stats
        features['Min Packet Length'] = min(all_packets) if all_packets else 0
        features['Max Packet Length'] = max(all_packets) if all_packets else 0
        features['Packet Length Mean'] = np.mean(all_packets) if all_packets else 0
        features['Packet Length Std'] = np.std(all_packets) if len(all_packets) > 1 else 0
        features['Packet Length Variance'] = np.var(all_packets) if len(all_packets) > 1 else 0
        
        # TCP Flags
        features['FIN Flag Count'] = flow['flags'].get('FIN', 0)
        features['SYN Flag Count'] = flow['flags'].get('SYN', 0)
        features['RST Flag Count'] = flow['flags'].get('RST', 0)
        features['PSH Flag Count'] = flow['flags'].get('PSH', 0)
        features['ACK Flag Count'] = flow['flags'].get('ACK', 0)
        features['URG Flag Count'] = flow['flags'].get('URG', 0)
        features['CWE Flag Count'] = flow['flags'].get('CWR', 0)
        features['ECE Flag Count'] = flow['flags'].get('ECE', 0)
        
        # Ratios and averages
        features['Down/Up Ratio'] = len(bwd_packets) / len(fwd_packets) if fwd_packets else 0
        features['Average Packet Size'] = np.mean(all_packets) if all_packets else 0
        features['Avg Fwd Segment Size'] = np.mean(fwd_packets) if fwd_packets else 0
        features['Avg Bwd Segment Size'] = np.mean(bwd_packets) if bwd_packets else 0
        
        # Bulk features (not implemented - set to 0)
        features['Fwd Avg Bytes/Bulk'] = 0
        features['Fwd Avg Packets/Bulk'] = 0
        features['Fwd Avg Bulk Rate'] = 0
        features['Bwd Avg Bytes/Bulk'] = 0
        features['Bwd Avg Packets/Bulk'] = 0
        features['Bwd Avg Bulk Rate'] = 0
        
        # Subflow features
        features['Subflow Fwd Packets'] = len(fwd_packets)
        features['Subflow Fwd Bytes'] = sum(fwd_packets) if fwd_packets else 0
        features['Subflow Bwd Packets'] = len(bwd_packets)
        features['Subflow Bwd Bytes'] = sum(bwd_packets) if bwd_packets else 0
        
        # Window and segment size features
        features['Init_Win_bytes_forward'] = 8192  # Typical initial window
        features['Init_Win_bytes_backward'] = 229  # Typical
        features['act_data_pkt_fwd'] = max(1, len(fwd_packets) - 1)
        features['min_seg_size_forward'] = 20  # Typical minimum
        
        # Active/Idle time features (simplified - based on flow duration)
        features['Active Mean'] = duration_microsec / 2
        features['Active Std'] = 0
        features['Active Max'] = duration_microsec
        features['Active Min'] = 0
        features['Idle Mean'] = 0
        features['Idle Std'] = 0
        features['Idle Max'] = 0
        features['Idle Min'] = 0
        
        # Create DataFrame with correct column order
        df = pd.DataFrame([features])
        df = df.reindex(columns=self.feature_names, fill_value=0)
        
        return df
    
    def cleanup_old_flows(self, timeout=60):
        """Remove flows older than timeout seconds"""
        current_time = datetime.now()
        flows_to_remove = [
            fid for fid, f in self.flows.items() 
            if f['start_time'] and (current_time - f['start_time']).total_seconds() > timeout
        ]
        for flow_id in flows_to_remove:
            del self.flows[flow_id]
        return len(flows_to_remove)