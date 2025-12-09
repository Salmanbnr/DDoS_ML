import threading
import time
from scapy.all import sniff, IP
from packet_processor import FlowFeatureExtractor
from collections import deque
import json
from datetime import datetime


class TrafficCapture:
    """Capture and process network traffic in real-time"""

    def __init__(self, interface=None, callback=None):
        # Handle interface selection for Windows
        import platform
        if platform.system() == 'Windows':
            if interface == 'lo':
                # Try to find Windows loopback interface
                from scapy.all import get_if_list
                interfaces = get_if_list()
                loopback_found = False
                for iface in interfaces:
                    if 'Loopback' in iface or 'NPF_Loopback' in iface or '127.0.0.1' in iface:
                        self.interface = iface
                        loopback_found = True
                        print(f"Found Windows loopback interface: {iface}")
                        break
                if not loopback_found:
                    self.interface = None
                    print(
                        "Windows loopback not found, capturing on all interfaces (may not capture localhost traffic)")
            else:
                self.interface = interface
        else:
            self.interface = interface or 'lo'

        self.callback = callback
        self.extractor = FlowFeatureExtractor()
        self.running = False
        self.capture_thread = None

        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'packets_per_second': 0,
            'bytes_per_second': 0,
            'start_time': None
        }

        # Recent packets for display
        self.recent_packets = deque(maxlen=100)
        self.lock = threading.Lock()

    def packet_handler(self, packet):
        """Process each captured packet"""
        try:
            if IP not in packet:
                return

            with self.lock:
                self.stats['total_packets'] += 1

                # Add to extractor
                flow_id = self.extractor.add_packet(packet)

                if flow_id:
                    # Store packet info
                    packet_info = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': packet[IP].src,
                        'dst_ip': packet[IP].dst,
                        'protocol': packet[IP].proto,
                        'length': len(packet),
                        'flow_id': flow_id
                    }
                    self.recent_packets.append(packet_info)

                    # FIXED: Wait for MORE packets before classification (10 instead of 5)
                    flow = self.extractor.flows[flow_id]
                    if len(flow['packets']) >= 10:  # Increased from 5 to 10 for better feature quality
                        features_df = self.extractor.extract_features(flow_id)

                        if features_df is not None and self.callback:
                            try:
                                self.callback(
                                    features_df, flow_id, packet_info)
                            except Exception as e:
                                print(f"Error in callback: {e}")

        except Exception as e:
            print(f"Error processing packet: {e}")

    def start(self):
        """Start capturing traffic"""
        if self.running:
            print("Traffic capture already running")
            return

        self.running = True
        self.stats['start_time'] = datetime.now()

        def capture_loop():
            print(
                f"Starting traffic capture on interface: {self.interface if self.interface else 'ALL'}...")
            try:
                # On Windows, if interface is None, capture on all interfaces
                if self.interface:
                    sniff(
                        iface=self.interface,
                        prn=self.packet_handler,
                        store=False,
                        stop_filter=lambda x: not self.running
                    )
                else:
                    # Capture on all interfaces (Windows)
                    sniff(
                        prn=self.packet_handler,
                        store=False,
                        stop_filter=lambda x: not self.running
                    )
            except Exception as e:
                print(f"Error in capture loop: {e}")
                print(
                    "HINT: On Windows, make sure Npcap is installed with loopback support")
                print("Download from: https://npcap.com/#download")
                self.running = False

        self.capture_thread = threading.Thread(
            target=capture_loop, daemon=True)
        self.capture_thread.start()

        # Start statistics updater
        self.stats_thread = threading.Thread(
            target=self._update_stats, daemon=True)
        self.stats_thread.start()

        print("Traffic capture started successfully")

    def stop(self):
        """Stop capturing traffic"""
        print("Stopping traffic capture...")
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        print("Traffic capture stopped")

    def _update_stats(self):
        """Update statistics periodically"""
        last_packets = 0
        last_bytes = 0

        while self.running:
            time.sleep(1)

            with self.lock:
                current_packets = self.stats['total_packets']

                # Calculate rates
                self.stats['packets_per_second'] = current_packets - \
                    last_packets
                self.stats['total_flows'] = len(self.extractor.flows)

                last_packets = current_packets

            # Cleanup old flows
            self.extractor.cleanup_old_flows(timeout=30)

    def get_stats(self):
        """Get current statistics"""
        with self.lock:
            return self.stats.copy()

    def get_recent_packets(self, n=20):
        """Get recent packets"""
        with self.lock:
            return list(self.recent_packets)[-n:]

    def get_active_flows(self):
        """Get information about active flows"""
        with self.lock:
            flows = []
            for flow_id, flow_data in self.extractor.flows.items():
                if flow_data['start_time']:
                    age = (datetime.now() -
                           flow_data['start_time']).total_seconds()
                    flows.append({
                        'flow_id': flow_id,
                        'packets': len(flow_data['packets']),
                        'age': age,
                        'fwd_packets': len(flow_data['fwd_packets']),
                        'bwd_packets': len(flow_data['bwd_packets'])
                    })
            return flows