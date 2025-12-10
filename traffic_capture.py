#traffic_capture.py
import threading
import time
from scapy.all import sniff, IP, conf
from packet_processor import FlowFeatureExtractor
from collections import deque
import json
from datetime import datetime
import platform


class TrafficCapture:
    """Capture and process network traffic in real-time - FIXED for loopback"""

    def __init__(self, interface=None, callback=None):
        self.callback = callback
        self.extractor = FlowFeatureExtractor()
        self.running = False
        self.capture_thread = None

        # **FIXED**: Better loopback interface detection
        self.interface = self._detect_loopback_interface(interface)
        
        # Track when each flow was last processed
        self.last_processed = {}
        self.processing_interval = 1.0  # **REDUCED** from 2.0 to 1.0 for faster detection
        
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

    def _detect_loopback_interface(self, interface):
        """Detect the correct loopback interface for the OS"""
        system = platform.system()
        
        if interface and interface != 'lo':
            print(f"Using specified interface: {interface}")
            return interface
        
        if system == 'Windows':
            from scapy.all import get_if_list, IFACES
            
            print("\n=== Detecting Windows Loopback Interface ===")
            interfaces = get_if_list()
            print(f"Available interfaces: {interfaces}")
            
            # Try multiple methods to find loopback
            loopback_candidates = []
            
            for iface in interfaces:
                iface_lower = iface.lower()
                if any(keyword in iface_lower for keyword in ['loopback', 'npcap', 'adapter for loopback']):
                    loopback_candidates.append(iface)
                    print(f"Found loopback candidate: {iface}")
            
            if loopback_candidates:
                chosen = loopback_candidates[0]
                print(f"✓ Selected loopback interface: {chosen}")
                return chosen
            
            # If no loopback found, try to capture on all interfaces
            print("⚠ WARNING: Loopback interface not found!")
            print("⚠ This might prevent detection of attacks to 127.0.0.1")
            print("\n** SOLUTION: Install Npcap with 'Loopback Support' enabled **")
            print("   Download from: https://npcap.com/#download")
            print("   During installation, CHECK 'Install Npcap in WinPcap API-compatible Mode'")
            print("   and CHECK 'Support loopback traffic'\n")
            
            return None  # Will capture on all interfaces
            
        elif system == 'Linux':
            print("Using Linux loopback interface: lo")
            return 'lo'
            
        elif system == 'Darwin':  # macOS
            print("Using macOS loopback interface: lo0")
            return 'lo0'
        
        return None

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

                    # Check if we should process this flow
                    flow = self.extractor.flows[flow_id]
                    current_time = time.time()
                    last_proc_time = self.last_processed.get(flow_id, 0)
                    
                    # **FIXED**: More aggressive processing
                    # Process flow if:
                    # 1. It has enough packets (reduced to 10 from 20)
                    # 2. Enough time has passed (1 second instead of 2)
                    # 3. OR flow has accumulated many packets (>30 instead of >50)
                    should_process = (
                        len(flow['packets']) >= 10 and  # REDUCED threshold
                        (current_time - last_proc_time) >= self.processing_interval
                    ) or len(flow['packets']) >= 30  # REDUCED threshold
                    
                    if should_process:
                        self.last_processed[flow_id] = current_time
                        features_df = self.extractor.extract_features(flow_id)

                        if features_df is not None and self.callback:
                            try:
                                self.callback(features_df, flow_id, packet_info)
                            except Exception as e:
                                print(f"Error in callback: {e}")
                                import traceback
                                traceback.print_exc()

        except Exception as e:
            print(f"Error processing packet: {e}")
            import traceback
            traceback.print_exc()

    def start(self):
        """Start capturing traffic"""
        if self.running:
            print("Traffic capture already running")
            return

        self.running = True
        self.stats['start_time'] = datetime.now()

        def capture_loop():
            interface_msg = f"interface: {self.interface}" if self.interface else "ALL interfaces"
            print(f"\n🔍 Starting traffic capture on {interface_msg}...")
            print(f"   Monitoring for traffic to/from 127.0.0.1...")
            
            try:
                # **FIXED**: Add filter for better loopback capture
                # Filter for IP traffic only (speeds up processing)
                capture_filter = "ip"
                
                if self.interface:
                    print(f"   Using BPF filter: {capture_filter}")
                    sniff(
                        iface=self.interface,
                        filter=capture_filter,
                        prn=self.packet_handler,
                        store=False,
                        stop_filter=lambda x: not self.running
                    )
                else:
                    print(f"   Using BPF filter: {capture_filter}")
                    print("   ⚠ Capturing on ALL interfaces - may miss loopback traffic!")
                    sniff(
                        filter=capture_filter,
                        prn=self.packet_handler,
                        store=False,
                        stop_filter=lambda x: not self.running
                    )
            except PermissionError:
                print("\n❌ ERROR: Permission denied!")
                print("   SOLUTION: Run as administrator/root:")
                if platform.system() == 'Windows':
                    print("   - Right-click Python/IDE and 'Run as Administrator'")
                else:
                    print("   - Use: sudo python your_script.py")
                self.running = False
            except Exception as e:
                print(f"\n❌ ERROR in capture loop: {e}")
                if platform.system() == 'Windows':
                    print("\n** TROUBLESHOOTING for Windows:**")
                    print("1. Install Npcap from: https://npcap.com/#download")
                    print("2. During installation, CHECK these options:")
                    print("   ✓ 'Install Npcap in WinPcap API-compatible Mode'")
                    print("   ✓ 'Support loopback traffic'")
                    print("3. Restart your computer after installation")
                    print("4. Run this script as Administrator")
                self.running = False

        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()

        # Start statistics updater
        self.stats_thread = threading.Thread(target=self._update_stats, daemon=True)
        self.stats_thread.start()

        time.sleep(1)  # Give it time to start
        
        if self.running:
            print("✓ Traffic capture started successfully\n")
        else:
            print("✗ Traffic capture failed to start\n")

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

        while self.running:
            time.sleep(1)

            with self.lock:
                current_packets = self.stats['total_packets']
                self.stats['packets_per_second'] = current_packets - last_packets
                last_packets = current_packets
                self.stats['total_flows'] = len(self.extractor.flows)
                
                # Print live stats every 5 seconds
                if self.stats['total_predictions'] % 5 == 0 and self.stats['packets_per_second'] > 0:
                    print(f"📊 Packets/s: {self.stats['packets_per_second']}, Total: {current_packets}, Flows: {self.stats['total_flows']}")

            # Cleanup old flows (keep for 60 seconds)
            self.extractor.cleanup_old_flows(timeout=60)

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
                    age = (datetime.now() - flow_data['start_time']).total_seconds()
                    flows.append({
                        'flow_id': flow_id,
                        'packets': len(flow_data['packets']),
                        'age': age,
                        'fwd_packets': len(flow_data['fwd_packets']),
                        'bwd_packets': len(flow_data['bwd_packets'])
                    })
            return flows