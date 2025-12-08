#!/usr/bin/env python3
"""
Local Traffic Simulator for DDoS Detection Projects
--------------------------------------------------
This script ONLY generates high-volume traffic to 127.0.0.1 for research/testing.
It CANNOT target external IPs. All external targeting is blocked for safety.
"""

import socket
import random
import time
import threading
from scapy.all import IP, TCP, UDP, send, RandShort
import argparse


class TrafficSimulator:
    """Generate traffic patterns for ML-based DDoS detection (localhost only)."""

    def __init__(self, target_ip="127.0.0.1", target_port=8050):
        if target_ip != "127.0.0.1":
            raise ValueError(
                "⚠ This simulator only allows localhost (127.0.0.1) for safety.")

        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.threads = []
        self.stats = {"packets_sent": 0, "start_time": None}

    # --------------------------------------------------------------
    # SYN FLOOD (Local Simulation)
    # --------------------------------------------------------------
    def syn_flood(self, duration=10, rate=50):
        print(f"Local SYN Flood → {self.target_ip}:{self.target_port}")
        self.running = True
        self.stats["start_time"] = time.time()

        def worker():
            while self.running and (time.time() - self.stats["start_time"]) < duration:
                try:
                    packet = IP(dst=self.target_ip) / TCP(
                        sport=random.randint(1024, 65535),
                        dport=self.target_port,
                        flags="S",
                        seq=random.randint(1000, 99999)
                    )
                    send(packet, verbose=0)
                    self.stats["packets_sent"] += 1
                    time.sleep(1 / rate)
                except:
                    break

        self._spawn_threads(worker, rate)
        self._live_stats(duration, "Packets")

    # --------------------------------------------------------------
    # UDP FLOOD (Local Simulation)
    # --------------------------------------------------------------
    def udp_flood(self, duration=10, rate=50):
        print(f"Local UDP Flood → {self.target_ip}:{self.target_port}")
        self.running = True
        self.stats["start_time"] = time.time()

        def worker():
            while self.running and (time.time() - self.stats["start_time"]) < duration:
                try:
                    payload = bytes([random.randint(0, 255)
                                    for _ in range(256)])
                    packet = IP(dst=self.target_ip) / UDP(
                        sport=RandShort(), dport=self.target_port
                    ) / payload

                    send(packet, verbose=0)
                    self.stats["packets_sent"] += 1
                    time.sleep(1 / rate)
                except:
                    break

        self._spawn_threads(worker, rate)
        self._live_stats(duration, "Packets")

    # --------------------------------------------------------------
    # HTTP FLOOD (Local Simulation)
    # --------------------------------------------------------------
    def http_flood(self, duration=10, rate=20):
        print(f"Local HTTP Flood → {self.target_ip}:{self.target_port}")
        self.running = True
        self.stats["start_time"] = time.time()

        def worker():
            while self.running and (time.time() - self.stats["start_time"]) < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)

                    try:
                        sock.connect((self.target_ip, self.target_port))
                        request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
                        sock.send(request.encode())
                        self.stats["packets_sent"] += 1
                    except:
                        pass
                    finally:
                        sock.close()

                    time.sleep(1 / rate)

                except:
                    break

        self._spawn_threads(worker, rate)
        self._live_stats(duration, "Requests")

    # --------------------------------------------------------------
    # NORMAL TRAFFIC
    # --------------------------------------------------------------
    def normal_traffic(self, duration=10, rate=5):
        print(
            f"Generating Normal Local Traffic → {self.target_ip}:{self.target_port}")
        self.running = True
        self.stats["start_time"] = time.time()

        def worker():
            while self.running and (time.time() - self.stats["start_time"]) < duration:
                try:
                    pkt_type = random.choice(["syn", "ack", "data"])

                    if pkt_type == "syn":
                        packet = IP(dst=self.target_ip) / \
                            TCP(flags="S", dport=self.target_port)
                    elif pkt_type == "ack":
                        packet = IP(dst=self.target_ip) / \
                            TCP(flags="A", dport=self.target_port)
                    else:
                        packet = IP(dst=self.target_ip) / \
                            TCP(flags="PA", dport=self.target_port) / b"OK"

                    send(packet, verbose=0)
                    self.stats["packets_sent"] += 1
                    time.sleep(random.uniform(0.5, 2.0) / rate)

                except:
                    break

        self._spawn_threads(worker, 1)
        self._live_stats(duration, "Packets")

    # --------------------------------------------------------------
    # Thread Helper
    # --------------------------------------------------------------
    def _spawn_threads(self, worker, rate):
        num_threads = max(1, min(10, rate // 10 + 1))
        for _ in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            self.threads.append(t)

        print(f"Threads Started: {num_threads}")

    # --------------------------------------------------------------
    # Stats Helper
    # --------------------------------------------------------------
    def _live_stats(self, duration, label):
        try:
            while self.running and (time.time() - self.stats["start_time"]) < duration:
                elapsed = time.time() - self.stats["start_time"]
                print(
                    f"\rTime: {elapsed:.1f}s | {label}: {self.stats['packets_sent']}", end="")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopped manually.")

        self.stop()
        print("\nDone.")
        print(f"Total {label}: {self.stats['packets_sent']}")

    # --------------------------------------------------------------
    # Stop Traffic
    # --------------------------------------------------------------
    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=1)
        self.threads = []


# --------------------------------------------------------------
# Main CLI
# --------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Local Traffic Simulator for DDoS Detection ML Projects")
    parser.add_argument(
        "--type", "-t", choices=["syn", "udp", "http", "normal"], default="syn")
    parser.add_argument("--duration", "-d", type=int, default=10)
    parser.add_argument("--rate", "-r", type=int, default=50)
    parser.add_argument("--port", "-p", type=int, default=8050)

    args = parser.parse_args()

    print("\n===== LOCAL TRAFFIC SIMULATOR (SAFE) =====")
    simulator = TrafficSimulator(target_ip="127.0.0.1", target_port=args.port)

    if args.type == "syn":
        simulator.syn_flood(args.duration, args.rate)
    elif args.type == "udp":
        simulator.udp_flood(args.duration, args.rate)
    elif args.type == "http":
        simulator.http_flood(args.duration, args.rate)
    elif args.type == "normal":
        simulator.normal_traffic(args.duration, args.rate)


if __name__ == "__main__":
    main()
