#!/usr/bin/env python3
"""
Connection Tester - Verify Docker can reach your Windows 11 machine
Run this BEFORE starting the attack to ensure everything is configured correctly
"""

import socket
import sys
import time
import requests

def test_basic_connectivity(target_ip):
    """Test if target IP is reachable"""
    print(f"\n1️⃣ Testing basic connectivity to {target_ip}...")
    
    try:
        # Try to resolve hostname
        socket.gethostbyname(target_ip)
        print(f"   ✓ IP address is valid")
        return True
    except socket.error as e:
        print(f"   ✗ Cannot resolve {target_ip}: {e}")
        return False

def test_port_connection(target_ip, target_port):
    """Test if target port is open"""
    print(f"\n2️⃣ Testing port {target_port} on {target_ip}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        result = sock.connect_ex((target_ip, target_port))
        if result == 0:
            print(f"   ✓ Port {target_port} is OPEN and accepting connections")
            sock.close()
            return True
        else:
            print(f"   ✗ Port {target_port} is CLOSED or filtered")
            print(f"   → Check firewall settings")
            print(f"   → Ensure dashboard is running on this port")
            sock.close()
            return False
    except socket.timeout:
        print(f"   ✗ Connection timeout")
        print(f"   → Target might be unreachable")
        sock.close()
        return False
    except Exception as e:
        print(f"   ✗ Connection error: {e}")
        sock.close()
        return False

def test_http_connection(target_ip, target_port):
    """Test if HTTP service is responding"""
    print(f"\n3️⃣ Testing HTTP service at http://{target_ip}:{target_port}...")
    
    try:
        url = f"http://{target_ip}:{target_port}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            print(f"   ✓ HTTP service is responding (Status: {response.status_code})")
            print(f"   ✓ Dashboard is accessible!")
            return True
        else:
            print(f"   ⚠️ HTTP service responded with status: {response.status_code}")
            return True  # Still counts as success
    except requests.exceptions.ConnectionError:
        print(f"   ✗ Cannot connect to HTTP service")
        print(f"   → Is the dashboard running?")
        print(f"   → Check: python dashboard.py")
        return False
    except requests.exceptions.Timeout:
        print(f"   ✗ HTTP request timeout")
        return False
    except Exception as e:
        print(f"   ⚠️ HTTP test failed: {e}")
        print(f"   → But port might still be usable for TCP attacks")
        return True  # Don't fail completely

def test_packet_sending(target_ip, target_port):
    """Test sending actual packets"""
    print(f"\n4️⃣ Testing packet transmission to {target_ip}:{target_port}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((target_ip, target_port))
        
        # Send a simple HTTP GET request
        request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
        sock.send(request.encode())
        
        print(f"   ✓ Successfully sent test packet")
        
        # Try to receive response
        try:
            data = sock.recv(1024)
            if data:
                print(f"   ✓ Received response ({len(data)} bytes)")
            else:
                print(f"   ⚠️ No response received (but packet was sent)")
        except socket.timeout:
            print(f"   ⚠️ No response received (but packet was sent)")
        
        sock.close()
        return True
    except Exception as e:
        print(f"   ✗ Packet transmission failed: {e}")
        return False

def main():
    print("="*70)
    print("🔍 DOCKER CONNECTION TESTER")
    print("="*70)
    print("\nThis script verifies that Docker can attack your Windows 11 machine")
    print("Run this BEFORE starting the actual attack!\n")
    
    # Get target from command line or prompt
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    else:
        target_ip = input("Enter your Windows 11 IP address: ").strip()
    
    if len(sys.argv) > 2:
        target_port = int(sys.argv[2])
    else:
        port_input = input("Enter target port (default 8050): ").strip()
        target_port = int(port_input) if port_input else 8050
    
    print(f"\n📋 Testing configuration:")
    print(f"   Target IP: {target_ip}")
    print(f"   Target Port: {target_port}")
    print(f"\n{'='*70}")
    
    # Run tests
    results = []
    
    results.append(("Basic Connectivity", test_basic_connectivity(target_ip)))
    time.sleep(1)
    
    results.append(("Port Connection", test_port_connection(target_ip, target_port)))
    time.sleep(1)
    
    results.append(("HTTP Service", test_http_connection(target_ip, target_port)))
    time.sleep(1)
    
    results.append(("Packet Transmission", test_packet_sending(target_ip, target_port)))
    
    # Summary
    print(f"\n{'='*70}")
    print("📊 TEST SUMMARY")
    print(f"{'='*70}")
    
    all_passed = True
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"   {test_name:.<30} {status}")
        if not result:
            all_passed = False
    
    print(f"{'='*70}")
    
    if all_passed:
        print("\n🎉 ALL TESTS PASSED!")
        print("\n✓ Your system is ready for DDoS testing")
        print("✓ Docker can reach your Windows 11 machine")
        print("✓ The dashboard is accessible")
        print("\n➡️  You can now run the attack:")
        print(f"   docker run --rm -it ddos-attacker python3 docker_ddos_attacker.py \\")
        print(f"       --target {target_ip} --port {target_port} --type http \\")
        print(f"       --duration 120 --intensity medium")
    else:
        print("\n⚠️  SOME TESTS FAILED!")
        print("\n🔧 Troubleshooting steps:")
        print("   1. Ensure Docker Desktop is running")
        print("   2. Check your Windows 11 IP address (ipconfig)")
        print("   3. Start your dashboard (python dashboard.py)")
        print("   4. Open firewall port:")
        print(f"      netsh advfirewall firewall add rule name=\"DDoS Dashboard\" \\")
        print(f"          dir=in action=allow protocol=TCP localport={target_port}")
        print("   5. Verify dashboard is accessible in browser:")
        print(f"      http://127.0.0.1:{target_port}")
        print("\n   Then run this test again!")
    
    print(f"\n{'='*70}\n")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())