"""
Find the correct network interface for packet capture on Windows
"""



from scapy.all import get_if_list, conf
import platform

print("=" * 60)
print("Network Interface Finder")
print("=" * 60)
print(f"\nOperating System: {platform.system()}")
print(f"Platform: {platform.platform()}\n")

print("Available Network Interfaces:")
print("-" * 60)

interfaces = get_if_list()

if not interfaces:
    print("No interfaces found!")
else:
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")

print("\n" + "-" * 60)
print(f"\nDefault interface: {conf.iface}")
print("\n" + "=" * 60)

print("\nRECOMMENDATIONS FOR WINDOWS:")
print("-" * 60)
print("1. For localhost testing, try these interfaces:")
print("   - Look for 'Loopback' in the name")
print("   - Or interfaces with 'Local' or '127.0.0.1'")
print("\n2. If nothing works, Npcap might not be installed properly")
print("   Download from: https://npcap.com/#download")
print("   IMPORTANT: Install with 'WinPcap API-compatible Mode'")
print("             AND 'Support loopback traffic capture'\n")

print("\n3. Common Windows interface names:")
if platform.system() == "Windows":
    print("   - Try: None (captures all interfaces)")
    print("   - Or the default interface shown above")
    
print("\n" + "=" * 60)

# Test capture
print("\nTesting packet capture on default interface...")
print("Attempting to capture 1 packet (timeout: 5 seconds)...\n")

try:
    from scapy.all import sniff
    
    def packet_callback(pkt):
        print(f"✓ Successfully captured a packet!")
        print(f"  Source: {pkt.src if hasattr(pkt, 'src') else 'Unknown'}")
        print(f"  Protocol: {pkt.name if hasattr(pkt, 'name') else 'Unknown'}")
        return True
    
    packets = sniff(count=1, timeout=5, prn=packet_callback)
    
    if packets:
        print(f"\n✓ Packet capture is WORKING on interface: {conf.iface}")
    else:
        print("\n✗ No packets captured in 5 seconds")
        print("  This might be normal if there's no network activity")
        
except Exception as e:
    print(f"\n✗ Error during capture test: {e}")
    print("\nPossible issues:")
    print("  1. Npcap not installed")
    print("  2. Need to run as Administrator")
    print("  3. Npcap not configured for loopback")

print("\n" + "=" * 60)
print("NEXT STEPS:")
print("=" * 60)
print("1. Note the default interface name above")
print("2. If capture test failed, install/reinstall Npcap")
print("3. Update dashboard.py with correct interface")
print("=" * 60)