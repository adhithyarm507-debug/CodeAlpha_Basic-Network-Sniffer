# cSpell:ignore dport sport Npcap libpcap
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, Raw
from scapy.arch import get_if_list
import sys
import platform
import os
from datetime import datetime
from collections import defaultdict

# Global packet counter and statistics
packet_count = 0
protocol_stats = defaultdict(int)
ip_stats = defaultdict(int)
port_stats = defaultdict(int)
packets_data = []

# Configure Scapy for Windows - Use layer 3 socket
if platform.system() == "Windows":
    conf.use_pcap = False
    try:
        # Try to use Npcap if installed
        from scapy.arch.windows import get_windows_if_list
        conf.use_pcap = True
    except Exception:
        # Fallback to layer 3 socket (doesn't require Npcap)
        from scapy.arch import windows
        try:
            conf.iface = windows.get_ip_from_name(windows.get_windows_if_list()[0][0])
        except Exception:
            pass

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Analyzes and prints key information.
    """
    global packet_count
    packet_count += 1
    
    packet_info = {
        'timestamp': datetime.now().isoformat(),
        'number': packet_count,
        'size': len(packet)
    }
    
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        ttl = packet[IP].ttl
        packet_len = len(packet)
        
        # Update statistics
        ip_stats[ip_src] += 1
        protocol_stats[protocol] += 1
        
        # Determine protocol name and extract port information
        src_port = dst_port = "N/A"
        payload = b""
        flags = ""
        
        if protocol == 6:
            proto_name = "TCP"
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                payload = bytes(packet[TCP].payload) if packet[TCP].payload else b""
                port_stats[f"{src_port}/{proto_name}"] += 1
                port_stats[f"{dst_port}/{proto_name}"] += 1
        elif protocol == 17:
            proto_name = "UDP"
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload = bytes(packet[UDP].payload) if packet[UDP].payload else b""
                port_stats[f"{src_port}/{proto_name}"] += 1
                port_stats[f"{dst_port}/{proto_name}"] += 1
        elif protocol == 1:
            proto_name = "ICMP"
            payload = bytes(packet[ICMP].payload) if ICMP in packet and packet[ICMP].payload else b""
        else:
            proto_name = f"Other ({protocol})"
            payload = bytes(packet.payload) if packet.payload else b""
        
        # Store packet data
        packet_info.update({
            'src_ip': ip_src,
            'dst_ip': ip_dst,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto_name,
            'ttl': ttl,
            'flags': flags,
            'payload_size': len(payload)
        })
        packets_data.append(packet_info)
        
        # Print packet info
        print(f"\n[Packet #{packet_count}] Size: {packet_len} bytes | Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"  SRC: {ip_src}:{src_port} -> DST: {ip_dst}:{dst_port}")
        print(f"  Protocol: {proto_name} | TTL: {ttl}", end="")
        
        if flags and proto_name == "TCP":
            print(f" | Flags: {flags}", end="")
        print()
        
        # Display payload if it's printable text (first 100 bytes)
        if payload:
            try:
                printable_payload = payload.decode('utf-8', errors='ignore')[:100]
                if printable_payload.strip():
                    print(f"  Payload: {repr(printable_payload)}")
            except Exception:
                if len(payload) > 0:
                    print(f"  Payload (hex): {payload.hex()[:50]}...")
        
        print("-" * 70)
    else:
        # Non-IP packets
        print(f"\n[Packet #{packet_count}] Non-IP packet detected | Size: {len(packet)} bytes")
        print("-" * 70)

def display_statistics():
    """Display captured packet statistics"""
    print(f"\n\n{'='*70}")
    print("CAPTURE STATISTICS")
    print(f"{'='*70}\n")
    
    print(f"Total Packets Captured: {packet_count}")
    
    if protocol_stats:
        print(f"\nProtocol Distribution:")
        protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        for proto_num in sorted(protocol_stats.keys()):
            proto_name = protocol_names.get(proto_num, f'Other ({proto_num})')
            count = protocol_stats[proto_num]
            percentage = (count / packet_count * 100) if packet_count > 0 else 0
            print(f"  {proto_name}: {count} packets ({percentage:.1f}%)")
    
    if ip_stats:
        print(f"\nTop Source IPs:")
        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_ips:
            print(f"  {ip}: {count} packets")
    
    if port_stats:
        print(f"\nTop Ports:")
        sorted_ports = sorted(port_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for port, count in sorted_ports:
            print(f"  {port}: {count} packets")
    
    print(f"\n{'='*70}\n")

def save_to_csv():
    """Save captured packets to CSV file"""
    if not packets_data:
        print("No packets to save.")
        return
    
    csv_filename = f"network_sniffer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    try:
        with open(csv_filename, 'w', encoding='utf-8') as f:
            f.write("Timestamp,Packet#,Size,SrcIP,DstIP,SrcPort,DstPort,Protocol,TTL,Flags,PayloadSize\n")
            for pkt in packets_data:
                f.write(f"{pkt.get('timestamp', '')},{pkt.get('number', '')},{pkt.get('size', '')},"
                       f"{pkt.get('src_ip', '')},{pkt.get('dst_ip', '')},{pkt.get('src_port', '')},"
                       f"{pkt.get('dst_port', '')},{pkt.get('protocol', '')},{pkt.get('ttl', '')},"
                       f"{pkt.get('flags', '')},{pkt.get('payload_size', '')}\n")
        print(f"✓ Packets saved to: {csv_filename}")
    except Exception as e:
        print(f"✗ Error saving CSV: {e}")

def list_interfaces():
    """List available network interfaces"""
    try:
        interfaces = get_if_list()
        if interfaces:
            print("\nAvailable Network Interfaces:")
            for i, interface in enumerate(interfaces, 1):
                print(f"  {i}. {interface}")
            return interfaces
        else:
            print("No network interfaces found.")
    except Exception as e:
        print(f"Error listing interfaces: {e}")
    return []

def print_help():
    """Display help information"""
    print("""
Network Packet Sniffer - Usage Guide
=====================================

Basic Usage:
  python "BASIC NETWORK SNIFFER.py"                 # Start sniffing on default interface
  python "BASIC NETWORK SNIFFER.py" 100             # Capture 100 packets
  python "BASIC NETWORK SNIFFER.py" -i eth0         # Use specific interface
  python "BASIC NETWORK SNIFFER.py" -l              # List available interfaces

Options:
  -h, --help      Show this help message
  -l, --list      List available network interfaces
  -i, --interface NAME  Specify network interface

Requirements:
  - Administrator/root privileges
  - Scapy library (pip install scapy)
  - Windows: Npcap (https://nmap.org/npcap/)
  - Linux: libpcap
  - macOS: Command Line Tools

Examples:
  # Capture 50 packets on default interface
  python "BASIC NETWORK SNIFFER.py" 50
  
  # Capture on specific interface with limit
  python "BASIC NETWORK SNIFFER.py" -i eth0 100
    """)

def main():
    """Main function to run the packet sniffer"""
    # Check command line arguments
    interface = None
    packet_limit = None
    show_interfaces = False
    
    # Process arguments
    args = [arg for arg in sys.argv[1:] if arg.strip()]
    
    # Parse arguments
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.lower() in ['-h', '--help']:
            print_help()
            sys.exit(0)
        elif arg.lower() in ['-l', '--list']:
            show_interfaces = True
        elif arg.lower() in ['-i', '--interface'] and i + 1 < len(args):
            interface = args[i + 1]
            i += 1
        elif arg.isdigit():
            packet_limit = int(arg)
        i += 1
    
    print("="*70)
    print("NETWORK PACKET SNIFFER - Advanced Edition")
    print("="*70)
    print(f"Operating System: {platform.system()}")
    print(f"Python Version: {sys.version.split()[0]}")
    
    # Show available interfaces if requested
    if show_interfaces:
        list_interfaces()
        sys.exit(0)
    
    try:
        # Check for administrator privileges on Windows
        if platform.system() == "Windows":
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    print("\n⚠ Warning: Running without Administrator privileges!")
                    print("  Some packets may not be captured. Run as Administrator for best results.")
            except Exception:
                pass
        
        print(f"\nStarting packet sniffer...")
        print(f"  Interface: {interface if interface else 'Default'}")
        if packet_limit:
            print(f"  Capture limit: {packet_limit} packets")
        print("  Press Ctrl+C to stop.\n")
        
        # Sniff packets using layer 3 socket for better Windows compatibility
        sniff(iface=interface, prn=packet_callback, store=False, 
              count=packet_limit if packet_limit else 0, filter=None)
              
    except KeyboardInterrupt:
        print("\n")
        display_statistics()
        save_choice = input("Save packets to CSV? (y/n): ").strip().lower()
        if save_choice == 'y':
            save_to_csv()
        print(f"{'='*70}")
        print("Sniffing stopped.")
        print(f"{'='*70}\n")
        sys.exit(0)
        
    except PermissionError:
        print("\n✗ Error: Administrator privileges required!")
        print("  On Windows: Right-click PowerShell → 'Run as Administrator'")
        print("  On Linux/Mac: Run with 'sudo'")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n✗ Error: {type(e).__name__}: {e}")
        print("\n⚠ Requirements:")
        print("  1. Administrator/root privileges")
        print("  2. Scapy library: pip install scapy")
        print("  3. On Windows: Npcap (https://nmap.org/npcap/)")
        print("  4. On Linux: libpcap (usually pre-installed)")
        print("  5. On macOS: Command Line Tools (xcode-select --install)")
        print("\nFor help, run: python \"BASIC NETWORK SNIFFER.py\" -h")
        sys.exit(1)

if __name__ == "__main__":
    main()
