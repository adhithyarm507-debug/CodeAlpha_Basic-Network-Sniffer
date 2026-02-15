from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, Raw
from scapy.arch import get_if_list
import sys
import platform
import os
from datetime import datetime
from collections import defaultdict

packet_count = 0
protocol_stats = defaultdict(int)
ip_stats = defaultdict(int)
port_stats = defaultdict(int)
packets_data = []

if platform.system() == "Windows":
    conf.use_pcap = False
    try:

        from scapy.arch.windows import get_windows_if_list
        conf.use_pcap = True
    except Exception:
        
        from scapy.arch import windows
        try:
            conf.iface = windows.get_ip_from_name(windows.get_windows_if_list()[0][0])
        except Exception:
            pass

def packet_callback(packet):
    
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
        
        ip_stats[ip_src] += 1
        protocol_stats[protocol] += 1
        
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
        
        print(f"\n[Packet #{packet_count}] Size: {packet_len} bytes | Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"  SRC: {ip_src}:{src_port} -> DST: {ip_dst}:{dst_port}")
        print(f"  Protocol: {proto_name} | TTL: {ttl}", end="")
        
        if flags and proto_name == "TCP":
            print(f" | Flags: {flags}", end="")
        print()
        
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
        print(f"\n[Packet #{packet_count}] Non-IP packet detected | Size: {len(packet)} bytes")
        print("-" * 70)

def display_statistics():
    
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
    help_text = """
    ╔══════════════════════════════════════════════════════════════╗
    ║       NETWORK PACKET SNIFFER - Advanced Edition             ║
    ║               Usage Guide & Examples                         ║
    ╚══════════════════════════════════════════════════════════════╝

    DESCRIPTION:
      Captures and analyzes network packets in real-time with detailed
      protocol information, IP statistics, and packet payload analysis.

    USAGE:
      python "BASIC NETWORK SNIFFER.py" [OPTIONS] [PACKET_LIMIT]

    OPTIONS:
      -h, --help              Show this help message and exit
      -l, --list              List available network interfaces
      -i, --interface IFACE    Specify network interface to sniff on
                              (default: system default interface)

    ARGUMENTS:
      PACKET_LIMIT            Maximum number of packets to capture
                              (default: unlimited, press Ctrl+C to stop)

    EXAMPLES:
      1. List available interfaces:
         python "BASIC NETWORK SNIFFER.py" --list

      2. Capture packets on default interface:
         python "BASIC NETWORK SNIFFER.py"

      3. Capture 100 packets:
         python "BASIC NETWORK SNIFFER.py" 100

      4. Capture on specific interface (Windows):
         python "BASIC NETWORK SNIFFER.py" --interface "Ethernet"

      5. Capture 50 packets on specific interface:
         python "BASIC NETWORK SNIFFER.py" --interface "Ethernet" 50

    FEATURES:
      • Real-time packet capture and display
      • Protocol analysis (TCP, UDP, ICMP, etc.)
      • Source/Destination IP and Port tracking
      • TTL (Time To Live) analysis
      • TCP flags detection
      • Payload preview (UTF-8 text or hex)
      • Detailed statistics report
      • CSV export of captured packets
      • Cross-platform support (Windows, Linux, macOS)

    REQUIREMENTS:
      • Python 3.6+
      • Scapy library: pip install scapy
      • Administrator/root privileges
      • Windows: Npcap (https://nmap.org/npcap/)
      • Linux: libpcap (usually pre-installed)
      • macOS: Command Line Tools

    STATISTICS REPORT:
      After stopping (Ctrl+C), the tool displays:
      • Total packets captured
      • Protocol distribution (TCP/UDP/ICMP/Other)
      • Top 5 source IPs
      • Top 5 ports in use

    CSV EXPORT:
      Captured packets can be saved to CSV with columns:
      Timestamp, Packet#, Size, SrcIP, DstIP, SrcPort, DstPort,
      Protocol, TTL, Flags, PayloadSize

    TROUBLESHOOTING:
      • "Permission denied": Run with Administrator privileges (Windows)
                            or sudo (Linux/macOS)
      • "No module named scapy": Install with: pip install scapy
      • "No interfaces found": Check network adapter status
      • No packets captured: Check firewall settings

    AUTHOR: CodeAlpha Project
    VERSION: 1.0.0 (Advanced Edition)
    """
    print(help_text)

def main():
    
    interface = None
    packet_limit = None
    show_interfaces = False
    
    args = [arg for arg in sys.argv[1:] if arg.strip()]
    
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
    
    
    if show_interfaces:
        list_interfaces()
        sys.exit(0)
    
    try:
        
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
