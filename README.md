# Network Packet Sniffer

A comprehensive network packet sniffer tool for Windows, Linux, and macOS built with Python and Scapy.

## Features

- **Real-time packet capture** - Capture live network traffic with detailed analysis
- **Protocol detection** - Identifies TCP, UDP, ICMP, and other protocols
- **Payload inspection** - View packet payloads (printable text or hex)
- **Statistics & Analytics** - Protocol distribution, top source IPs, top ports
- **CSV export** - Save captured packets to CSV for further analysis
- **Interface management** - List and select specific network interfaces
- **Cross-platform** - Works on Windows, Linux, and macOS

## Requirements

### System Requirements
- **Windows**: Administrator privileges + Npcap
- **Linux**: Root privileges + libpcap
- **macOS**: Root privileges + Command Line Tools

### Python Requirements
- Python 3.7+
- Scapy library

## Installation

### Step 1: Install Python
Download from [python.org](https://www.python.org/downloads/)

### Step 2: Install Scapy
```bash
pip install scapy
```

### Step 3: Install Npcap (Windows)
- Download from [https://nmap.org/npcap/](https://nmap.org/npcap/)
- Run installer with administrator privileges
- Restart your computer after installation

### Step 4: Install libpcap (Linux)
```bash
sudo apt-get install libpcap-dev
```

### Step 5: Install Command Line Tools (macOS)
```bash
xcode-select --install
```

## Usage

### Basic Usage
```bash
# Start sniffing on default interface
python "BASIC NETWORK SNIFFER.py"

# Capture 100 packets
python "BASIC NETWORK SNIFFER.py" 100

# List available network interfaces
python "BASIC NETWORK SNIFFER.py" -l

# Use specific interface
python "BASIC NETWORK SNIFFER.py" -i eth0

# Show help
python "BASIC NETWORK SNIFFER.py" -h
```

### On Windows (Administrator Mode)
```bash
# Right-click PowerShell → "Run as Administrator"
# Then run:
python "BASIC NETWORK SNIFFER.py" 50
```

### On Linux/macOS
```bash
sudo python "BASIC NETWORK SNIFFER.py" 50
```

## Output

The sniffer displays real-time packet information:

```
[Packet #1] Size: 134 bytes | Time: 19:23:13
  SRC: 10.116.80.47:63815 -> DST: 20.207.70.99:443
  Protocol: TCP | TTL: 128 | Flags: PA
  Payload: [binary or text data]
```

After capture, you'll see:
- **Total packets captured**
- **Protocol distribution** (TCP, UDP, ICMP percentages)
- **Top source IPs**
- **Top ports used**
- **Option to export to CSV**

## CSV Export Format

Exported CSV includes:
- Timestamp
- Packet number
- Size
- Source IP & Port
- Destination IP & Port
- Protocol
- TTL
- TCP Flags
- Payload size

## Troubleshooting

### "Sniffing not available at layer 2"
**Windows**: Install Npcap from https://nmap.org/npcap/
**Linux**: Install libpcap: `sudo apt-get install libpcap-dev`
**macOS**: Install Command Line Tools: `xcode-select --install`

### "Administrator privileges required"
**Windows**: Right-click PowerShell → "Run as Administrator"
**Linux/macOS**: Prefix command with `sudo`

### "Interface not found"
List available interfaces: `python "BASIC NETWORK SNIFFER.py" -l`

## Project Structure

```
BASIC NETWORK SNIFFER.py    - Main sniffer script
README.md                    - This file
.gitignore                   - Git ignore rules
```

## Features Explained

### Packet Callback
Processes each captured packet in real-time:
- Extracts IP, TCP, UDP, ICMP headers
- Analyzes port information
- Captures payload data
- Updates statistics

### Statistics Module
Tracks during capture:
- Protocol distribution
- Source IP frequency
- Port usage patterns

### CSV Export
Saves all captured packets with full metadata for:
- Network analysis
- Traffic investigation
- Security monitoring
- Performance analysis

## Contributing

Feel free to enhance this project with:
- Additional protocol support (IPv6, DNS, HTTP)
- Packet filtering options
- Advanced statistics visualization
- Export format options (JSON, SQLite)

## License

This project is open source and available for educational and professional use.

## Disclaimer

This tool is for legitimate network monitoring and analysis only. Ensure you have proper authorization before capturing network traffic on networks you don't own.
