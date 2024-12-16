# Network Sniffer

This project is a simple **Network Sniffer** implemented in Python using the Scapy library. The program captures network packets on a specified interface and optionally filters them based on user-provided criteria.

## Features

- Sniff packets on a specified network interface.
- Apply optional filters to capture only specific types of packets.
- Display a summary of captured packets in real time.

## Requirements

- Python 3.x
- Scapy library
- [Npcap](https://nmap.org/npcap/) (for Windows)

Install Scapy using pip if it is not already installed:

```bash
pip install scapy
```

### Additional Setup for Windows

If you are running this script on Windows, you need to install the Npcap executable. Npcap is a packet capturing driver and library for Windows.

Download and install it from the [official Npcap website](https://nmap.org/npcap/).

## Usage

Run the script using Python. You can specify the network interface and an optional filter:

```bash
python sniffer.py [-i INTERFACE] [-f FILTER]
```

### Arguments

- `-i, --interface`: Specify the network interface to sniff (e.g., `eth0`, `wlan0`).
- `-f, --filter`: Apply a filter to capture specific packets (e.g., `tcp`, `udp`, `icmp`).

### Examples

#### Sniff all packets on a specific interface:

```bash
python sniffer.py -i eth0
```

#### Sniff packets with a filter:

```bash
python sniffer.py -i wlan0 -f "tcp"
```

#### Sniff all packets without specifying an interface:

```bash
python sniffer.py
```

## How It Works

1. The script uses `argparse` to parse command-line arguments for the interface and filter.
2. It calls the `sniffNetwork` function to start packet sniffing using Scapy.
3. Captured packets are processed and summarized by the `process_packet` function.

## Important Notes

- The script may require root or administrative privileges to run, as packet sniffing often requires elevated permissions.
- Ensure you have the necessary permissions to sniff packets on the chosen network interface.
- On Windows, Npcap must be installed and properly configured for the script to work.

## Disclaimer

This tool is for educational purposes only. Unauthorized network sniffing may violate privacy laws or policies. Use it responsibly and only on networks you own or have permission to analyze.

## Author

- **Wasila**
