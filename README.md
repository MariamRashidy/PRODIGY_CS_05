# Python Network Sniffer with Scapy

This is a Python-based network sniffer built using the `scapy` library. The tool allows you to capture and analyze network packets, supporting various common protocols like TCP, UDP, ICMP, DNS, HTTP, HTTPS, and ARP. You can also define custom filters or capture all protocols.

## Features
- Capture and analyze network packets.
- Supports popular protocols like:
  - **TCP** (Transmission Control Protocol)
  - **UDP** (User Datagram Protocol)
  - **ICMP** (Internet Control Message Protocol)
  - **DNS** (Domain Name System)
  - **HTTP** (Hypertext Transfer Protocol)
  - **HTTPS** (Secure HTTP)
  - **ARP** (Address Resolution Protocol)
- User-friendly options for selecting predefined protocols or defining custom filters.
- Captures both HTTP requests and payloads (unencrypted) and recognizes encrypted HTTPS traffic.
- Exception handling for robust packet processing.
- Option to capture **all traffic** without any filter.

## Requirements

Make sure you have Python and the following libraries installed:

- `scapy`

You can install the required libraries using pip:

```bash
pip install scapy
```

## How to Use
Run the script using Python, and it will prompt you to select a protocol filter or provide a custom one.

1- Start the Sniffer:
```bash 
network_analyzer.py
```
2- Choose a Protocol:
```yaml
Select a protocol filter:
1: tcp
2: udp
3: icmp
4: port 53
5: tcp port 80
6: tcp port 443
7: arp
8: Capture all protocols
0: Custom filter (enter manually)
```
-Enter the number corresponding to the protocol you want to capture.

-Select 8 to capture all protocols.

-Select 0 to enter a custom Berkeley Packet Filter (BPF), such as:
tcp and port 80

3- Stopping the Sniffer: To stop packet sniffing, press Ctrl+C.


## Ethical Use Disclaimer

This tool is intended strictly for educational purposes and for use in environments where you have explicit permission to monitor and analyze network traffic. Unauthorized use of this tool on networks or devices without permission may violate laws and regulations.
