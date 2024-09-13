# Packet Sniffer Tool

This is a simple packet sniffer tool developed in Python using the scapy library. It captures and analyzes network packets, displaying important information such as source and destination IP addresses, protocols (TCP, UDP, ICMP, HTTP, and HTTPS), and payload data.

## Features

-Capture and analyze network packets
-Identifies and analyzes different protocols: TCP, UDP, ICMP, HTTP, and HTTPS.
-Displays HTTP request information (method, host, and path).
-Indicates when HTTPS traffic is detected (encrypted data).
-This tool is intended strictly for educational purposes and to be used on networks where you have explicit permission to capture and analyze traffic.

## Requirements

To run this tool, you need the following:
Python 3.x
scapy library

You can install the required Python libraries using the following command:
```bash
pip install scapy
```

## Usage

1- Clone this repository or download the script to your local machine.
2- Run the script with elevated privileges (root/administrator), as packet sniffing typically requires such permissions:
```bash
python packet_sniffer.py
```
3- The tool will start capturing and displaying packets on your network. You can stop the sniffing by pressing Ctrl + C.

## Code Explanation

-packet_callback: This function is triggered when a packet is captured. It analyzes the packet and displays relevant information.
-For TCP and UDP packets, it displays source and destination ports.
-For HTTP packets (port 80), it displays the HTTP method, host, and path.
-For HTTPS packets (port 443), it indicates that the data is encrypted and cannot be displayed.
-For all packets, it shows the source and destination IP addresses and protocol.
-Protocol Analysis: The tool identifies the protocol (TCP, UDP, ICMP, HTTP, HTTPS) using the protocol numbers and ports.

## Ethical Use Disclaimer

This tool is intended strictly for educational purposes and for use in environments where you have explicit permission to monitor and analyze network traffic. Unauthorized use of this tool on networks or devices without permission may violate laws and regulations.
