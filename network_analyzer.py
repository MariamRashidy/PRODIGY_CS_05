from scapy.all import sniff, IP, TCP, UDP, Raw, ARP
from scapy.layers.http import HTTPRequest

def packet_callback(packet):
    try:
        if IP in packet or ARP in packet:  
            if IP in packet:
                ip_layer = packet[IP]
                protocol = ip_layer.proto

                print(f"\n[+] New Packet:")
                print(f"Source IP: {ip_layer.src}")
                print(f"Destination IP: {ip_layer.dst}")

                # TCP Protocol
                if protocol == 6:  
                    print("Protocol: TCP")
                    if TCP in packet:
                        tcp_layer = packet[TCP]
                        print(f"Source Port: {tcp_layer.sport}")
                        print(f"Destination Port: {tcp_layer.dport}")
                        
                        # Handle HTTP requests
                        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                            if packet.haslayer(HTTPRequest):
                                http_layer = packet[HTTPRequest]
                                print(f"HTTP Request: {http_layer.Method} {http_layer.Host}{http_layer.Path}")
                            if packet.haslayer(Raw):
                                print(f"HTTP Payload: {packet[Raw].load}")

                        # Handle HTTPS
                        elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                            print("Protocol: HTTPS (Data is encrypted)")

                # UDP Protocol
                elif protocol == 17:  
                    print("Protocol: UDP")
                    if UDP in packet:
                        udp_layer = packet[UDP]
                        print(f"Source Port: {udp_layer.sport}")
                        print(f"Destination Port: {udp_layer.dport}")

                        # Handle DNS (usually uses UDP port 53)
                        if udp_layer.dport == 53 or udp_layer.sport == 53:
                            print("Protocol: DNS")

                # ICMP Protocol
                elif protocol == 1:  
                    print("Protocol: ICMP")

                else:
                    print(f"Protocol: {protocol}")

                # Print raw data if it exists
                if packet.haslayer(Raw):
                    print(f"Payload Data: {packet[Raw].load}")

            # Handle ARP (non-IP protocol)
            elif ARP in packet:
                arp_layer = packet[ARP]
                print(f"Protocol: ARP")
                print(f"ARP Source: {arp_layer.psrc}")
                print(f"ARP Destination: {arp_layer.pdst}")

    except Exception as e:
        print(f"Error processing packet: {e}")


popular_protocols = {
    "1": "tcp",
    "2": "udp",
    "3": "icmp",
    "4": "port 53",  
    "5": "tcp port 80",  
    "6": "tcp port 443",  
    "7": "arp",
    "8": "all"
}

# User selects a predefined protocol filter or enters a custom one
print("Select a protocol filter:")
for key, protocol in popular_protocols.items():
    if protocol == "all":
        print(f"{key}: Capture all protocols")
    else:
        print(f"{key}: {protocol}")
print("0: Custom filter (enter manually)")

choice = input("Enter the number of your choice: ")

# Determine the filter based on the user's choice
if choice in popular_protocols:
    if popular_protocols[choice] == "all":
        user_filter = None  # No filter captures all traffic
    else:
        user_filter = popular_protocols[choice]
elif choice == "0":
    user_filter = input("Enter a BPF filter: ")
else:
    print("Invalid choice, using no filter (capturing all protocols).")
    user_filter = None

print(f"Starting packet sniffing with filter: {user_filter if user_filter else 'No filter (All protocols)'} ... Press Ctrl+C to stop.")
# Start sniffing with the chosen filter
sniff(prn=packet_callback, store=0, filter=user_filter if user_filter else None)

