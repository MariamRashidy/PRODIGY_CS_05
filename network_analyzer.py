from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.http import HTTPRequest  

def packet_callback(packet):
   
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        
        print(f"\n[+] New Packet:")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
    
        if protocol == 6:  # TCP protocol number
            print("Protocol: TCP")
          
            if TCP in packet:
                tcp_layer = packet[TCP]
                print(f"Source Port: {tcp_layer.sport}")
                print(f"Destination Port: {tcp_layer.dport}")
                
             
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:  

                    if packet.haslayer(HTTPRequest):
                        http_layer = packet[HTTPRequest]
                        print(f"HTTP Request: {http_layer.Method} {http_layer.Host}{http_layer.Path}")
                    if packet.haslayer(Raw):  
                        print(f"HTTP Payload: {packet[Raw].load}")

              
                elif tcp_layer.dport == 443 or tcp_layer.sport == 443:  # HTTPS uses port 443
                    print("Protocol: HTTPS (Data is encrypted)")

        elif protocol == 17:  
            print("Protocol: UDP")
            
            if UDP in packet:
                udp_layer = packet[UDP]
                print(f"Source Port: {udp_layer.sport}")
                print(f"Destination Port: {udp_layer.dport}")
                
        elif protocol == 1:  
            print("Protocol: ICMP")
            
        else:
            print(f"Protocol: {protocol}")
        
       
        if packet.haslayer(Raw):
            print(f"Payload Data: {packet[Raw].load}")


print("Starting packet sniffing... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
