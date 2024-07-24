from scapy.all import sniff, Ether, IP

def packet_callback(packet):   #Function to handle each packet
    if Ether in packet:        # Check if the packet has an Ethernet layer
        eth_layer = packet[Ether]
        print(f"Ethernet Frame: {eth_layer.src} -> {eth_layer.dst} (Type: {eth_layer.type})")
    
    if IP in packet:           # Check if the packet has an IP layer
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst} (Protocol: {ip_layer.proto})")
        print()

sniff(prn=packet_callback, store=False)  # Start sniffing