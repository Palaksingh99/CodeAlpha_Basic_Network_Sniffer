from scapy.all import sniff, Ether, IP, TCP, UDP

def packet_callback(packet):       #Function to handle each packet
    if Ether in packet:            # Check if the packet has an Ethernet layer
        eth_layer = packet[Ether]
        print(f"Ethernet Frame: {eth_layer.src} -> {eth_layer.dst} (Type: {eth_layer.type})")
    
    if IP in packet:               # Check if the packet has an IP layer
        ip_layer = packet[IP] 
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst} (Protocol: {ip_layer.proto})")

        if TCP in packet:          # Check if the packet has an TCP layer 
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Packet: {ip_layer.src}:{tcp_sport} -> {ip_layer.dst}:{tcp_dport}")

        elif UDP in packet:        # Check if the packet has an UDP layer
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"UDP Packet: {ip_layer.src}:{udp_sport} -> {ip_layer.dst}:{udp_dport}")

    print()

sniff(prn=packet_callback,store=False) # Start sniffing