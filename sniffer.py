from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_callback(packet):

    # Check if packet contains an IP layer
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        protocol = packet[IP].proto

        print("\n==============================")
        print(f"Source      : {source}")
        print(f"Destination : {destination}")
        print(f"Protocol    : {protocol}")

        # TCP packet
        if TCP in packet:
            print(f"TCP Source Port      : {packet[TCP].sport}")
            print(f"TCP Destination Port : {packet[TCP].dport}")

        # UDP packet
        elif UDP in packet:
            print(f"UDP Source Port      : {packet[UDP].sport}")
            print(f"UDP Destination Port : {packet[UDP].dport}")

        # ICMP packet
        elif ICMP in packet:
            print("ICMP packet detected")


print("Starting packet sniffer...")
print("Press CTRL+C to stop.\n")

sniff(prn=packet_callback, store=False)

