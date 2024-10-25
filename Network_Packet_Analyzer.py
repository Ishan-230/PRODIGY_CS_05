import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, wrpcap
from scapy.layers.http import HTTPRequest, HTTPResponse

# Analyze packets and print relevant info
def packet_analyzer(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # TCP Protocol (HTTP, HTTPS, etc.)
        if protocol == 6:  # TCP
            print(f"\n[TCP] {ip_src}:{packet[TCP].sport} --> {ip_dst}:{packet[TCP].dport}")
            if packet.haslayer(HTTPRequest):  # HTTP Request
                print(f"HTTP Request: {packet[HTTPRequest].Host.decode()} {packet[HTTPRequest].Path.decode()}")
            elif packet.haslayer(HTTPResponse):  # HTTP Response
                print(f"HTTP Response detected")
            # Detect HTTPS traffic by port (commonly 443)
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                print(f"Encrypted HTTPS traffic detected (Port 443)")
            else:
                print(f"Payload (hex): {bytes(packet[TCP].payload).hex()}")
        
        # UDP Protocol (DNS, etc.)
        elif protocol == 17:  # UDP
            print(f"\n[UDP] {ip_src}:{packet[UDP].sport} --> {ip_dst}:{packet[UDP].dport}")
            if packet.haslayer(DNS):
                if packet.haslayer(DNSQR):  # DNS Query
                    print(f"DNS Query: {packet[DNSQR].qname.decode()}")
                elif packet.haslayer(DNSRR):  # DNS Response
                    print(f"DNS Response: {packet[DNSRR].rdata}")
            print(f"Payload (hex): {bytes(packet[UDP].payload).hex()}")

        # ICMP Protocol (for Ping requests)
        elif protocol == 1:  # ICMP
            print(f"\n[ICMP] {ip_src} --> {ip_dst} | Type: {packet[ICMP].type} Code: {packet[ICMP].code}")
        
        else:
            print(f"\n[Other IP Protocol] {ip_src} --> {ip_dst} | Protocol: {protocol}")

    elif ARP in packet:
        if packet[ARP].op == 1:  # ARP Request
            print(f"[ARP Request] Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}")
        elif packet[ARP].op == 2:  # ARP Reply
            print(f"[ARP Reply] {packet[ARP].hwsrc} is at {packet[ARP].psrc}")

# Function to save packets to a pcap file
def save_packet(packet, filename="captured_packets.pcap"):
    wrpcap(filename, packet, append=True)

# Start sniffing on an interface
def start_sniffing(interface="eth0", filter=None, save_to_file=False):
    print(f"Starting packet capture on {interface} with filter: {filter}")
    
    # Sniff packets, apply filter if specified
    if save_to_file:
        sniff(iface=interface, prn=lambda x: (packet_analyzer(x), save_packet(x)), filter=filter, store=0)
    else:
        sniff(iface=interface, prn=packet_analyzer, filter=filter, store=0)

# Sniffing in a separate thread
def start_sniffing_thread(interface="eth0", filter=None, save_to_file=False):
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface, filter, save_to_file))
    sniff_thread.start()
    return sniff_thread

if __name__ == "__main__":
    interface = "eth0"  # Set your network interface
    protocol_filter = "ip or arp"  # You can customize the filter
    save_to_file = True  # Set to True if you want to save to file
    
    # Start sniffing
    start_sniffing_thread(interface, protocol_filter, save_to_file)
