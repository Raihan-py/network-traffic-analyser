"""Read a PCAP file and display useful information about each packet."""

from scapy.all import IP, TCP, UDP, ICMP, ARP, rdpcap
from scapy.error import Scapy_Exception
from datetime import datetime, timezone


def display_packet(packet, packet_number):
    """Display decoded information for one Scapy packet."""

    print(f"\n--- Packet {packet_number} ---") 
    print(packet.summary())
    print("Packet size:", len(packet), "bytes")
    print("Raw timestamp:", packet.time)

    # Convert Scapy's Unix timestamp to an unambiguous UTC date and time.
    capture_time = datetime.fromtimestamp(float(packet.time), tz = timezone.utc)
    print("Timestamp (UTC):", capture_time.isoformat())

    packet_record = { 
        "packet_number": packet_number,
        "timestamp": capture_time.isoformat(),
        "packet_size": len(packet),
        "source_ip": None,
        "destination_ip": None,
        "protocol": "N/A",
        "source_port": None,
        "destination_port": None,
    }

    # IP addresses belong to the network layer and are separate from ports.
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("Source IP:", ip_layer.src)
        print("Destination IP", ip_layer.dst)

    # Only access a protocol layer after confirming that the packet contains it.
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print("Protocol: TCP")
        print("Source port:", tcp_layer.sport)
        print("Destination port", tcp_layer.dport)

    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("Protocol: UDP")
        print("Source port:", udp_layer.sport)
        print("Destination port", udp_layer.dport)

    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        print("Protocol: ICMP")
        print("ICMP type:", icmp_layer.type)
        print("ICMP code:", icmp_layer.code)

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        print("Protocol: ARP")
        print("Operation:", arp_layer.op)
        print("Sender IP:", arp_layer.psrc)
        print("Target IP:", arp_layer.pdst)
        print("Sender MAC:", arp_layer.hwsrc)
        print("Target MAC:", arp_layer.hwdst)

    else :
        print("Protocol : N/A")

    print("")


# Ask at runtime so the analyser can inspect different capture files.
pcap_filename = input("enter the PCAP filename: ").strip()

try:
    packets = rdpcap(pcap_filename)
except FileNotFoundError:
    print(f"Error: '{pcap_filename}' was not found.")
    raise SystemExit(1)
except Scapy_Exception as error:
    print(f"Error: '{pcap_filename}' is not a valid capture file.")
    print("Details:", error)
    raise SystemExit(1)

print("Number of packets:", len(packets))

for packet_number, packet in enumerate(packets, start=1):
    display_packet(packet, packet_number)
    
