"""Read a PCAP file and display useful information about each packet."""

from datetime import datetime, timezone

from scapy.all import IP, TCP, UDP, ICMP, IPv6, ARP, rdpcap
from scapy.error import Scapy_Exception


def parse_packet(packet, packet_number):
    """Convert one Scapy packet into a normalized dictionary.

    Every returned dictionary has the same keys. Values remain ``None`` when a
    field does not apply, such as ports on an ICMP or ARP packet.

    Args:
        packet: A packet decoded by Scapy.
        packet_number: The packet's one-based position in the capture.

    Returns:
        A dictionary containing the common fields used by later analysis.
    """

    # Convert Scapy's Unix timestamp to an unambiguous UTC date and time.
    capture_time = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)

    # A fixed schema lets later statistics process every protocol consistently.
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
        packet_record["source_ip"] = ip_layer.src
        packet_record["destination_ip"] = ip_layer.dst

    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        packet_record["source_ip"] = ipv6_layer.src
        packet_record["destination_ip"] = ipv6_layer.dst

    # This is a separate check because TCP/UDP can run over either IPv4 or IPv6,
    # while ARP does not contain an IP layer at all.
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        packet_record["protocol"] = "TCP"
        packet_record["source_port"] = tcp_layer.sport
        packet_record["destination_port"] = tcp_layer.dport

    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        packet_record["protocol"] = "UDP"
        packet_record["source_port"] = udp_layer.sport
        packet_record["destination_port"] = udp_layer.dport

    elif packet.haslayer(ICMP):
        packet_record["protocol"] = "ICMP"

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        packet_record["protocol"] = "ARP"
        packet_record["source_ip"] = arp_layer.psrc
        packet_record["destination_ip"] = arp_layer.pdst

    return packet_record

def display_packet(packet_record):
    """Display one normalized packet record without depending on Scapy."""

    print(f"\n--- Packet {packet_record['packet_number']} ---")
    print("Timestamp (UTC):", packet_record["timestamp"])
    print("Packet size:", packet_record["packet_size"], "bytes")
    print("Source IP:", packet_record["source_ip"])
    print("Destination IP:", packet_record["destination_ip"])
    print("Protocol:", packet_record["protocol"])

    # Ports only apply to protocols such as TCP and UDP.
    if packet_record["source_port"] is not None:
        print("Source port:", packet_record["source_port"])
        print("Destination port:", packet_record["destination_port"])

    print()

def calculate_total_bytes(packet_records):
    """Return the combined size of all parsed packets"""

    total_bytes = 0

    for packet_record in packet_records:
        total_bytes += packet_record["packet_size"]

    return total_bytes

def calculate_average_packet_size(packet_records):
    """Return the average packet size, or 0.0 for an empty capture"""
    if not packet_records:
        return 0.0

    total_bytes = calculate_total_bytes(packet_records)
    return total_bytes / len(packet_records)

def calculate_protocol_distribution(packet_records):
    """Return the number of packets observed for each protocol"""
    protocol_counts = {}

    for packet_record in packet_records:
        protocol = packet_record["protocol"]
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

    return protocol_counts

def main():
    """Run the command-line PCAP analyser."""

    # Ask at runtime so the analyser can inspect different capture files.
    pcap_filename = input("enter the PCAP filename: ").strip()

    try:
        # rdpcap is convenient for small files because it loads every packet.
        # A streaming reader will be preferable for large captures later.
        packets = rdpcap(pcap_filename)
    except FileNotFoundError:
        print(f"Error: '{pcap_filename}' was not found.")
        raise SystemExit(1)
    except Scapy_Exception as error:
        print(f"Error: '{pcap_filename}' is not a valid capture file.")
        print("Details:", error)
        raise SystemExit(1)

    print("Number of packets:", len(packets))

    packet_records = []

    # start=1 gives users familiar one-based packet numbering.
    for packet_number, packet in enumerate(packets, start=1):
        packet_record = parse_packet(packet, packet_number)
        packet_records.append(packet_record)
        display_packet(packet_record)

    print("Packet records created:", len(packet_records))

    total_bytes = calculate_total_bytes(packet_records)
    print("Total bytes:", total_bytes)

    average_packet_size = calculate_average_packet_size(packet_records)
    print("Average packet size:", average_packet_size, "bytes")

    protocol_distribution = calculate_protocol_distribution(packet_records)
    print("Protocol distribution:")
    for protocol, count in protocol_distribution.items():
        print(f" {protocol}: {count}")

# Prevent the interactive program from running when tests import its functions.
if __name__ == "__main__":
    main()
