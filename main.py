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

def calculate_source_ip_counts(packet_records):
    """Count packets for each available source IP address."""

    source_ip_counts = {}

    for packet_record in packet_records:
        source_ip = packet_record["source_ip"]

        # None represents a packet without an applicable network address.
        if source_ip is None:
            continue

        source_ip_counts[source_ip] = source_ip_counts.get(source_ip, 0) + 1

    return source_ip_counts

def calculate_destination_ip_counts(packet_records):
    """Count packets for each available destination IP address."""

    destination_ip_counts = {}

    for packet_record in packet_records:
        destination_ip = packet_record["destination_ip"]

        # Do not treat a missing address as a contacted destination host.
        if destination_ip is None:
            continue

        destination_ip_counts[destination_ip] = (
            destination_ip_counts.get(destination_ip, 0) + 1
        )

    return destination_ip_counts

def calculate_destination_port_counts(packet_records):
    """Count packets for each available destination port."""

    destination_port_counts = {}

    for packet_record in packet_records:
        destination_port = packet_record["destination_port"]

        # ICMP, ARP, and unsupported protocols may not have port numbers.
        if destination_port is None:
            continue

        destination_port_counts[destination_port] = (
            destination_port_counts.get(destination_port, 0) + 1
        )

    return destination_port_counts

def get_top_counts(counts, limit=5):
    """Return up to ``limit`` items ordered from highest to lowest count."""

    count_pairs = counts.items()

    # Each pair is (item, count), so pair[1] is the value used for ranking.
    sorted_pairs = sorted(
        count_pairs,
        key=lambda pair: pair[1],
        reverse=True,
    )

    return sorted_pairs[:limit]

def calculate_capture_duration(packet_records):
    """Return seconds between the earliest and latest packet timestamps."""

    # A duration needs at least two observations.
    if len(packet_records) < 2:
        return 0.0

    timestamps = []
    for packet_record in packet_records:
        timestamp = packet_record["timestamp"]
        timestamps.append(datetime.fromisoformat(timestamp))

    # min/max remain correct even if records are not in chronological order.
    earliest = min(timestamps)
    latest = max(timestamps)

    duration = latest - earliest
    return duration.total_seconds()

def calculate_packets_per_second(packet_records):
    """Return the average packet rate across the capture duration."""

    duration = calculate_capture_duration(packet_records)

    # Identical timestamps (or too few packets) give no measurable time span.
    if duration == 0:
        return 0.0

    total_records = len(packet_records)
    packets_per_second = total_records / duration
    return packets_per_second

def calculate_statistics(packet_records):
    """Combine packet records into one capture-level statistics dictionary."""

    protocol_counts = calculate_protocol_distribution(packet_records)
    source_ip_counts = calculate_source_ip_counts(packet_records)
    destination_ip_counts = calculate_destination_ip_counts(packet_records)
    destination_port_counts = calculate_destination_port_counts(packet_records)

    # Keep the complete protocol breakdown, but limit potentially long host and
    # port rankings to the most frequent entries.
    top_source_ips = get_top_counts(source_ip_counts)
    top_destination_ips = get_top_counts(destination_ip_counts)
    top_destination_ports = get_top_counts(destination_port_counts)

    total_packets = len(packet_records)
    total_bytes = calculate_total_bytes(packet_records)
    average_packet_size = calculate_average_packet_size(packet_records)
    capture_duration = calculate_capture_duration(packet_records)
    packets_per_second = calculate_packets_per_second(packet_records)

    statistics = {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "average_packet_size": average_packet_size,
        "protocol_distribution": protocol_counts,
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "top_destination_ports": top_destination_ports,
        "capture_duration": capture_duration,
        "packets_per_second": packets_per_second,
    }

    return statistics

def display_ranked_counts(title, ranked_counts):
    """Print a named list of items ordered by their occurrence count."""

    print(f"\n{title}:")
    for item, count in ranked_counts:
        print(f" {item}: {count}")


def display_statistics(statistics):
    """Display the complete capture summary in a readable format."""

    print("Total packets:", statistics["total_packets"])
    print("Total bytes:", statistics["total_bytes"], "bytes")
    print("Average packet size:", statistics["average_packet_size"], "bytes")
    print("Capture duration:", statistics["capture_duration"], "seconds")
    print(
        "Packets per second:",
        statistics["packets_per_second"],
        "packets/second",
    )

    print("\nProtocol distribution:")
    for protocol, count in statistics["protocol_distribution"].items():
        print(f" {protocol}: {count}")

    display_ranked_counts("Top source IPs", statistics["top_source_ips"])
    display_ranked_counts("Top destination IPs", statistics["top_destination_ips"])
    display_ranked_counts("Top destination ports", statistics["top_destination_ports"])


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

    statistics = calculate_statistics(packet_records)
    display_statistics(statistics)

# Prevent the interactive program from running when tests import its functions.
if __name__ == "__main__":
    main()
