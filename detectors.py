"""Explainable rule-based detections for normalized packet records."""


def detect_syn_port_scans(packet_records, minimum_ports=5):
    """Return routes that receive SYN attempts on many unique ports."""

    syn_ports_by_route = {}
    for packet_record in packet_records:
        if packet_record["protocol"] != "TCP":
            continue
        tcp_flags = packet_record["tcp_flags"]
        if tcp_flags is None:
            continue
        if "S" not in tcp_flags:
            continue
        if "A" in tcp_flags:
            continue

        source_ip = packet_record["source_ip"]
        destination_ip = packet_record["destination_ip"]
        destination_port = packet_record["destination_port"]

        if source_ip is None or destination_ip is None or destination_port is None:
            continue

        route = (source_ip, destination_ip)
        syn_ports_by_route.setdefault(route, set()).add(destination_port)

    detections = []
    for (source_ip, destination_ip), ports in syn_ports_by_route.items():
        if len(ports) < minimum_ports:
            continue
        detections.append(
            {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "ports": sorted(ports),
                "port_count": len(ports),
            }
        )

    return detections

def detect_long_dns_queries(packet_records, minimum_length=50):
    """Return DNS queries whose names meet the suspicious length threshold."""

    detections = []
    for packet_record in packet_records:
        if packet_record["dns_message_type"] != "Query":
            continue
        dns_query = packet_record["dns_query"]
        if dns_query is None:
            continue

        clean_query = dns_query.rstrip(".")
        query_length = len(clean_query)

        if query_length >= minimum_length:
            detection = {
                "packet_number": packet_record["packet_number"],
                "source_ip": packet_record["source_ip"],
                "dns_query": clean_query,
                "query_length": query_length,
            }
            detections.append(detection)

    return detections

def detect_high_traffic_sources(packet_records, minimum_packets=100):
    """Return source IPs whose packet counts meet the high-traffic threshold."""

    source_packet_counts = {}
    for packet_record in packet_records:
        source_ip = packet_record["source_ip"]
        if source_ip is None:
            continue

        source_packet_counts[source_ip] = (
            source_packet_counts.get(source_ip, 0) + 1
        )

    detections = []
    for source_ip, packet_count in source_packet_counts.items():
        if packet_count >= minimum_packets:
            detection = {
                "source_ip": source_ip,
                "packet_count": packet_count,
            }
            detections.append(detection)
    return detections
