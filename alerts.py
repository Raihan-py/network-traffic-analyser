"""Create consistent security alerts from rule-based detection results."""


def create_alert(
    alert_type,
    severity,
    source_ip,
    description,
    timestamp,
    evidence=None,
):
    """Return one security alert using the project's standard schema."""

    if evidence is None:
        evidence = {}

    alert = {
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "description": description,
        "timestamp": timestamp,
        "evidence": evidence,
    }

    return alert


def create_port_scan_alert(detection):
    """Convert a TCP SYN port-scan detection into a structured alert."""

    source_ip = detection["source_ip"]
    destination_ip = detection["destination_ip"]
    ports = detection["ports"]
    port_count = detection["port_count"]
    timestamp = detection["timestamp"]

    evidence = {
        "destination_ip": destination_ip,
        "ports": ports,
        "port_count": port_count,
    }

    description = (
        f"{source_ip} contacted {port_count} unique destination ports "
        f"on {destination_ip}."
    )

    return create_alert(
        alert_type="TCP SYN Port Scan",
        severity="HIGH",
        source_ip=source_ip,
        description=description,
        timestamp=timestamp,
        evidence=evidence,
    )


def create_long_dns_query_alert(detection):
    """Convert a long DNS query detection into a structured alert."""

    packet_number = detection["packet_number"]
    source_ip = detection["source_ip"]
    dns_query = detection["dns_query"]
    query_length = detection["query_length"]
    timestamp = detection["timestamp"]

    evidence = {
        "packet_number": packet_number,
        "dns_query": dns_query,
        "query_length": query_length,
    }

    description = (
        f"{source_ip} sent a DNS query containing "
        f"{query_length} characters."
    )

    return create_alert(
        alert_type="Long DNS Query",
        severity="MEDIUM",
        source_ip=source_ip,
        description=description,
        timestamp=timestamp,
        evidence=evidence,
    )


def create_high_traffic_source_alert(detection):
    """Convert a high-traffic source detection into a structured alert."""

    source_ip = detection["source_ip"]
    packet_count = detection["packet_count"]
    timestamp = detection["timestamp"]

    evidence = {
        "packet_count": packet_count,
    }

    description = (
        f"{source_ip} sent {packet_count} packets during the capture."
    )

    return create_alert(
        alert_type="High Traffic Source",
        severity="MEDIUM",
        source_ip=source_ip,
        description=description,
        timestamp=timestamp,
        evidence=evidence,
    )


def create_security_alerts(
    port_scan_detections,
    long_dns_query_detections,
    high_traffic_detections,
):
    """Convert and combine all supported detections into structured alerts."""

    security_alerts = []

    for port_scan in port_scan_detections:
        port_scan_alert = create_port_scan_alert(port_scan)
        security_alerts.append(port_scan_alert)

    for long_dns in long_dns_query_detections:
        long_dns_alert = create_long_dns_query_alert(long_dns)
        security_alerts.append(long_dns_alert)

    for high_traffic in high_traffic_detections:
        high_traffic_alert = create_high_traffic_source_alert(high_traffic)
        security_alerts.append(high_traffic_alert)

    return security_alerts
