"""Automated tests for rule-based traffic detections."""

import unittest

from detectors import (
    detect_high_traffic_sources,
    detect_long_dns_queries,
    detect_syn_port_scans,
)


class SynPortScanTests(unittest.TestCase):
    """Verify detection of repeated SYN attempts across unique ports."""

    @staticmethod
    def record(**overrides):
        """Create a minimal normalized record for a detector test."""

        packet_record = {
            "protocol": "TCP",
            "tcp_flags": "S",
            "source_ip": "192.0.2.100",
            "destination_ip": "198.51.100.100",
            "destination_port": 80,
            "timestamp": "2026-09-22T12:00:00+00:00",
        }
        packet_record.update(overrides)
        return packet_record

    def test_detects_route_at_minimum_unique_port_threshold(self):
        records = [
            self.record(destination_port=443),
            self.record(destination_port=22),
            self.record(destination_port=80),
        ]

        detections = detect_syn_port_scans(records, minimum_ports=3)

        self.assertEqual(
            detections,
            [
                {
                    "source_ip": "192.0.2.100",
                    "destination_ip": "198.51.100.100",
                    "ports": [22, 80, 443],
                    "port_count": 3,
                    "timestamp": "2026-09-22T12:00:00+00:00",
                }
            ],
        )

    def test_keeps_first_timestamp_for_route(self):
        records = [
            self.record(
                destination_port=22,
                timestamp="2026-09-22T12:00:00+00:00",
            ),
            self.record(
                destination_port=80,
                timestamp="2026-09-22T12:00:01+00:00",
            ),
        ]

        detections = detect_syn_port_scans(records, minimum_ports=2)

        self.assertEqual(
            detections[0]["timestamp"],
            "2026-09-22T12:00:00+00:00",
        )

    def test_does_not_detect_route_below_threshold(self):
        records = [
            self.record(destination_port=22),
            self.record(destination_port=80),
        ]

        detections = detect_syn_port_scans(records, minimum_ports=3)

        self.assertEqual(detections, [])

    def test_duplicate_attempts_do_not_inflate_unique_port_count(self):
        records = [
            self.record(destination_port=22),
            self.record(destination_port=22),
            self.record(destination_port=80),
        ]

        detections = detect_syn_port_scans(records, minimum_ports=3)

        self.assertEqual(detections, [])

    def test_ignores_non_syn_attempts_and_incomplete_records(self):
        records = [
            self.record(protocol="UDP"),
            self.record(tcp_flags="SA"),
            self.record(tcp_flags="PA"),
            self.record(tcp_flags=None),
            self.record(destination_port=None),
        ]

        detections = detect_syn_port_scans(records, minimum_ports=1)

        self.assertEqual(detections, [])

    def test_keeps_different_routes_separate(self):
        records = [
            self.record(destination_port=22),
            self.record(destination_port=80),
            self.record(destination_ip="203.0.113.100", destination_port=443),
            self.record(destination_ip="203.0.113.100", destination_port=8080),
        ]

        detections = detect_syn_port_scans(records, minimum_ports=2)

        self.assertEqual(len(detections), 2)
        self.assertEqual(detections[0]["ports"], [22, 80])
        self.assertEqual(detections[1]["ports"], [443, 8080])

class LongDnsQueryTests(unittest.TestCase):
    """Verify detection of unusually long DNS query names."""

    @staticmethod
    def record(**overrides):
        """Create a minimal normalized DNS record for a detector test."""

        packet_record = {
            "packet_number": 1,
            "source_ip": "192.0.2.10",
            "dns_message_type": "Query",
            "dns_query": "example.com.",
            "timestamp": "2026-09-22T12:00:00+00:00",
        }
        packet_record.update(overrides)
        return packet_record

    def test_detects_query_at_minimum_length(self):
        query = "a" * 38 + ".example.com."

        detections = detect_long_dns_queries(
            [self.record(dns_query=query)], minimum_length=50
        )

        self.assertEqual(
            detections,
            [
                {
                    "packet_number": 1,
                    "source_ip": "192.0.2.10",
                    "dns_query": query.rstrip("."),
                    "query_length": 50,
                    "timestamp": "2026-09-22T12:00:00+00:00",
                }
            ],
        )

    def test_preserves_triggering_packet_timestamp(self):
        timestamp = "2026-09-22T12:34:56+00:00"

        detections = detect_long_dns_queries(
            [self.record(dns_query="a" * 55 + ".", timestamp=timestamp)],
            minimum_length=50,
        )

        self.assertEqual(detections[0]["timestamp"], timestamp)

    def test_does_not_detect_query_below_threshold(self):
        detections = detect_long_dns_queries(
            [self.record(dns_query="short.example.com.")], minimum_length=50
        )

        self.assertEqual(detections, [])

    def test_ignores_dns_responses_and_missing_queries(self):
        records = [
            self.record(dns_message_type="Response", dns_query="a" * 60 + "."),
            self.record(dns_query=None),
        ]

        detections = detect_long_dns_queries(records, minimum_length=50)

        self.assertEqual(detections, [])

    def test_checks_every_packet_record(self):
        records = [
            self.record(packet_number=1, dns_query="short.example.com."),
            self.record(packet_number=2, dns_query="b" * 55 + "."),
        ]

        detections = detect_long_dns_queries(records, minimum_length=50)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["packet_number"], 2)

class HighTrafficSourceTests(unittest.TestCase):
    """Verify detection of sources contributing many packets."""

    @staticmethod
    def record(
        source_ip="192.0.2.10",
        timestamp="2026-09-22T12:00:00+00:00",
    ):
        """Create the minimal normalized record needed by this detector."""

        return {"source_ip": source_ip, "timestamp": timestamp}

    def test_detects_source_at_minimum_packet_threshold(self):
        records = [self.record() for _ in range(3)]

        detections = detect_high_traffic_sources(records, minimum_packets=3)

        self.assertEqual(
            detections,
            [
                {
                    "source_ip": "192.0.2.10",
                    "packet_count": 3,
                    "timestamp": "2026-09-22T12:00:00+00:00",
                }
            ],
        )

    def test_keeps_first_timestamp_for_source(self):
        records = [
            self.record(timestamp="2026-09-22T12:00:00+00:00"),
            self.record(timestamp="2026-09-22T12:00:01+00:00"),
        ]

        detections = detect_high_traffic_sources(records, minimum_packets=2)

        self.assertEqual(
            detections[0]["timestamp"],
            "2026-09-22T12:00:00+00:00",
        )

    def test_does_not_detect_source_below_threshold(self):
        records = [self.record() for _ in range(2)]

        detections = detect_high_traffic_sources(records, minimum_packets=3)

        self.assertEqual(detections, [])

    def test_counts_sources_separately(self):
        records = [
            self.record("192.0.2.10"),
            self.record("192.0.2.10"),
            self.record("192.0.2.20"),
        ]

        detections = detect_high_traffic_sources(records, minimum_packets=2)

        self.assertEqual(
            detections,
            [
                {
                    "source_ip": "192.0.2.10",
                    "packet_count": 2,
                    "timestamp": "2026-09-22T12:00:00+00:00",
                }
            ],
        )

    def test_ignores_records_without_a_source_ip(self):
        records = [self.record(None), self.record(None)]

        detections = detect_high_traffic_sources(records, minimum_packets=1)

        self.assertEqual(detections, [])

if __name__ == "__main__":
    unittest.main()
