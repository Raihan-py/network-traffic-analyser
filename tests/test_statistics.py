"""Automated tests for aggregate traffic statistics."""

import unittest

from main import (
    calculate_average_packet_size,
    calculate_protocol_distribution,
    calculate_source_ip_counts,
    calculate_total_bytes,
)


class TrafficStatisticsTests(unittest.TestCase):
    """Verify statistics calculated from normalized packet records."""

    def test_total_bytes_adds_every_packet_size(self):
        packet_records = [
            {"packet_size": 40},
            {"packet_size": 28},
            {"packet_size": 28},
        ]

        total_bytes = calculate_total_bytes(packet_records)

        self.assertEqual(total_bytes, 96)

    def test_total_bytes_is_zero_for_an_empty_capture(self):
        total_bytes = calculate_total_bytes([])

        self.assertEqual(total_bytes, 0)

    def test_average_packet_size_uses_total_bytes_and_packet_count(self):
        packet_records = [
            {"packet_size": 40},
            {"packet_size": 28},
            {"packet_size": 28},
        ]

        average_size = calculate_average_packet_size(packet_records)

        self.assertEqual(average_size, 32.0)

    def test_average_packet_size_is_zero_for_an_empty_capture(self):
        average_size = calculate_average_packet_size([])

        self.assertEqual(average_size, 0.0)

    def test_protocol_distribution_counts_repeated_protocols(self):
        packet_records = [
            {"protocol": "TCP"},
            {"protocol": "TCP"},
            {"protocol": "UDP"},
            {"protocol": "ICMP"},
        ]

        distribution = calculate_protocol_distribution(packet_records)

        self.assertEqual(distribution, {"TCP": 2, "UDP": 1, "ICMP": 1})

    def test_protocol_distribution_includes_unknown_protocols(self):
        packet_records = [{"protocol": "N/A"}]

        distribution = calculate_protocol_distribution(packet_records)

        self.assertEqual(distribution, {"N/A": 1})

    def test_protocol_distribution_is_empty_for_an_empty_capture(self):
        distribution = calculate_protocol_distribution([])

        self.assertEqual(distribution, {})

    def test_source_ip_counts_repeated_addresses(self):
        packet_records = [
            {"source_ip": "192.0.2.10"},
            {"source_ip": "192.0.2.10"},
            {"source_ip": "192.0.2.30"},
        ]

        source_counts = calculate_source_ip_counts(packet_records)

        self.assertEqual(source_counts, {"192.0.2.10": 2, "192.0.2.30": 1})

    def test_source_ip_counts_ignore_missing_addresses(self):
        packet_records = [
            {"source_ip": None},
            {"source_ip": "192.0.2.10"},
        ]

        source_counts = calculate_source_ip_counts(packet_records)

        self.assertEqual(source_counts, {"192.0.2.10": 1})

    def test_source_ip_counts_are_empty_for_an_empty_capture(self):
        source_counts = calculate_source_ip_counts([])

        self.assertEqual(source_counts, {})


if __name__ == "__main__":
    unittest.main()
