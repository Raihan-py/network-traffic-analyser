"""Automated tests for aggregate traffic statistics."""

import io
import unittest
from contextlib import redirect_stdout

from main import (
    calculate_average_packet_size,
    calculate_capture_duration,
    calculate_destination_ip_counts,
    calculate_destination_port_counts,
    calculate_packets_per_second,
    calculate_protocol_distribution,
    calculate_source_ip_counts,
    calculate_statistics,
    calculate_total_bytes,
    display_ranked_counts,
    display_statistics,
    get_top_counts,
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

    def test_destination_ip_counts_repeated_addresses(self):
        packet_records = [
            {"destination_ip": "198.51.100.20"},
            {"destination_ip": "198.51.100.20"},
            {"destination_ip": "198.51.100.40"},
        ]

        destination_counts = calculate_destination_ip_counts(packet_records)

        self.assertEqual(
            destination_counts,
            {"198.51.100.20": 2, "198.51.100.40": 1},
        )

    def test_destination_ip_counts_ignore_missing_addresses(self):
        packet_records = [
            {"destination_ip": None},
            {"destination_ip": "198.51.100.20"},
        ]

        destination_counts = calculate_destination_ip_counts(packet_records)

        self.assertEqual(destination_counts, {"198.51.100.20": 1})

    def test_destination_ip_counts_are_empty_for_an_empty_capture(self):
        destination_counts = calculate_destination_ip_counts([])

        self.assertEqual(destination_counts, {})

    def test_destination_port_counts_repeated_ports(self):
        packet_records = [
            {"destination_port": 443},
            {"destination_port": 443},
            {"destination_port": 53},
        ]

        port_counts = calculate_destination_port_counts(packet_records)

        self.assertEqual(port_counts, {443: 2, 53: 1})

    def test_destination_port_counts_ignore_missing_ports(self):
        packet_records = [
            {"destination_port": None},
            {"destination_port": 80},
        ]

        port_counts = calculate_destination_port_counts(packet_records)

        self.assertEqual(port_counts, {80: 1})

    def test_destination_port_counts_are_empty_for_an_empty_capture(self):
        port_counts = calculate_destination_port_counts([])

        self.assertEqual(port_counts, {})

    def test_top_counts_are_sorted_from_highest_to_lowest(self):
        counts = {"host-a": 2, "host-b": 7, "host-c": 4}

        top_counts = get_top_counts(counts)

        self.assertEqual(top_counts, [("host-b", 7), ("host-c", 4), ("host-a", 2)])

    def test_top_counts_respect_a_custom_limit(self):
        counts = {"host-a": 2, "host-b": 7, "host-c": 4}

        top_counts = get_top_counts(counts, limit=2)

        self.assertEqual(top_counts, [("host-b", 7), ("host-c", 4)])

    def test_top_counts_default_to_five_results(self):
        counts = {f"host-{number}": number for number in range(1, 8)}

        top_counts = get_top_counts(counts)

        self.assertEqual(len(top_counts), 5)
        self.assertEqual(top_counts[0], ("host-7", 7))

    def test_top_counts_preserve_input_order_when_counts_are_tied(self):
        counts = {"host-a": 2, "host-b": 2}

        top_counts = get_top_counts(counts)

        self.assertEqual(top_counts, [("host-a", 2), ("host-b", 2)])

    def test_top_counts_are_empty_when_counts_are_empty(self):
        top_counts = get_top_counts({})

        self.assertEqual(top_counts, [])

    def test_capture_duration_uses_earliest_and_latest_timestamps(self):
        packet_records = [
            {"timestamp": "2026-08-31T12:00:03+00:00"},
            {"timestamp": "2026-08-31T12:00:00+00:00"},
            {"timestamp": "2026-08-31T12:00:01+00:00"},
        ]

        duration = calculate_capture_duration(packet_records)

        self.assertEqual(duration, 3.0)

    def test_capture_duration_preserves_fractional_seconds(self):
        packet_records = [
            {"timestamp": "2026-08-31T12:00:00.250000+00:00"},
            {"timestamp": "2026-08-31T12:00:01.750000+00:00"},
        ]

        duration = calculate_capture_duration(packet_records)

        self.assertEqual(duration, 1.5)

    def test_capture_duration_is_zero_for_identical_timestamps(self):
        packet_records = [
            {"timestamp": "2026-08-31T12:00:00+00:00"},
            {"timestamp": "2026-08-31T12:00:00+00:00"},
        ]

        duration = calculate_capture_duration(packet_records)

        self.assertEqual(duration, 0.0)

    def test_capture_duration_is_zero_with_fewer_than_two_packets(self):
        one_record = [{"timestamp": "2026-08-31T12:00:00+00:00"}]

        self.assertEqual(calculate_capture_duration(one_record), 0.0)
        self.assertEqual(calculate_capture_duration([]), 0.0)

    def test_packets_per_second_uses_packet_count_and_duration(self):
        packet_records = [
            {"timestamp": "2026-08-31T12:00:00+00:00"},
            {"timestamp": "2026-08-31T12:00:00.500000+00:00"},
            {"timestamp": "2026-08-31T12:00:01+00:00"},
        ]

        packet_rate = calculate_packets_per_second(packet_records)

        self.assertEqual(packet_rate, 3.0)

    def test_packets_per_second_supports_fractional_durations(self):
        packet_records = [
            {"timestamp": "2026-08-31T12:00:00+00:00"},
            {"timestamp": "2026-08-31T12:00:02+00:00"},
        ]

        packet_rate = calculate_packets_per_second(packet_records)

        self.assertEqual(packet_rate, 1.0)

    def test_packets_per_second_is_zero_for_identical_timestamps(self):
        packet_records = [
            {"timestamp": "2026-08-31T12:00:00+00:00"},
            {"timestamp": "2026-08-31T12:00:00+00:00"},
        ]

        packet_rate = calculate_packets_per_second(packet_records)

        self.assertEqual(packet_rate, 0.0)

    def test_packets_per_second_is_zero_with_fewer_than_two_packets(self):
        one_record = [{"timestamp": "2026-08-31T12:00:00+00:00"}]

        self.assertEqual(calculate_packets_per_second(one_record), 0.0)
        self.assertEqual(calculate_packets_per_second([]), 0.0)

    def test_statistics_combine_all_capture_metrics(self):
        packet_records = [
            {
                "timestamp": "2026-08-31T12:00:00+00:00",
                "packet_size": 40,
                "protocol": "TCP",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 80,
            },
            {
                "timestamp": "2026-08-31T12:00:00.500000+00:00",
                "packet_size": 28,
                "protocol": "UDP",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.40",
                "destination_port": 80,
            },
            {
                "timestamp": "2026-08-31T12:00:01+00:00",
                "packet_size": 28,
                "protocol": "ICMP",
                "source_ip": "192.0.2.30",
                "destination_ip": "198.51.100.20",
                "destination_port": None,
            },
        ]

        statistics = calculate_statistics(packet_records)

        self.assertEqual(statistics["total_packets"], 3)
        self.assertEqual(statistics["total_bytes"], 96)
        self.assertEqual(statistics["average_packet_size"], 32.0)
        self.assertEqual(
            statistics["protocol_distribution"],
            {"TCP": 1, "UDP": 1, "ICMP": 1},
        )
        self.assertEqual(
            statistics["top_source_ips"],
            [("192.0.2.10", 2), ("192.0.2.30", 1)],
        )
        self.assertEqual(
            statistics["top_destination_ips"],
            [("198.51.100.20", 2), ("198.51.100.40", 1)],
        )
        self.assertEqual(statistics["top_destination_ports"], [(80, 2)])
        self.assertEqual(statistics["capture_duration"], 1.0)
        self.assertEqual(statistics["packets_per_second"], 3.0)

    def test_statistics_return_safe_defaults_for_an_empty_capture(self):
        statistics = calculate_statistics([])

        self.assertEqual(
            statistics,
            {
                "total_packets": 0,
                "total_bytes": 0,
                "average_packet_size": 0.0,
                "protocol_distribution": {},
                "top_source_ips": [],
                "top_destination_ips": [],
                "top_destination_ports": [],
                "capture_duration": 0.0,
                "packets_per_second": 0.0,
            },
        )

    def test_display_ranked_counts_prints_heading_and_entries(self):
        output = io.StringIO()

        with redirect_stdout(output):
            display_ranked_counts("Top source IPs", [("192.0.2.10", 2)])

        self.assertEqual(output.getvalue(), "\nTop source IPs:\n 192.0.2.10: 2\n")

    def test_display_statistics_prints_metrics_and_rankings(self):
        statistics = {
            "total_packets": 3,
            "total_bytes": 96,
            "average_packet_size": 32.0,
            "protocol_distribution": {"TCP": 1},
            "top_source_ips": [("192.0.2.10", 1)],
            "top_destination_ips": [("198.51.100.20", 1)],
            "top_destination_ports": [(80, 1)],
            "capture_duration": 1.0,
            "packets_per_second": 3.0,
        }
        output = io.StringIO()

        with redirect_stdout(output):
            display_statistics(statistics)

        displayed_text = output.getvalue()
        self.assertIn("Average packet size: 32.0 bytes", displayed_text)
        self.assertIn("Capture duration: 1.0 seconds", displayed_text)
        self.assertIn("Packets per second: 3.0 packets/second", displayed_text)
        self.assertIn("Top destination ports:\n 80: 1", displayed_text)


if __name__ == "__main__":
    unittest.main()
