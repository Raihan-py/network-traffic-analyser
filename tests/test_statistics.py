"""Automated tests for aggregate traffic statistics."""

import unittest

from main import calculate_average_packet_size, calculate_total_bytes


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


if __name__ == "__main__":
    unittest.main()
