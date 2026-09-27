"""Tests for pure dashboard data helpers."""

import csv
import unittest
from io import StringIO

from dashboard_utils import create_packet_csv


class DashboardCsvTests(unittest.TestCase):
    """Verify packet records are exported as predictable CSV text."""

    def test_create_packet_csv_keeps_selected_fields_in_order(self):
        records = [
            {
                "packet_number": 1,
                "protocol": "TCP",
                "packet_size": 40,
                "dns_query": "ignored.example",
            },
            {
                "packet_number": 2,
                "protocol": "UDP",
                "packet_size": 28,
                "dns_query": None,
            },
        ]
        fieldnames = ["packet_number", "protocol", "packet_size"]

        csv_text = create_packet_csv(records, fieldnames)
        reader = csv.DictReader(StringIO(csv_text))

        self.assertEqual(reader.fieldnames, fieldnames)
        self.assertEqual(
            list(reader),
            [
                {
                    "packet_number": "1",
                    "protocol": "TCP",
                    "packet_size": "40",
                },
                {
                    "packet_number": "2",
                    "protocol": "UDP",
                    "packet_size": "28",
                },
            ],
        )

    def test_create_packet_csv_with_no_records_still_has_header(self):
        csv_text = create_packet_csv([], ["packet_number", "protocol"])

        self.assertEqual(csv_text, "packet_number,protocol\r\n")


if __name__ == "__main__":
    unittest.main()
