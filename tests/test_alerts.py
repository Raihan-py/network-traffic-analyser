"""Automated tests for structured security alerts."""

import io
import unittest
from contextlib import redirect_stdout

from alerts import (
    create_alert,
    create_high_traffic_source_alert,
    create_long_dns_query_alert,
    create_port_scan_alert,
    create_security_alerts,
)
from main import display_security_alerts


class CreateAlertTests(unittest.TestCase):
    """Verify that alerts always use the standard project schema."""

    def test_creates_alert_with_all_fields(self):
        evidence = {"port_count": 6}

        alert = create_alert(
            alert_type="TCP SYN Port Scan",
            severity="HIGH",
            source_ip="192.0.2.100",
            description="Source contacted several destination ports.",
            timestamp="2026-09-22T12:00:00+00:00",
            evidence=evidence,
        )

        self.assertEqual(
            alert,
            {
                "alert_type": "TCP SYN Port Scan",
                "severity": "HIGH",
                "source_ip": "192.0.2.100",
                "description": "Source contacted several destination ports.",
                "timestamp": "2026-09-22T12:00:00+00:00",
                "evidence": {"port_count": 6},
            },
        )

    def test_replaces_missing_evidence_with_empty_dictionary(self):
        alert = create_alert(
            "Long DNS Query",
            "MEDIUM",
            "192.0.2.90",
            "A DNS query exceeded the configured length threshold.",
            "2026-09-22T12:00:00+00:00",
        )

        self.assertEqual(alert["evidence"], {})

    def test_preserves_provided_evidence_dictionary(self):
        evidence = {"query_length": 63}

        alert = create_alert(
            "Long DNS Query",
            "MEDIUM",
            "192.0.2.90",
            "A DNS query exceeded the configured length threshold.",
            "2026-09-22T12:00:00+00:00",
            evidence,
        )

        self.assertIs(alert["evidence"], evidence)

    def test_default_evidence_is_not_shared_between_alerts(self):
        arguments = (
            "High Traffic Source",
            "MEDIUM",
            "198.51.100.40",
            "A source met the packet-count threshold.",
            "2026-09-22T12:00:00+00:00",
        )
        first_alert = create_alert(*arguments)
        second_alert = create_alert(*arguments)

        first_alert["evidence"]["packet_count"] = 100

        self.assertEqual(second_alert["evidence"], {})


class PortScanAlertTests(unittest.TestCase):
    """Verify conversion of port-scan evidence into a structured alert."""

    def test_creates_high_severity_port_scan_alert(self):
        detection = {
            "source_ip": "192.0.2.100",
            "destination_ip": "198.51.100.100",
            "ports": [22, 80, 443, 3389, 8080, 8443],
            "port_count": 6,
            "timestamp": "2026-09-22T12:00:00+00:00",
        }

        alert = create_port_scan_alert(detection)

        self.assertEqual(alert["alert_type"], "TCP SYN Port Scan")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["source_ip"], "192.0.2.100")
        self.assertEqual(alert["timestamp"], "2026-09-22T12:00:00+00:00")
        self.assertEqual(
            alert["description"],
            "192.0.2.100 contacted 6 unique destination ports "
            "on 198.51.100.100.",
        )
        self.assertEqual(
            alert["evidence"],
            {
                "destination_ip": "198.51.100.100",
                "ports": [22, 80, 443, 3389, 8080, 8443],
                "port_count": 6,
            },
        )


class LongDnsQueryAlertTests(unittest.TestCase):
    """Verify conversion of long-DNS evidence into a structured alert."""

    def test_creates_medium_severity_long_dns_query_alert(self):
        detection = {
            "packet_number": 1,
            "source_ip": "192.0.2.90",
            "dns_query": "a" * 50 + ".example.test",
            "query_length": 63,
            "timestamp": "2026-09-22T12:00:00+00:00",
        }

        alert = create_long_dns_query_alert(detection)

        self.assertEqual(alert["alert_type"], "Long DNS Query")
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["source_ip"], "192.0.2.90")
        self.assertEqual(alert["timestamp"], "2026-09-22T12:00:00+00:00")
        self.assertEqual(
            alert["description"],
            "192.0.2.90 sent a DNS query containing 63 characters.",
        )
        self.assertEqual(
            alert["evidence"],
            {
                "packet_number": 1,
                "dns_query": "a" * 50 + ".example.test",
                "query_length": 63,
            },
        )


class HighTrafficSourceAlertTests(unittest.TestCase):
    """Verify conversion of high-traffic evidence into a structured alert."""

    def test_creates_medium_severity_high_traffic_alert(self):
        detection = {
            "source_ip": "198.51.100.40",
            "packet_count": 100,
            "timestamp": "2026-09-22T12:00:00+00:00",
        }

        alert = create_high_traffic_source_alert(detection)

        self.assertEqual(alert["alert_type"], "High Traffic Source")
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["source_ip"], "198.51.100.40")
        self.assertEqual(alert["timestamp"], "2026-09-22T12:00:00+00:00")
        self.assertEqual(
            alert["description"],
            "198.51.100.40 sent 100 packets during the capture.",
        )
        self.assertEqual(alert["evidence"], {"packet_count": 100})


class SecurityAlertCollectionTests(unittest.TestCase):
    """Verify conversion and collection of all supported detection types."""

    def test_combines_each_detection_type_in_order(self):
        timestamp = "2026-09-22T12:00:00+00:00"
        port_scan_detections = [
            {
                "source_ip": "192.0.2.100",
                "destination_ip": "198.51.100.100",
                "ports": [22, 80, 443],
                "port_count": 3,
                "timestamp": timestamp,
            }
        ]
        long_dns_detections = [
            {
                "packet_number": 4,
                "source_ip": "192.0.2.90",
                "dns_query": "a" * 55,
                "query_length": 55,
                "timestamp": timestamp,
            }
        ]
        high_traffic_detections = [
            {
                "source_ip": "198.51.100.40",
                "packet_count": 100,
                "timestamp": timestamp,
            }
        ]

        alerts = create_security_alerts(
            port_scan_detections,
            long_dns_detections,
            high_traffic_detections,
        )

        self.assertEqual(len(alerts), 3)
        self.assertEqual(
            [alert["alert_type"] for alert in alerts],
            ["TCP SYN Port Scan", "Long DNS Query", "High Traffic Source"],
        )

    def test_returns_empty_list_when_there_are_no_detections(self):
        alerts = create_security_alerts([], [], [])

        self.assertEqual(alerts, [])


class SecurityAlertDisplayTests(unittest.TestCase):
    """Verify consistent terminal output for structured alerts."""

    def test_reports_when_no_alerts_were_generated(self):
        output = io.StringIO()

        with redirect_stdout(output):
            display_security_alerts([])

        self.assertIn("No security alerts generated.", output.getvalue())

    def test_displays_standard_fields_and_readable_evidence_labels(self):
        alerts = [
            {
                "alert_type": "High Traffic Source",
                "severity": "MEDIUM",
                "source_ip": "198.51.100.40",
                "description": "A source met the packet-count threshold.",
                "timestamp": "2026-09-22T12:00:00+00:00",
                "evidence": {
                    "destination_ip": "192.0.2.30",
                    "dns_query": "example.test",
                    "packet_count": 100,
                },
            }
        ]
        output = io.StringIO()

        with redirect_stdout(output):
            display_security_alerts(alerts)

        displayed_text = output.getvalue()
        self.assertIn("Alert 1:", displayed_text)
        self.assertIn("Severity: MEDIUM", displayed_text)
        self.assertIn("Alert type: High Traffic Source", displayed_text)
        self.assertIn("Timestamp: 2026-09-22T12:00:00+00:00", displayed_text)
        self.assertIn("Source IP: 198.51.100.40", displayed_text)
        self.assertIn("Destination IP: 192.0.2.30", displayed_text)
        self.assertIn("DNS query: example.test", displayed_text)
        self.assertIn("Packet count: 100", displayed_text)


if __name__ == "__main__":
    unittest.main()
