"""Automated tests for converting Scapy packets into normalized records."""

import io
import unittest
from contextlib import redirect_stdout

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, Ether, TCP, UDP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from main import display_packet, parse_packet


EXPECTED_KEYS = {
    "packet_number",
    "timestamp",
    "packet_size",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "application_protocol",
    "dns_query",
    "dns_message_type",
    "dns_answer",
    "http_method",
    "http_host",
    "http_path",
    "http_message_type",
    "http_status_code",
    "http_reason",
}


class ParsePacketTests(unittest.TestCase):
    """Verify that common packet types produce predictable records."""

    @staticmethod
    def parse(packet, packet_number=1):
        """Give a packet a fixed time, then parse it for deterministic tests."""

        # A constant timestamp prevents test results changing with the clock.
        packet.time = 1_700_000_000.0
        return parse_packet(packet, packet_number)

    def test_ipv4_tcp_packet(self):
        packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
            sport=51000,
            dport=80,
        )

        record = self.parse(packet, packet_number=3)

        self.assertEqual(record["packet_number"], 3)
        self.assertEqual(record["source_ip"], "192.0.2.10")
        self.assertEqual(record["destination_ip"], "198.51.100.20")
        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["source_port"], 51000)
        self.assertEqual(record["destination_port"], 80)
        self.assertEqual(record["packet_size"], 40)

    def test_ipv4_udp_packet(self):
        packet = IP(src="192.0.2.30", dst="198.51.100.40") / UDP(
            sport=52000,
            dport=53,
        )

        record = self.parse(packet)

        self.assertEqual(record["protocol"], "UDP")
        self.assertEqual(record["source_port"], 52000)
        self.assertEqual(record["destination_port"], 53)
        self.assertEqual(record["packet_size"], 28)
        self.assertIsNone(record["application_protocol"])
        self.assertIsNone(record["dns_query"])

    def test_dns_query_preserves_udp_and_extracts_domain(self):
        packet = (
            IP(src="192.0.2.30", dst="198.51.100.40")
            / UDP(sport=52000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.test"))
        )

        record = self.parse(packet)

        self.assertEqual(record["protocol"], "UDP")
        self.assertEqual(record["application_protocol"], "DNS")
        self.assertEqual(record["dns_query"], "example.test.")
        self.assertEqual(record["dns_message_type"], "Query")
        self.assertIsNone(record["dns_answer"])

    def test_dns_response_extracts_answer(self):
        packet = (
            IP(src="198.51.100.40", dst="192.0.2.30")
            / UDP(sport=53, dport=52000)
            / DNS(
                qr=1,
                qd=DNSQR(qname="example.test"),
                an=DNSRR(
                    rrname="example.test",
                    type="A",
                    rdata="203.0.113.10",
                ),
            )
        )

        record = self.parse(packet)

        self.assertEqual(record["protocol"], "UDP")
        self.assertEqual(record["source_port"], 53)
        self.assertEqual(record["destination_port"], 52000)
        self.assertEqual(record["application_protocol"], "DNS")
        self.assertEqual(record["dns_message_type"], "Response")
        self.assertEqual(record["dns_query"], "example.test.")
        self.assertEqual(record["dns_answer"], "203.0.113.10")

    def test_http_request_extracts_method_host_and_path(self):
        packet = (
            IP(src="192.0.2.70", dst="198.51.100.80")
            / TCP(sport=54000, dport=80, flags="PA")
            / HTTP()
            / HTTPRequest(
                Method=b"GET",
                Host=b"example.test",
                Path=b"/index.html",
            )
        )

        record = self.parse(packet)

        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["application_protocol"], "HTTP")
        self.assertEqual(record["http_method"], "GET")
        self.assertEqual(record["http_host"], "example.test")
        self.assertEqual(record["http_path"], "/index.html")
        self.assertEqual(record["http_message_type"], "Request")
        self.assertIsNone(record["http_status_code"])
        self.assertIsNone(record["http_reason"])

    def test_http_response_extracts_status_and_reason(self):
        packet = (
            IP(src="198.51.100.80", dst="192.0.2.70")
            / TCP(sport=80, dport=54000, flags="PA")
            / HTTP()
            / HTTPResponse(Status_Code=b"200", Reason_Phrase=b"OK")
        )

        record = self.parse(packet)

        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["source_port"], 80)
        self.assertEqual(record["destination_port"], 54000)
        self.assertEqual(record["application_protocol"], "HTTP")
        self.assertEqual(record["http_message_type"], "Response")
        self.assertEqual(record["http_status_code"], "200")
        self.assertEqual(record["http_reason"], "OK")
        self.assertIsNone(record["http_method"])

    def test_display_packet_prints_http_metadata(self):
        packet = (
            IP(src="192.0.2.70", dst="198.51.100.80")
            / TCP(sport=54000, dport=80, flags="PA")
            / HTTP()
            / HTTPRequest(
                Method=b"GET",
                Host=b"example.test",
                Path=b"/index.html",
            )
        )
        record = self.parse(packet)
        output = io.StringIO()

        with redirect_stdout(output):
            display_packet(record)

        displayed_text = output.getvalue()
        self.assertIn("Application protocol: HTTP", displayed_text)
        self.assertIn("HTTP method: GET", displayed_text)
        self.assertIn("HTTP host: example.test", displayed_text)
        self.assertIn("HTTP path: /index.html", displayed_text)
        self.assertIn("HTTP message type: Request", displayed_text)

    def test_display_packet_prints_http_response_metadata(self):
        packet = (
            IP(src="198.51.100.80", dst="192.0.2.70")
            / TCP(sport=80, dport=54000, flags="PA")
            / HTTP()
            / HTTPResponse(Status_Code=b"200", Reason_Phrase=b"OK")
        )
        record = self.parse(packet)
        output = io.StringIO()

        with redirect_stdout(output):
            display_packet(record)

        displayed_text = output.getvalue()
        self.assertIn("Application protocol: HTTP", displayed_text)
        self.assertIn("HTTP status code: 200", displayed_text)
        self.assertIn("HTTP reason: OK", displayed_text)
        self.assertIn("HTTP message type: Response", displayed_text)

    def test_icmp_packet_has_no_ports(self):
        packet = IP(src="192.0.2.50", dst="198.51.100.60") / ICMP()

        record = self.parse(packet)

        self.assertEqual(record["protocol"], "ICMP")
        self.assertIsNone(record["source_port"])
        self.assertIsNone(record["destination_port"])

    def test_ipv6_tcp_packet(self):
        packet = IPv6(src="2001:db8::10", dst="2001:db8::20") / TCP(
            sport=53000,
            dport=443,
        )

        record = self.parse(packet)

        self.assertEqual(record["source_ip"], "2001:db8::10")
        self.assertEqual(record["destination_ip"], "2001:db8::20")
        self.assertEqual(record["protocol"], "TCP")
        self.assertEqual(record["packet_size"], 60)

    def test_arp_packet_uses_protocol_addresses(self):
        packet = Ether() / ARP(psrc="192.0.2.10", pdst="192.0.2.1")

        record = self.parse(packet)

        self.assertEqual(record["protocol"], "ARP")
        self.assertEqual(record["source_ip"], "192.0.2.10")
        self.assertEqual(record["destination_ip"], "192.0.2.1")
        self.assertIsNone(record["source_port"])
        self.assertIsNone(record["destination_port"])

    def test_every_record_has_the_same_keys_and_utc_timestamp(self):
        packet = IP(src="192.0.2.10", dst="198.51.100.20") / UDP()

        record = self.parse(packet)

        self.assertEqual(set(record), EXPECTED_KEYS)
        self.assertEqual(record["timestamp"], "2023-11-14T22:13:20+00:00")


if __name__ == "__main__":
    unittest.main()
