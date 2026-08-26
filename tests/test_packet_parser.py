"""Automated tests for converting Scapy packets into normalized records."""

import unittest

from scapy.all import ARP, ICMP, IP, IPv6, Ether, TCP, UDP

from main import parse_packet


EXPECTED_KEYS = {
    "packet_number",
    "timestamp",
    "packet_size",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
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
