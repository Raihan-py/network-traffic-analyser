"""Create small, synthetic PCAP files for safely testing the analyser.

The packets are written to disk only; this script does not transmit them.
"""

import time

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, Ether, TCP, UDP, wrpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

# Scapy's / operator stacks protocol layers; it does not mean division here.
# These IPv4 ranges are reserved for documentation and examples.
tcp_packet = (
    IP(src="192.0.2.10", dst="198.51.100.20")
    / TCP(sport=51000, dport=80)
)
udp_packet = (
    IP(src="192.0.2.30", dst="198.51.100.40")
    / UDP(sport=52000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.test"))
)
icmp_packet = (
    IP(src="192.0.2.50", dst="198.51.100.60")
    / ICMP()
)

# ARP carries its own hardware addresses inside an Ethernet frame.
arp_packet = (
    Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
    / ARP(
        hwsrc="02:00:00:00:00:01",
        hwdst="00:00:00:00:00:00",
        psrc="192.0.2.10",
        pdst="192.0.2.1",
    )
)

# 2001:db8::/32 is the IPv6 prefix reserved for documentation.
ipv6_packet = (
    IPv6(src="2001:db8::10", dst="2001:db8::20")
    / TCP(sport=53000, dport=443)
)

dns_response_packet = (
    # A server response reverses the query's IP addresses and UDP ports.
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

http_request_packet = (
    # HTTP is intentionally unencrypted here so its metadata can be decoded.
    IP(src="192.0.2.70", dst="198.51.100.80")
    / TCP(sport=54000, dport=80, flags="PA")
    / HTTP()
    / HTTPRequest(Method=b"GET", Host=b"example.test", Path=b"/index.html")
)

http_response_packet = (
    # Return the synthetic response from server port 80 to the client endpoint.
    IP(src="198.51.100.80", dst="192.0.2.70")
    / TCP(sport=80, dport=54000, flags="PA")
    / HTTP()
    / HTTPResponse(Status_Code=b"200", Reason_Phrase=b"OK")
)

packets = [tcp_packet, udp_packet, dns_response_packet, http_request_packet, http_response_packet, icmp_packet]

base_timestamp = time.time()
tcp_packet.time = base_timestamp
udp_packet.time = base_timestamp + 0.5
dns_response_packet.time = base_timestamp + 0.75
http_request_packet.time = base_timestamp + 1
http_response_packet.time = base_timestamp + 1.125
icmp_packet.time = base_timestamp + 1.25


# wrpcap serializes packets into a capture file without sending network traffic.
wrpcap("sample.pcap", packets)
print("created sample.pcap")

# Keep ARP separate because it uses Ethernet, unlike the raw IP sample.
wrpcap("arp_sample.pcap", [arp_packet])
print("created arp_sample.pcap")

wrpcap("ipv6_sample.pcap", [ipv6_packet])
print("created ipv6_sample.pcap")
