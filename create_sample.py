"""Create small, synthetic PCAP files for safely testing the analyser."""

from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP, wrpcap

# These IP ranges are reserved for documentation and examples.
tcp_packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=51000, dport=80)
udp_packet = IP(src="192.0.2.30", dst="198.51.100.40") / UDP(sport=52000, dport=53)
icmp_packet = IP(src="192.0.2.50", dst="198.51.100.60") / ICMP()

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

packets = [tcp_packet, udp_packet,icmp_packet]

wrpcap("sample.pcap", packets)
print("created sample.pcap")

# Keep ARP separate because it uses Ethernet, unlike the raw IP sample.
wrpcap("arp_sample.pcap", [arp_packet])
print("created arp_sample.pcap")
