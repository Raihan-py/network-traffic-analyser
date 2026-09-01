# Network Traffic Analyser

A Python cybersecurity learning project for reading PCAP files, decoding packet
layers with Scapy, and turning packets into consistent records for traffic
analysis and security detection.

The project currently focuses on offline, controlled PCAP analysis. It does not
capture or transmit live network traffic.

## Current status

Stages 1 and 2 are functionally complete. The analyser currently supports:

- Reading a user-selected PCAP file
- IPv4 and IPv6 source and destination addresses
- TCP and UDP source and destination ports
- TCP, UDP, ICMP, and ARP identification
- Packet sizes and UTC timestamps
- Consistent dictionary records for different protocols
- Friendly errors for missing or invalid capture files
- Synthetic test captures that do not send network traffic
- Total traffic volume and average packet size
- Protocol distribution
- Most active source and destination IP addresses
- Most frequently used destination ports
- Capture duration and packets-per-second rate
- Automated parser and statistics tests using Python's built-in `unittest`

## Project structure

```text
network_traffic_analyser/
|-- main.py                    # Parser, statistics, and terminal output
|-- create_sample.py           # Generates safe synthetic test captures
|-- requirements.txt           # Python dependency versions
|-- tests/
|   |-- test_packet_parser.py  # Automated parser tests
|   `-- test_statistics.py     # Automated statistics and output tests
`-- README.md
```

Generated `.pcap` files and the local virtual environment are intentionally
excluded from Git. Real packet captures may contain sensitive addresses,
hostnames, DNS queries, or payload data and should not be committed casually.

## Requirements

- Python 3.12 (the version currently tested)
- Scapy 2.7.0

## Setup

Clone the repository and enter its directory:

```powershell
git clone https://github.com/Raihan-py/network-traffic-analyser.git
cd network-traffic-analyser
```

Create and activate a virtual environment on Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependency:

```powershell
python -m pip install -r requirements.txt
```

## Create safe sample captures

Generate controlled sample PCAPs:

```powershell
python create_sample.py
```

This creates separate IPv4, IPv6, and ARP captures. Scapy's `/` operator in the
generator stacks packet layers; none of these packets are transmitted.

## Run the analyser

```powershell
python main.py
```

When prompted, enter one of the generated filenames, for example:

```text
sample.pcap
```

Other generated examples are `ipv6_sample.pcap` and `arp_sample.pcap`.

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The tests construct packets in memory and verify normalized records for IPv4,
IPv6, TCP, UDP, ICMP, and ARP. They also verify aggregate statistics, edge cases,
rankings, and formatted statistics output. They do not send network traffic.

## Safety and scope

Only analyse traffic from your own systems, lab environments, or networks for
which you have explicit authorization. Live capture is deliberately deferred
until the offline analyser and detection rules are well understood.

Scapy may display `No libpcap provider available` on Windows. This does not block
the current synthetic-packet or basic offline-PCAP exercises. Live capture and
its platform-specific dependencies will be addressed in a later stage.

## Roadmap

- [x] Stage 1: PCAP packet reader and normalized packet records
- [x] Stage 2: Traffic statistics
- [ ] Stage 3: Protocol analysis, including DNS and appropriate HTTP metadata
- [ ] Stage 4: Understandable rule-based security detection
- [ ] Stage 5: Structured security alerts
- [ ] Stage 6: Dashboard
- [ ] Stage 7: Authorized live traffic analysis
