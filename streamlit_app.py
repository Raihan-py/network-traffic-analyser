"""Streamlit dashboard for exploring analysed network traffic."""

from io import BytesIO

import streamlit as st
from scapy.all import rdpcap
from scapy.error import Scapy_Exception

from main import parse_packet, calculate_statistics
from alerts import create_security_alerts
from dashboard_utils import create_packet_csv
from detectors import detect_syn_port_scans, detect_long_dns_queries, detect_high_traffic_sources

st.set_page_config(
    page_title="Network Traffic Analyser",
    page_icon=":material/security:",
    layout="wide",
)


@st.cache_data(max_entries=5, show_spinner="Reading capture...")
def load_capture(file_bytes):
    """Read uploaded capture bytes into a cached Scapy packet collection."""

    capture_stream = BytesIO(file_bytes)
    return rdpcap(capture_stream)


st.title("Network traffic analyser")
st.caption(
    "Upload a PCAP file to explore traffic statistics and security alerts."
)

uploaded_file = st.file_uploader(
    "Choose a PCAP file",
    type=["pcap", "pcapng"],
    key="pcap_upload",
    help=(
        "Upload traffic captured from a system or network you are authorised to analyse."
    ),
    max_upload_size=50,
)

if uploaded_file is None:
    st.info("Upload a PCAP or PCAPNG file to begin analysis.")
    st.stop()

uploaded_file_bytes = uploaded_file.getvalue()

try:
    packets = load_capture(uploaded_file_bytes)
except Scapy_Exception:
    st.error("The uploaded file is not a valid PCAP or PCAPNG")
    st.stop()

st.success(f"Loaded {len(packets)} packets from {uploaded_file.name}.")

packet_records = []

for packet_number, packet in enumerate(packets, start=1):
    packet_record = parse_packet(packet, packet_number)
    packet_records.append(packet_record)

statistics = calculate_statistics(packet_records)
port_scans = detect_syn_port_scans(packet_records)
long_dns_queries = detect_long_dns_queries(packet_records)
high_traffic_sources = detect_high_traffic_sources(packet_records)
security_alerts = create_security_alerts(port_scans, long_dns_queries, high_traffic_sources)

st.subheader("Capture overview")
with st.container(horizontal=True):
    st.metric("Total packets", statistics["total_packets"], border=True)
    st.metric("Total bytes", f"{statistics['total_bytes']:,}", border=True)
    st.metric(
        "Capture duration",
        f"{statistics['capture_duration']:.2f} s",
        border=True,
    )
    st.metric(
        "Packets per second",
        f"{statistics['packets_per_second']:.2f}",
        border=True,
    )

st.subheader("Protocol distribution")
protocol_chart_data = []
for protocol, count in statistics["protocol_distribution"].items():
    protocol_row = {"Protocol": protocol, "Packets": count}
    protocol_chart_data.append(protocol_row)

st.bar_chart(protocol_chart_data, x="Protocol", y="Packets")

st.subheader("Traffic rankings")
source_column, destination_column, port_column = st.columns(3, border=True)

with source_column:
    st.markdown("**Top source IPs**")
    source_ip_rows = []
    for source_ip, count in statistics["top_source_ips"]:
        source_ip_row = {"Source IP": source_ip, "Packets": count}
        source_ip_rows.append(source_ip_row)
    st.table(source_ip_rows, border="horizontal")

with destination_column:
    st.markdown("**Top destination IPs**")
    destination_ip_rows = []
    for destination_ip, count in statistics["top_destination_ips"]:
        destination_ip_row = {"Destination IP": destination_ip, "Packets": count}
        destination_ip_rows.append(destination_ip_row)
    st.table(destination_ip_rows, border="horizontal")

with port_column:
    st.markdown("**Top destination ports**")
    destination_port_rows = []
    for destination_port, count in statistics["top_destination_ports"]:
        destination_port_row = {
            "Destination port": str(destination_port),
            "Packets": count,
        }
        destination_port_rows.append(destination_port_row)
    st.table(destination_port_rows, border="horizontal")

st.subheader("Security alerts")
if not security_alerts:
    st.success("No security alerts detected")
else:
    st.warning(f"Security alerts detected: {len(security_alerts)}")
    for count, alert in enumerate(security_alerts, start=1):
        alert_label = (
            f"Alert {count} - {alert['severity']} - {alert['alert_type']}"
        )
        with st.expander(alert_label):
            st.write(alert["description"])
            st.markdown(f"**Source IP:** {alert['source_ip']}")
            st.caption(f"Timestamp: {alert['timestamp']}")
            st.markdown("**Evidence**")
            for name, value in alert["evidence"].items():
                readable_name = name.replace("_", " ").title()
                st.markdown(f"- **{readable_name}:** {value}")

st.subheader("Packet details")
packet_columns = [
    "packet_number",
    "timestamp",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "application_protocol",
    "packet_size",
    "tcp_flags",
]

packet_column_config = {
    "packet_number": "Packet number",
    "timestamp": "Timestamp (UTC)",
    "source_ip": "Source IP",
    "source_port": "Source port",
    "destination_ip": "Destination IP",
    "destination_port": "Destination port",
    "protocol": "Protocol",
    "application_protocol": "Application protocol",
    "packet_size": "Size (bytes)",
    "tcp_flags": "TCP flags",
}

available_protocols = sorted({record["protocol"] for record in packet_records})
selected_protocols = st.pills(
    label="Protocols",
    options=available_protocols,
    default=available_protocols,
    selection_mode="multi",
)
filtered_packet_records = []
for record in packet_records:
    if record["protocol"] in selected_protocols:
        filtered_packet_records.append(record)

st.dataframe(
    data=filtered_packet_records,
    hide_index=True,
    height="auto",
    column_order=packet_columns,
    column_config=packet_column_config,
)

csv_data = create_packet_csv(filtered_packet_records, packet_columns)
st.download_button(
    label="Download filtered packets",
    data=csv_data,
    file_name="filtered_packets.csv",
    mime="text/csv",
    on_click="ignore",
    icon=":material/download:",
    disabled=not filtered_packet_records,
)
