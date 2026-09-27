"""Pure data helpers used by the Streamlit dashboard."""

import csv
from io import StringIO


def create_packet_csv(packet_records, fieldnames):
    """Return selected packet-record fields as CSV text.

    Fields not listed in ``fieldnames`` are deliberately omitted so the
    exported data matches the columns visible in the dashboard.
    """

    csv_buffer = StringIO()
    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=fieldnames,
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(packet_records)
    return csv_buffer.getvalue()
