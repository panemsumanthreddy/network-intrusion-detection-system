"""Feature contract for CIC flow CSVs and Scapy flow summaries."""

SCHEMA = "cic-directional-v1"
COLUMNS = ("Flow Duration", "Total Fwd Packets", "Total Backward Packets")


def vector(duration_us, forward, backward):
    return [max(0, int(duration_us)), int(forward), int(backward)]
