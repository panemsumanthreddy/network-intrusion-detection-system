"""Compare unique directional five-tuples against labeled Tuesday flows in the same UTC minute."""

import argparse
from collections import defaultdict
from datetime import timezone
from itertools import islice

import pandas as pd
from scapy.all import PcapReader

from nids.engine import Engine
from nids.features import COLUMNS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("labels")
    args = parser.parse_args()
    cols = [
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Protocol",
        "Timestamp",
        *COLUMNS,
    ]
    labels = pd.read_parquet(args.labels, columns=cols)
    samples = defaultdict(list)

    def emitted(kind, row):
        if kind == "flow":
            key = (
                row["src"],
                row["sport"],
                row["dst"],
                row["dport"],
                6 if row["protocol"] == "TCP" else 17,
                int(row["start"] // 60),
            )
            samples[key].append(row["features"])

    engine = Engine(emitted)
    with PcapReader(args.pcap) as packets:
        for pkt in islice(packets, 1000):
            engine.packet(pkt)
    engine.finish()
    candidates = defaultdict(list)
    for src, sp, dst, dp, proto, ts, *values in labels.itertuples(
        index=False, name=None
    ):
        key = (
            src,
            sp,
            dst,
            dp,
            proto,
            int(ts.replace(tzinfo=timezone.utc).timestamp() // 60),
        )
        if key in samples:
            candidates[key].append(values)
    pairs = [
        (rows[0], candidates[k][0])
        for k, rows in samples.items()
        if len(rows) == len(candidates[k]) == 1
    ]
    exact = sum(a == b for a, b in pairs)
    print(f"Comparable unique flows: {len(pairs)}; exact feature vectors: {exact}")
    if not exact:
        raise SystemExit("No matching feature vectors")


if __name__ == "__main__":
    main()
