import argparse
import os
import time
from pathlib import Path

import joblib
from scapy.all import PcapReader, sniff
from scapy.interfaces import resolve_iface

from .engine import Engine
from .features import COLUMNS, SCHEMA
from .storage import append, database, meta, status


def run(args):
    db = database()
    meta.create_all(db)
    path = Path(os.environ.get("MODEL_PATH", "model/forest.joblib"))
    model = None
    if path.exists():
        bundle = joblib.load(path)
        if bundle["schema"] != SCHEMA or tuple(bundle["columns"]) != COLUMNS:
            raise ValueError("Model feature contract mismatch")
        model = bundle["model"]
    source = (
        ("Demo replay" if args.demo else "PCAP replay") if args.pcap else "Live capture"
    )
    label = SCHEMA if model else "Rules only"
    pending = []
    engine = Engine(
        lambda kind, body: pending.append((kind, body)),
        model,
        args.window,
        args.scan,
        args.attempts,
    )

    def flush(state):
        with db.begin() as conn:
            for kind, body in pending:
                append(conn, kind, body)
            status(conn, source, state, label)
        pending.clear()

    flush("running")
    try:
        if args.pcap:
            with PcapReader(args.pcap) as packets:
                previous = None
                for pkt in packets:
                    now = float(pkt.time)
                    if previous is not None and args.speed:
                        time.sleep(max(0, now - previous) / args.speed)
                    engine.packet(pkt)
                    if pending:
                        flush("running")
                    previous = now
        else:
            interface = resolve_iface(args.interface)
            socket = interface.l2listen()(iface=interface)
            try:
                while True:
                    sniff(
                        opened_socket=socket,
                        prn=engine.packet,
                        store=False,
                        timeout=1,
                        chainCC=True,
                    )
                    engine.sweep(time.time())
                    flush("running")
            finally:
                socket.close()
    except KeyboardInterrupt:
        pass
    except Exception:
        flush("failed")
        raise
    engine.finish()
    flush("complete")


if __name__ == "__main__":
    p = argparse.ArgumentParser(
        description="Passively monitor a network interface or read a PCAP"
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap")
    group.add_argument("--interface")
    p.add_argument("--demo", action="store_true")
    p.add_argument(
        "--speed",
        type=float,
        default=0,
        help="Replay speed multiplier, 0 for immediate",
    )
    p.add_argument("--window", type=int, default=60)
    p.add_argument("--scan", type=int, default=10)
    p.add_argument("--attempts", type=int, default=8)
    args = p.parse_args()
    if min(args.window, args.scan, args.attempts) < 1 or args.speed < 0:
        p.error("Thresholds must be positive and replay speed nonnegative")
    run(args)
