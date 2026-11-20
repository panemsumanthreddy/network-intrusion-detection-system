"""Generate an offline, header-only fixture. All IP addresses are documentation addresses."""

from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether, wrpcap

packets = []


def add(t, src, dst, segment):
    pkt = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src=src, dst=dst)
        / segment
    )
    pkt.time = 1735689600 + t
    packets.append(pkt)


for i in range(96):
    t = i * 1.1
    client = f"192.0.2.{1 + i % 7}"
    port = 49000 + i
    add(t, client, "198.51.100.53", UDP(sport=port, dport=53))
    add(t + 0.012, "198.51.100.53", client, UDP(sport=53, dport=port))
for i in range(14):
    t = 28 + i * 0.6
    add(
        t,
        "192.0.2.81",
        "198.51.100.10",
        TCP(sport=51000 + i, dport=8000 + i, flags="S"),
    )
    add(
        t + 0.004,
        "198.51.100.10",
        "192.0.2.81",
        TCP(sport=8000 + i, dport=51000 + i, flags="RA"),
    )
for i in range(11):
    t = 72 + i * 0.8
    add(t, "192.0.2.92", "198.51.100.22", TCP(sport=52000 + i, dport=22, flags="S"))
    add(
        t + 0.009,
        "198.51.100.22",
        "192.0.2.92",
        TCP(sport=22, dport=52000 + i, flags="RA"),
    )
path = Path("demo/branch-office.pcap")
path.parent.mkdir(exist_ok=True)
wrpcap(str(path), sorted(packets, key=lambda p: p.time))
