"""Packet-time flow aggregation and rolling rule episodes."""

from dataclasses import dataclass

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from .features import vector


@dataclass
class Flow:
    start: float
    last: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: str
    forward: int = 0
    backward: int = 0
    octets: int = 0

    def summary(self):
        return {
            **vars(self),
            "features": vector(
                round((self.last - self.start) * 1e6), self.forward, self.backward
            ),
        }


class Engine:
    def __init__(self, emit, model=None, window=60, scan=10, attempts=8):
        self.emit, self.model = emit, model
        self.window, self.scan, self.attempts = window, scan, attempts
        self.flows = {}
        self.episodes = {}
        self.last_sweep = 0

    def close(self, key):
        f = self.flows.pop(key)
        row = f.summary()
        self.emit("flow", row)
        if self.model:
            score = float(self.model.predict_proba([row["features"]])[0, 1])
            if score >= 0.8:
                self.emit(
                    "alert",
                    {
                        **row,
                        "type": "ML anomaly",
                        "detector": "Random forest",
                        "severity": "medium",
                        "evidence": {
                            "attack_score": round(score, 4),
                            "threshold": 0.8,
                            "features": row["features"],
                        },
                    },
                )

    def sweep(self, now):
        for key, flow in list(self.flows.items()):
            if now - flow.last >= 30 or now - flow.start >= 120:
                self.close(key)
        for key, (seen, _) in list(self.episodes.items()):
            if not seen or max(seen.values()) <= now - self.window:
                del self.episodes[key]
        self.last_sweep = now

    def observe(self, key, item, limit, flow, name):
        seen, active = self.episodes.get(key, ({}, False))
        now = flow.last
        seen = {k: v for k, v in seen.items() if v > now - self.window}
        active = active and len(seen) >= limit
        seen[item] = now
        if len(seen) >= limit and not active:
            self.emit(
                "alert",
                {
                    **flow.summary(),
                    "type": name,
                    "detector": "Rolling SYN rule",
                    "severity": "high",
                    "evidence": {
                        "observed": len(seen),
                        "threshold": limit,
                        "window_seconds": self.window,
                    },
                },
            )
            active = True
        self.episodes[key] = seen, active

    def packet(self, pkt):
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None or not isinstance(ip.payload, (TCP, UDP)):
            return
        layer = ip.payload
        tcp = isinstance(layer, TCP)
        now = float(pkt.time)
        if now - self.last_sweep >= 1:
            self.sweep(now)
        a, b = (ip.src, layer.sport), (ip.dst, layer.dport)
        proto = "TCP" if tcp else "UDP"
        key = (proto, *sorted((a, b)))
        f = self.flows.get(key)
        if f and (now - f.last >= 30 or now - f.start >= 120):
            self.close(key)
            f = None
        if f is None:
            f = self.flows[key] = Flow(
                now, now, ip.src, ip.dst, layer.sport, layer.dport, proto
            )
        f.last = max(f.last, now)
        f.octets += len(ip)
        if a == (f.src, f.sport):
            f.forward += 1
        else:
            f.backward += 1
        if tcp and layer.flags.S and not layer.flags.A and a == (f.src, f.sport):
            self.observe(
                ("scan", ip.src, ip.dst), layer.dport, self.scan, f, "Port scan"
            )
            if layer.dport in (21, 22, 3389):
                self.observe(
                    ("auth", ip.src, ip.dst, layer.dport),
                    layer.sport,
                    self.attempts,
                    f,
                    "Suspected brute force",
                )
        if tcp and (layer.flags.F or layer.flags.R):
            self.close(key)

    def finish(self):
        for key in list(self.flows):
            self.close(key)
