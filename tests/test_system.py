import os
from uuid import uuid4

import joblib
import pytest
from scapy.all import IP, TCP, PcapReader
from sqlalchemy import create_engine, text

from nids.api import create_app
from nids.engine import Engine
from nids.features import COLUMNS, SCHEMA
from nids.storage import append


def syn(t, sport, dport):
    pkt = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(
        sport=sport, dport=dport, flags="S"
    )
    pkt.time = t
    return pkt


def test_rules_window_and_suppression():
    alerts = []
    eng = Engine(
        lambda k, b: alerts.append(b) if k == "alert" else None,
        window=10,
        scan=3,
        attempts=2,
    )
    for i, dport in enumerate((21, 22, 23, 24)):
        eng.packet(syn(i, 1024 + i, dport))
    eng.packet(syn(4, 1025, 22))  # retransmitted SYN
    assert [a["type"] for a in alerts] == ["Port scan"]
    eng.packet(syn(5, 2048, 22))
    assert alerts[-1]["type"] == "Suspected brute force"
    for i in range(3):
        eng.packet(syn(20 + i, 2048, 80 + i))
    assert [a["type"] for a in alerts].count("Port scan") == 2


def test_model_and_demo():
    bundle = joblib.load("model/forest.joblib")
    assert (bundle["schema"], tuple(bundle["columns"])) == (SCHEMA, COLUMNS)
    rows = []
    engine = Engine(lambda k, b: rows.append((k, b)), bundle["model"])
    with PcapReader("demo/branch-office.pcap") as packets:
        for pkt in packets:
            engine.packet(pkt)
    engine.finish()
    flows = [b for k, b in rows if k == "flow"]
    assert len(flows) == 121
    assert next(f for f in flows if f["protocol"] == "UDP")["features"] == [12000, 1, 1]
    types = [b["type"] for k, b in rows if k == "alert"]
    assert types.count("Port scan") == types.count("Suspected brute force") == 1


@pytest.fixture
def db(tmp_path):
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        db = create_engine("sqlite:///" + (tmp_path / "test.db").as_posix())
        yield db
        db.dispose()
        return
    schema = "test_" + uuid4().hex
    admin = create_engine(url)
    with admin.begin() as c:
        c.execute(text(f"CREATE SCHEMA {schema}"))
    db = create_engine(url, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield db
    finally:
        db.dispose()
        with admin.begin() as c:
            c.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        admin.dispose()


def test_api_and_resume(db):
    client = create_app(db).test_client()
    with db.begin() as conn:
        for i in range(3):
            append(
                conn,
                "alert",
                dict(
                    src="192.0.2.1",
                    dst="192.0.2.2",
                    last=i,
                    type="Port scan",
                    severity="high",
                ),
            )
    first = client.get("/api/alerts?limit=2").json
    assert [r["id"] for r in first["items"]] == [3, 2]
    assert client.get("/api/alerts?before=2").json["items"][0]["id"] == 1
    assert (
        len(
            client.get(
                "/api/alerts?severity=high&type=Port%20scan&q=192.0&since=1&until=1"
            ).json["items"]
        )
        == 1
    )
    assert client.get("/api/alerts?severity=medium").json["items"] == []
    assert client.get("/api/flows").json["items"] == []
    assert client.get("/api/alerts?since=nan").status_code == 400
    assert client.get("/api/health").json["totals"] == {"alert": 3}
    for cursor, expected in [(2, b"id: 3"), (3, b": heartbeat")]:
        with client.get(
            "/api/events?after=0",
            headers={"Last-Event-ID": str(cursor)},
            buffered=False,
        ) as response:
            it = iter(response.response)
            next(it)
            assert expected in next(it)
