import os
import time

from sqlalchemy import (
    JSON,
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    insert,
    update,
)

meta = MetaData()
events = Table(
    "events",
    meta,
    Column("id", Integer, primary_key=True),
    Column("kind", String(12), nullable=False),
    Column("ts", Float, nullable=False),
    Column("src", String(64)),
    Column("dst", String(64)),
    Column("type", String(48)),
    Column("severity", String(12)),
    Column("body", JSON, nullable=False),
)
Index("ix_events_kind_id", events.c.kind, events.c.id)
Index("ix_events_kind_ts", events.c.kind, events.c.ts)
sensor = Table(
    "sensor",
    meta,
    Column("id", Integer, primary_key=True),
    Column("source", String(32)),
    Column("state", String(32)),
    Column("model", String(64)),
    Column("updated", Float),
)


def database(url=None):
    return create_engine(url or os.environ["DATABASE_URL"], pool_pre_ping=True)


def append(conn, kind, body):
    conn.execute(
        insert(events).values(
            kind=kind,
            ts=body["last"],
            src=body["src"],
            dst=body["dst"],
            type=body.get("type"),
            severity=body.get("severity"),
            body=body,
        )
    )


def status(conn, source, state, model):
    values = dict(source=source, state=state, model=model, updated=time.time())
    if not conn.execute(
        update(sensor).where(sensor.c.id == 1).values(**values)
    ).rowcount:
        conn.execute(insert(sensor).values(id=1, **values))


def public(row):
    return {**row.body, "id": row.id, "kind": row.kind}
