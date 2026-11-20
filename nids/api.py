import math
import os
import time
from pathlib import Path

from flask import Flask, Response, abort, jsonify, request, send_from_directory
from sqlalchemy import Integer, cast, func, or_, select

from .storage import database, events, meta, public, sensor


def create_app(db=None):
    db = db if db is not None else database()
    meta.create_all(db)
    dist = Path(os.environ.get("DASHBOARD_DIR", "web/dist")).resolve()
    app = Flask(__name__, static_folder=None)

    def integer(name, default, low, high):
        try:
            value = int(request.args.get(name, default))
        except ValueError:
            abort(400)
        if not low <= value <= high:
            abort(400)
        return value

    @app.get("/api/<kind>")
    def records(kind):
        if kind not in ("flows", "alerts"):
            abort(404)
        limit = integer("limit", 50, 1, 200)
        q = select(events).where(
            events.c.kind == ("flow" if kind == "flows" else "alert")
        )
        if "before" in request.args:
            q = q.where(events.c.id < integer("before", 0, 1, 2**31 - 1))
        for name in ("severity", "type"):
            if request.args.get(name):
                q = q.where(events.c[name] == request.args[name])
        for name in ("since", "until"):
            if name in request.args:
                try:
                    bound = float(request.args[name])
                    if not math.isfinite(bound):
                        raise ValueError
                except ValueError:
                    abort(400)
                q = q.where(
                    events.c.ts >= bound if name == "since" else events.c.ts <= bound
                )
        if needle := request.args.get("q", "").strip():
            q = q.where(
                or_(
                    events.c.src.contains(needle, autoescape=True),
                    events.c.dst.contains(needle, autoescape=True),
                )
            )
        with db.connect() as c:
            rows = c.execute(q.order_by(events.c.id.desc()).limit(limit + 1)).all()
        return jsonify(
            items=[public(r) for r in rows[:limit]],
            next_before=rows[limit - 1].id if len(rows) > limit else None,
        )

    @app.get("/api/health")
    def health():
        with db.connect() as c:
            s = c.execute(select(sensor)).mappings().first()
            totals = dict(
                c.execute(
                    select(events.c.kind, func.count()).group_by(events.c.kind)
                ).all()
            )
            latest = c.scalar(select(func.max(events.c.ts)))
            last_id = c.scalar(select(func.max(events.c.id))) or 0
            bucket = cast(func.floor(events.c.ts / 5), Integer)
            end = int((latest or 0) // 5)
            counts = dict(
                c.execute(
                    select(bucket, func.count())
                    .where(events.c.kind == "flow", events.c.ts >= (end - 23) * 5)
                    .group_by(bucket)
                ).all()
            )
        return jsonify(
            sensor=dict(s) if s else None,
            totals=totals,
            last_event=latest,
            cursor=last_id,
            timeline=[
                {"ts": i * 5, "flows": counts.get(i, 0)}
                for i in range(end - 23, end + 1)
            ],
        )

    @app.get("/api/events")
    def stream():
        try:
            cursor = int(
                request.headers.get("Last-Event-ID", request.args.get("after", "0"))
            )
            if cursor < 0:
                raise ValueError
        except ValueError:
            abort(400)

        def read():
            current = cursor
            yield "retry: 1500\n\n"
            while True:
                with db.connect() as c:
                    newest = c.scalar(select(func.max(events.c.id))) or 0
                if newest > current:
                    current = newest
                    yield f"id: {current}\nevent: update\ndata: {current}\n\n"
                else:
                    yield ": heartbeat\n\n"
                time.sleep(1)

        return Response(
            read(),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/")
    @app.get("/assets/<path:asset>")
    def dashboard(asset=None):
        return send_from_directory(
            dist / "assets" if asset else dist, asset or "index.html"
        )

    return app
