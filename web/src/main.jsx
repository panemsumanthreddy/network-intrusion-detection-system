import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const fmtTime = (value) =>
  value == null ? "—" : new Date(value * 1000).toISOString().slice(11, 19);
const date = (value) =>
  value == null
    ? "Waiting for traffic"
    : new Date(value * 1000).toLocaleDateString("en-GB", {
        day: "numeric",
        month: "long",
        year: "numeric",
        timeZone: "UTC",
      });
const number = (n) => (n || 0).toLocaleString();
async function get(path, signal) {
  const response = await fetch(path, { signal });
  if (!response.ok) throw new Error("Could not retrieve sensor data");
  return response.json();
}
function Mark() {
  return (
    <span className="mark" aria-hidden="true">
      {[10, 20, 30, 16, 8].map((h, i) => (
        <i key={i} style={{ height: h }} />
      ))}
    </span>
  );
}
function Timeline({ bins = [] }) {
  const peak = Math.max(1, ...bins.map((b) => b.flows));
  return (
    <div className="panel chart">
      <div className="section">
        <h2>Flow activity</h2>
        <span className="legend">
          <i /> Completed flows
        </span>
      </div>
      <div
        className="graph"
        role="img"
        aria-label={"Completed flows in five-second buckets, peak " + peak}
      >
        <div className="ticks">
          <span>{peak}</span>
          <span>0</span>
        </div>
        <div className="bars">
          {bins.map((b) => (
            <div
              key={b.ts}
              style={{ height: Math.max(1, (100 * b.flows) / peak) + "%" }}
              title={fmtTime(b.ts) + " UTC · " + b.flows + " flows"}
            />
          ))}
        </div>
      </div>
      <div className="axis">
        <span>{fmtTime(bins[0]?.ts)}</span>
        <span>5-second intervals · UTC</span>
        <span>{fmtTime(bins.at(-1)?.ts)}</span>
      </div>
    </div>
  );
}
function Detail({ row, close }) {
  const dialog = useRef(null);
  useEffect(() => {
    dialog.current.showModal();
  }, []);
  return (
    <dialog ref={dialog} onCancel={close}>
      <div className="section">
        <h2>{row.type || "Flow details"}</h2>
        <button onClick={close} autoFocus>
          Close
        </button>
      </div>
      <p className="muted">
        {date(row.last)} · {fmtTime(row.last)} UTC
      </p>
      <dl>
        {Object.entries({
          Source: row.src + ":" + row.sport,
          Destination: row.dst + ":" + row.dport,
          Protocol: row.protocol,
          ...(row.detector ? { Detector: row.detector } : {}),
          "Forward / reverse packets": row.forward + " / " + row.backward,
          "Duration (µs)": row.features[0],
          ...(row.evidence || {}),
        }).map(([key, v]) => (
          <React.Fragment key={key}>
            <dt>{key.replaceAll("_", " ")}</dt>
            <dd>{Array.isArray(v) ? v.join(" / ") : v}</dd>
          </React.Fragment>
        ))}
      </dl>
    </dialog>
  );
}
function App() {
  const [tab, setTab] = useState("Overview"),
    [health, setHealth] = useState(null),
    [version, setVersion] = useState(0),
    [link, setLink] = useState("Connecting");
  const [rows, setRows] = useState([]),
    [more, setMore] = useState(null),
    [pages, setPages] = useState([]),
    [detail, setDetail] = useState(null);
  const [q, setQuery] = useState(""),
    [severity, setSeverity] = useState(""),
    [type, setType] = useState(""),
    [period, setPeriod] = useState(""),
    [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const flow = tab === "Traffic logs",
    before = pages.at(-1);
  useEffect(() => {
    let alive = true,
      stream,
      timer;
    const control = new AbortController();
    async function start() {
      try {
        const first = await get("/api/health", control.signal);
        if (!alive) return;
        setHealth(first);
        setVersion((n) => n + 1);
        stream = new EventSource("/api/events?after=" + first.cursor);
        stream.onopen = () => setLink("Connected");
        stream.onerror = () => setLink("Reconnecting");
        stream.addEventListener("update", () => setVersion((n) => n + 1));
      } catch (e) {
        if (alive) {
          setLink("Disconnected");
          timer = setTimeout(start, 3000);
        }
      }
    }
    start();
    const pulse = setInterval(() => setVersion((n) => n + 1), 10000);
    return () => {
      alive = false;
      control.abort();
      stream?.close();
      clearTimeout(timer);
      clearInterval(pulse);
    };
  }, []);
  useEffect(() => {
    const control = new AbortController();
    async function refresh() {
      try {
        const h = await get("/api/health", control.signal);
        const params = new URLSearchParams({
          limit: tab === "Overview" ? "8" : "25",
          q,
        });
        if (!flow && type) params.set("type", type);
        if (!flow && severity) params.set("severity", severity);
        if (before) params.set("before", before);
        if (period && h.last_event)
          params.set("since", h.last_event - Number(period));
        const data = await get(
          "/api/" + (flow ? "flows" : "alerts") + "?" + params,
          control.signal,
        );
        setHealth(h);
        setRows(data.items);
        setMore(data.next_before);
        setError("");
      } catch (e) {
        if (e.name !== "AbortError") setError(e.message);
      }
    }
    refresh();
    return () => control.abort();
  }, [version, retry, tab, q, type, severity, period, before]);
  function navigate(t) {
    setTab(t);
    setPages([]);
    setQuery("");
    setType("");
    setSeverity("");
    setPeriod("");
    setRows([]);
    setMore(null);
  }
  function filter(set, v) {
    setPages([]);
    set(v);
  }
  const sensor = health?.sensor;
  return (
    <>
      <header>
        <div className="shell head">
          <div className="brand">
            <Mark />
            Tracewatch
          </div>
          <nav aria-label="Main navigation">
            {["Overview", "Alerts", "Traffic logs"].map((t) => (
              <button
                aria-current={tab === t ? "page" : undefined}
                className={tab === t ? "selected" : ""}
                onClick={() => navigate(t)}
                key={t}
              >
                {t}
              </button>
            ))}
          </nav>
          <div className="connection">
            <i className={link === "Connected" ? "on" : ""} />
            {link}
          </div>
        </div>
      </header>
      <main className="shell">
        <div className="heading">
          <div>
            <div className="eyebrow">NETWORK MONITORING</div>
            <h1>{tab === "Overview" ? "Sensor overview" : tab}</h1>
          </div>
          <div className="date">
            {date(health?.last_event)}
            <small>Capture time · UTC</small>
          </div>
        </div>
        {error && (
          <p role="alert">
            {error} <button onClick={() => setRetry(retry + 1)}>Retry</button>
          </p>
        )}
        {tab === "Overview" && (
          <>
            <div className="metrics">
              {[
                [
                  "Recorded flows",
                  number(health?.totals.flow),
                  "Bidirectional TCP and UDP",
                ],
                [
                  "Detection alerts",
                  number(health?.totals.alert),
                  "Rule and model detections",
                ],
                [
                  "Capture source",
                  sensor?.source || "Waiting",
                  sensor?.state === "running" &&
                  Date.now() / 1000 - sensor.updated > 30
                    ? "Last heartbeat overdue"
                    : "Sensor " + (sensor?.state || "offline"),
                ],
                [
                  "Last event",
                  fmtTime(health?.last_event),
                  "Packet timestamp · UTC",
                ],
              ].map(([label, value, sub]) => (
                <div className="metric" key={label}>
                  <label>{label}</label>
                  <strong>{value}</strong>
                  <small>{sub}</small>
                </div>
              ))}
            </div>
            <Timeline bins={health?.timeline} />
          </>
        )}
        <section className="panel">
          <div className="section">
            <h2>
              {tab === "Overview"
                ? "Recent alerts"
                : flow
                  ? "Flow records"
                  : "Detection alerts"}
            </h2>
            {tab === "Overview" && (
              <button onClick={() => navigate("Alerts")}>
                View all alerts →
              </button>
            )}
          </div>
          {tab !== "Overview" && (
            <div className="filters">
              <input
                aria-label="Search endpoint"
                placeholder="Search source or destination IP"
                value={q}
                onChange={(e) => filter(setQuery, e.target.value)}
              />
              {!flow && (
                <>
                  <select
                    aria-label="Severity"
                    value={severity}
                    onChange={(e) => filter(setSeverity, e.target.value)}
                  >
                    <option value="">All severities</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                  </select>
                  <select
                    aria-label="Detection type"
                    value={type}
                    onChange={(e) => filter(setType, e.target.value)}
                  >
                    <option value="">All detection types</option>
                    {["Port scan", "Suspected brute force", "ML anomaly"].map(
                      (s) => (
                        <option key={s}>{s}</option>
                      ),
                    )}
                  </select>
                </>
              )}
              <select
                aria-label="Time range"
                value={period}
                onChange={(e) => filter(setPeriod, e.target.value)}
              >
                <option value="">All capture time</option>
                <option value="60">Last capture minute</option>
                <option value="3600">Last capture hour</option>
              </select>
            </div>
          )}
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  {[
                    "Time (UTC)",
                    flow ? "Protocol" : "Detection",
                    "Source",
                    "Destination",
                    flow ? "Packets" : "Severity",
                    "Details",
                  ].map((c) => (
                    <th key={c}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td>{fmtTime(r.last)}</td>
                    <td className="name">{flow ? r.protocol : r.type}</td>
                    <td>{r.src}</td>
                    <td>{r.dst}</td>
                    <td>
                      {flow ? (
                        r.forward + r.backward
                      ) : (
                        <span className={"pill " + r.severity}>
                          {r.severity}
                        </span>
                      )}
                    </td>
                    <td>
                      <button
                        aria-label={"Inspect record " + r.id}
                        onClick={() => setDetail(r)}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!rows.length && (
            <p className="empty">
              {health ? "No matching records." : "Loading sensor data…"}
            </p>
          )}
          {tab !== "Overview" && (
            <div className="pager">
              <button
                disabled={!pages.length}
                onClick={() => setPages(pages.slice(0, -1))}
              >
                Previous
              </button>
              <span>Page {pages.length + 1}</span>
              <button
                disabled={!more}
                onClick={() => setPages([...pages, more])}
              >
                Next
              </button>
            </div>
          )}
        </section>
        <footer>
          <span>TRACEWATCH / SENSOR CONSOLE</span>
          <span>Model · {sensor?.model || "Unavailable"}</span>
        </footer>
      </main>
      {detail && <Detail row={detail} close={() => setDetail(null)} />}
    </>
  );
}
createRoot(document.getElementById("root")).render(<App />);
