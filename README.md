# Tracewatch

A passive network intrusion monitor built with Python, Scapy, scikit-learn, PostgreSQL, Flask, and React. Inspect a detection to see the endpoints, packet counts, and evidence that triggered it. Replay a bundled capture to explore the entire pipeline on a laptop.

![Tracewatch dashboard showing 121 completed flows, a port scan, and suspected brute force](docs/dashboard.png)

## Run the demo

From the repository root, start Docker Compose.

```sh
docker compose up --build -d
```

Open [the dashboard](http://localhost:8000). The demo takes about 35 seconds after startup. A fresh database ends with **121 flows and two high-severity alerts**. In **Alerts**, filter by detection type and choose **Inspect** to review the observed count, threshold, and time window. **Traffic logs** lets you search either endpoint and page through the underlying flows.

```sh
docker compose logs demo
docker compose down
```

The PostgreSQL volume retains the history. Running the demo again appends another observation of the capture. Dashboard times use UTC packet timestamps. The bundled fixture is synthetic, contains headers only, and can be regenerated with `python -m scripts.make_demo`.

## How detection works

```mermaid
flowchart LR
  NIC[Network interface] --> Sensor[Scapy sensor]
  PCAP[PCAP replay] --> Sensor
  Sensor --> Rules[Rolling SYN rules]
  Sensor --> Flows[Bidirectional flows]
  Flows --> ML[Random forest]
  Rules --> DB[(PostgreSQL)]
  ML --> DB
  Flows --> DB
  DB --> API[Flask API]
  API -->|JSON and event stream| UI[React dashboard]
```

| Detection | Evidence | Default |
| --- | --- | --- |
| Port scan | Distinct destination TCP ports contacted by one source on one host | 10 ports in 60 s |
| Suspected brute force | Distinct source ports initiating TCP connections to the same FTP, SSH, or RDP endpoint | 8 attempts in 60 s |
| ML anomaly | Supervised model score from duration and directional packet counts | Attack score ≥ 0.80 |

Rules count initial SYN packets. Repeated SYNs for the same counted port do not increment the distinct count. Each rule emits one alert per threshold crossing. The authentication rule measures connection activity. Confirm failed logins with service logs. NAT, legitimate discovery, and connection retries can also produce rule alerts.

The single sensor groups TCP and UDP packets by endpoint pair and transport, using the first observed direction as forward. It closes flows on TCP FIN/RST, 30 seconds of inactivity, a 120-second lifetime, or end of replay. Database records contain flow metadata and detection evidence. Run one sensor per database. The app is intended for local review with loopback-only published ports and no application login.

## Live capture on Windows

Start the API and database with `docker compose up -d --build api`. If the demo is running, allow it to finish first. Install [Npcap](https://npcap.com/) with capture access for the account running the sensor. Use a Python 3.12 environment in the repository root.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
$env:DATABASE_URL = 'postgresql+psycopg://tracewatch:localdemo@127.0.0.1:55432/tracewatch'
.\.venv\Scripts\python -c "from scapy.all import conf; print(conf.ifaces)"
.\.venv\Scripts\python -m nids.sensor --interface "Wi-Fi"
```

Choose the displayed interface name. Use elevated capture privileges if required by the Npcap installation. Open the dashboard, generate ordinary traffic on that interface, and check **Live capture**, the last event time, and new flows. A quiet UDP flow may take 30 seconds to close. Ctrl+C flushes active flows. Linux sensors can use the same CLI with an interface such as `eth0` and host capture permissions.

Use `--window`, `--scan`, and `--attempts` to change rule thresholds. For offline input, use `--pcap path/to/file.pcap`. Replay runs immediately by default, or at a time multiplier supplied with `--speed`. The sensor loads the bundled model, or a trusted local artifact at `MODEL_PATH`. A missing artifact enables rules-only operation and the dashboard shows **Rules only**.

## Model evaluation

The fixed random forest uses flow duration in microseconds, forward packet count, and reverse packet count. Training uses Tuesday and Wednesday CIC-IDS2017 captures with at most 40,000 examples per family and seed 42. Evaluation uses the entire cleaned Friday afternoon port-scan capture, including 127,501 normal flows and 158,930 port scans. Port scans were absent from training.

| Held-out class | Forest precision | Forest recall | Majority precision | Majority recall |
| --- | ---: | ---: | ---: | ---: |
| Normal | 44.29% | 99.04% | 0.00% | 0.00% |
| Attack | 5.33% | 0.043% | 55.49% | 100.00% |

At the fixed threshold, the model found 69 port-scan flows, missed 158,861, and flagged 1,226 normal flows. The majority baseline predicts attack for every flow because attack is the majority class after training-set sampling. This experiment shows poor generalization to the held-out attack family. The separate port-scan rule operates across connections. Its demo result is a functional check, independent of the model evaluation. [Full class counts, confusion matrices, input hashes, and model metrics](model/evaluation.json)

To reproduce, install the development dependencies and run from the repository root. The command downloads three CSVs from a revision-pinned mirror, fits the model, and writes the model and report into `model/`.

```sh
python -m pip install -r requirements-dev.txt
python -m scripts.train --data data --download
python -m pytest -q
```

**Feature parity.** On the first 1,000 packets of the original Tuesday PCAP, 81 directional flows matched a unique labeled flow by endpoints, protocol, and UTC minute. All three features agreed exactly on 60 of those flows. Capture boundaries and flow-closing behavior can change feature values. To repeat the check, install `pyarrow` and run `python -m scripts.check_parity Tuesday-WorkingHours.pcap Tuesday-WorkingHours.pcap_ISCX.csv.parquet` with the Tuesday PCAP and traffic-label parquet from the [packet and label mirror](https://huggingface.co/datasets/bvsam/cic-ids-2017/tree/70bac6246d99cf046186a02e1cce6883e2ffe7ea).

Dataset attribution: Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, ICISSP 2018. [University of New Brunswick dataset](https://www.unb.ca/cic/datasets/ids-2017.html) · [Training CSV mirror](https://huggingface.co/datasets/c01dsnap/CIC-IDS2017)

## API and development

| Method and path | Result |
| --- | --- |
| `GET /api/flows` | Flow records, newest ingestion ID first |
| `GET /api/alerts` | Detection type, severity, endpoint metadata, and evidence |
| `GET /api/health` | Sensor source, state, model availability, totals, last event, and 5-second flow buckets |
| `GET /api/events` | Server-sent update notifications with a database cursor and reconnect support |

List endpoints accept `q` for endpoint search, `since` and `until` as inclusive Unix timestamps, and `limit` from 1 to 200. Alerts also accept `severity` and `type`. Pass `next_before` as `before` to retrieve the next page. SSE clients can start with `after` or reconnect with `Last-Event-ID`. Each update signals the client to refresh matching records.

Build the frontend with `npm ci --prefix web` and `npm run build --prefix web`. With `DATABASE_URL` set, serve the built dashboard and API using `waitress-serve --listen=127.0.0.1:8000 --threads=16 --call nids.api:create_app`. PostgreSQL uses the local Compose password `localdemo` by default. Set `POSTGRES_PASSWORD` before first startup to choose a different password and update the host sensor URL accordingly.

Tests cover threshold crossings, retransmissions, window expiry, flow features, replay results, API filtering, pagination, and stream resumption. Set `TEST_DATABASE_URL` to run integration tests on PostgreSQL with an isolated temporary schema. GitHub Actions also builds the frontend and checks a fresh Compose replay.
