# Real-Time Network Intrusion Detection System: Analysis and Implementation Plan

## 1. Architectural Analysis & Tech Stack Evaluation

The proposed architecture is highly modular and follows modern best practices for combining real-time data processing with AI/ML. The concept of using an Agentic AI layer to correlate and explain alerts is excellent and addresses a major pain point in modern Security Operations Centers (SOCs). 

However, for a robust, scalable system, a few improvisations can elevate the project from a theoretical prototype to a production-ready solution.

### Original vs. Improvised Technology Stack

| Layer | Original Proposal | Recommended Improvisations & Why |
| :--- | :--- | :--- |
| **Packet Capture & Core NIDS** | Scapy, PCAP / tcpreplay | **Suricata** or **Zeek**. *Reason:* Scapy is excellent for prototyping but struggles with high-throughput real-time traffic. Suricata and Zeek are industry standards that can parse 10Gbps+ traffic effortlessly and output structured JSON logs (e.g., EVE JSON) containing flow and protocol features directly into your ML pipeline. |
| **Message Broker (New)** | *Not explicitly defined* | **Redis Streams**, **Apache Kafka**, or **RabbitMQ**. *Reason:* Network traffic generates massive amounts of events. Decoupling the packet capture from the ML engine and the Agentic layer using a message queue ensures the system doesn't drop packets during traffic spikes. |
| **ML / DL Pipeline** | Python, Scikit-learn, TensorFlow | **PyTorch** + **XGBoost**. *Reason:* PyTorch is currently the preferred framework for modern deep learning (LSTMs/Autoencoders). XGBoost often outperforms Random Forest for tabular network flow data and is faster to infer. |
| **Agentic AI** | LangGraph, Ollama, Gemma | **LangGraph or CrewAI** + **Llama 3 8B (via Ollama)**. *Reason:* Llama 3 currently offers exceptional reasoning capabilities for local, privacy-preserving deployments. CrewAI is a great alternative to LangGraph if you want to define distinct agent personas (e.g., a "Correlator Agent" and a "Reporting Agent"). |
| **Backend & API** | FastAPI, WebSockets | **Keep.** FastAPI is the absolute best choice for async Python backends and WebSocket streaming. |
| **Database & Memory** | PostgreSQL, Redis | **Keep.** PostgreSQL for long-term incident storage and Redis for short-term contextual memory (and message queuing). |
| **Frontend** | React, Vite, Tailwind CSS | **Keep.** Add **Zustand** or **Redux Toolkit** for managing the complex state of real-time incoming alerts. Add **Recharts** or **Chart.js** for data visualization. |
| **Reporting** | Jinja2 + WeasyPrint | **Keep.** Solid choice for automated PDF generation. |
| **Deployment** | Docker, Docker Compose | **Keep.** Standard and reliable. |

---

## 2. Step-by-Step Implementation Guide

### Current implementation: Layers 1, 2, and 3

The first implementation slice is available as the FastAPI backend service under
[`backend`](backend):

#### Progress through 2026-10-06

The prototype currently has a working Layer 1-3 path:

```text
Scapy / PCAP / Suricata EVE / Zeek JSON
                 |
                 v
          PacketEvent contract
                 |
       +---------+---------+
       |                   |
   JSONL history      Redis Stream
                       nids:raw-events
                             |
                    Redis consumer group
                       nids-workers
```

Implemented:

- Windows live capture through Scapy/Npcap.
- PCAP replay through Scapy.
- Suricata EVE JSON file replay and live tailing.
- Zeek JSON `conn.log` live tailing.
- Concurrent Suricata + Zeek ingestion with `mode: "sensors"`.
- Shared `PacketEvent` normalization for all input types.
- Schema version, stable observation `event_id`, `event_source`, and a
  bidirectional-flow `correlation_key`.
- Append-only local history at `data/normalized/events.jsonl`.
- Optional Redis Stream publishing to `nids:raw-events`.
- Redis consumer-group boundary with acknowledgement only after successful
  processing.
- FastAPI control/status/events endpoints and the initial React dashboard.
- Layer 4 Random Forest + Isolation Forest inference through the shared
  `backend.detection` package. Normalized events are converted to the ML
  feature contract, scored once, and written to
  `data/normalized/alerts.jsonl`.
- Every alert stores the linked `event_id`, packet/flow context, original
  sensor payload, derived ML features, model scores, and explanation. Raw
  normalized events remain in `data/normalized/events.jsonl`; alerts are the
  auditable detection projection of those events.
- Automatic bootstrap training from the included prototype dataset when ML
  artifacts are absent. Generated artifacts live under `data/ml/artifacts/`
  and are ignored by Git.
- Detection APIs at `/detection/status` and `/detection/alerts`, plus a
  four-layer command-center view in the React dashboard.
- Suricata `stats` records are accepted; `flow.age` is used as duration and
  timestamp-like `flow.end` is not parsed as a number.

Not implemented yet:

- Alert correlation into incidents.
- PostgreSQL incident persistence.
- LLM/agentic analysis, WebSockets, and PDF reporting.
- Automatic reclaiming of abandoned Redis pending messages and a dead-letter
  stream.

This means Layers 1-4 are ready for a controlled prototype demonstration, not
yet for a production NIDS deployment.

Run it with:

```text
cd C:\Users\Aditya\Desktop\NIDS
python -m pip install -e ".[api,capture,redis,ml,dev]"
python -m uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API.

The first scored event trains the prototype models from
`data/ml/sample_nids.csv` if no artifacts exist. Set
`NIDS_ML_AUTO_TRAIN=false` to require pre-built artifacts. The Redis worker
uses the same detector and alert contract:

```powershell
python -m backend.worker
```

The dashboard polls capture, sensor, model, event, and alert endpoints and
shows the state of Layers 1-4: capture, normalization, transport, and hybrid
ML detection. LOW results remain in alert history for auditability; the
command center highlights MEDIUM and HIGH signals.

Run that command from the repository root (`C:\Users\Aditya\Desktop\NIDS`).
Do not use `uvicorn main:app` from inside the `backend` directory; that loads
the module without its `backend` package context and causes an attempted
relative import error.

If your terminal is already inside `backend`, use:

```text
python -m uvicorn backend.main:app --app-dir .. --reload
```

The service exposes `/health`, `/capture/status`, `/sensors/status`,
`/capture/interfaces`, `/capture/events`, `/capture/start`, `/capture/switch`,
and `/capture/stop`.
The pipeline runs automatically in a background worker after `/capture/start`
or on application startup when `NIDS_AUTO_START=true`.

Live capture is continuous: it keeps reading packets until you call
`POST /capture/stop`, switch to another source, or shut down FastAPI. Captured
events are appended to `data/normalized/events.jsonl` and can be viewed through
`GET /capture/events?offset=0&limit=100`. The endpoint returns `total`, so
larger histories can be browsed page by page without loading everything into
memory.

You can switch between PCAP and Suricata directly from the Swagger UI by
opening `http://127.0.0.1:8000/docs` and calling `POST /capture/switch`.
The endpoint stops the current source before starting the selected one:

```json
{
  "mode": "suricata",
  "path": "data/suricata/eve.json"
}
```

To switch back to PCAP:

```json
{
  "mode": "pcap",
  "path": "data/pcaps/sample.pcap"
}
```

The repository's `backend/.env` is loaded automatically when the API starts.
The default `.env` is safe for development (`NIDS_AUTO_START=false`), so a
missing Suricata file or Redis server cannot prevent FastAPI from starting.

Configure automatic startup using environment variables:

```text
$env:NIDS_AUTO_START="true"
$env:NIDS_SOURCE_MODE="suricata"
$env:NIDS_SOURCE_PATH="data\suricata\eve.json"
$env:NIDS_HISTORY_PATH="data\normalized\events.jsonl"
$env:REDIS_URL="redis://localhost:6379/0"
python -m uvicorn backend.main:app --reload
```

Supported source modes are `live`, `pcap`, `suricata`, `suricata_live`,
`zeek_live`, `sensors`, `suricata_zeek`, `jsonl`, and `replay`.

#### Capture mode reference

| Mode | Input | Use it for |
| --- | --- | --- |
| `live` | Scapy + Windows/Npcap or Linux interface | Direct prototype capture from a selected adapter, such as a Windows Wi-Fi adapter. |
| `pcap` | PCAP file through Scapy | Deterministic replay of recorded traffic. |
| `suricata` / `eve` | Existing Suricata `eve.json` from the beginning | One-time import or replay of an existing EVE file. |
| `suricata_live` | Suricata `eve.json` from its current end | Follow new Suricata records as they are written. Use this for a Suricata-only live demo. |
| `zeek_live` | Zeek JSON `conn.log` from its current end | Follow new Zeek connection records as they are written. |
| `sensors` / `suricata_zeek` | Suricata EVE and Zeek JSON concurrently | Run both sensor tailers together and publish both event types through the same pipeline. |
| `jsonl` / `replay` | Normalized `events.jsonl` | Replay backend history without requiring a sensor. |

`suricata_live`, `zeek_live`, and `sensors` intentionally start at the
current end of their files, so old records are not replayed. Start the API
source first, then generate traffic or append new sensor records.

#### Suricata and Zeek integration

Suricata and Zeek are the production-oriented Layer 1 capture engines. They
run beside this backend and write structured logs; the backend consumes those
logs as Layer 2 input. Scapy remains useful for a lightweight Windows/Kali
prototype and direct Wi-Fi demonstration.

Suricata live integration is available through `suricata_live`. It tails EVE
JSON from the current end of the file, so old records are not replayed:

```json
{
  "mode": "suricata_live",
  "path": "data/suricata/eve.json"
}
```

Start Suricata on the monitored Linux sensor interface and configure EVE JSON
output to `data/suricata/eve.json`. Then call `POST /capture/start` or
`POST /capture/switch` from Swagger. The backend continuously normalizes new
Suricata flow and alert records into the shared `PacketEvent` contract,
persists them to JSONL, and publishes them to Redis. The live tailer handles
missing files and inode changes caused by log rotation.

Zeek live JSON ingestion is available through `zeek_live`:

```json
{
  "mode": "zeek_live",
  "path": "data/zeek/conn.log"
}
```

Run Zeek with JSON logs enabled. The adapter maps connection metadata such as
`id.orig_h`, `id.resp_h`, ports, `proto`, `ts`, duration, bytes, and packet
counts into the common event model.

Option C runs both sensors concurrently:

```text
Suricata eve.json ─┐
                   ├─> dual sensor source -> PacketEvent -> Redis
Zeek conn.log   ───┘
```

Configure the sensor output locations once in `backend/.env` (or deployment
environment variables):

```text
NIDS_SURICATA_EVE_PATH=data/suricata/eve.json
NIDS_ZEEK_CONN_PATH=data/zeek/conn.log
```

The production start request then only selects the sensor plane:

```json
{
  "mode": "sensors"
}
```

The two sensor tailers run in separate threads, stop together, and tolerate
the log files not existing yet. Suricata and Zeek should run on a Linux
sensor (Kali, Debian, or Ubuntu) with access to the monitored interface or a
SPAN/TAP feed. The Windows Scapy source remains a development fallback only.
Use `GET /sensors/status` to see whether both configured outputs are present,
their paths, file sizes, and the active pipeline mode. Suricata and Zeek still
need to be installed and attached to a real interface, SPAN port, or TAP by
the sensor host; FastAPI does not replace those sensor processes.

#### Suricata-only test from Windows + Ubuntu/WSL

This is the recommended current Suricata demonstration. Suricata runs in
Ubuntu/WSL and writes into the Windows repository; FastAPI runs on Windows and
tails only the Suricata file.

1. Start Redis if you want to demonstrate Layer 3:

```powershell
redis-cli ping
```

The expected response is `PONG`. Redis is optional for Layers 1-2.

2. Start FastAPI on Windows:

```powershell
cd C:\Users\Aditya\Desktop\NIDS
python -m uvicorn backend.main:app --reload
```

3. Open Ubuntu/WSL and install/check Suricata:

```bash
sudo apt update
sudo apt install -y suricata
suricata --build-info
ip addr
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Use the monitored Ubuntu interface, commonly `eth0`, in the next command.
WSL's `eth0` is a virtual interface; it may not see every packet on the
physical Windows Wi-Fi adapter.

4. Write EVE output into the repository:

```bash
mkdir -p /mnt/c/Users/Aditya/Desktop/NIDS/data/suricata
sudo suricata \
  -c /etc/suricata/suricata.yaml \
  -i eth0 \
  -l /mnt/c/Users/Aditya/Desktop/NIDS/data/suricata
```

In another Ubuntu terminal, verify that Suricata is producing JSON:

```bash
tail -f /mnt/c/Users/Aditya/Desktop/NIDS/data/suricata/eve.json
```

5. Start the Suricata-only source from PowerShell:

```powershell
$body = @{
    mode = "suricata_live"
    path = "data/suricata/eve.json"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/capture/start `
  -ContentType "application/json" `
  -Body $body
```

6. Generate harmless traffic inside Ubuntu:

```bash
curl https://example.com
nslookup example.com
```

7. Verify the normalized records from PowerShell:

```powershell
Invoke-RestMethod `
  "http://127.0.0.1:8000/capture/status" |
  ConvertTo-Json -Depth 10

Invoke-RestMethod `
  "http://127.0.0.1:8000/capture/events?latest=true&limit=10" |
  ConvertTo-Json -Depth 10
```

Look for `capture_source` and `event_source` equal to `suricata`. A `stats`
record proves that Suricata is running; `flow`, `dns`, `tls`, or `http` records
prove that it is observing traffic.

Stop the pipeline with:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/capture/stop
```

#### Zeek-only test from Windows + Ubuntu/WSL

Zeek follows the same pattern, but writes JSON `conn.log` instead of
Suricata EVE JSON.

1. Install/check Zeek in Ubuntu:

```bash
sudo apt update
sudo apt install -y zeek
zeek --version
```

If `zeek` is unavailable from the Ubuntu repository, install it using the
official Zeek packages for the Ubuntu version in use.

2. Start Zeek with JSON logs in the repository:

```bash
mkdir -p /mnt/c/Users/Aditya/Desktop/NIDS/data/zeek
cd /mnt/c/Users/Aditya/Desktop/NIDS/data/zeek
sudo zeek \
  -i eth0 \
  LogAscii::use_json=T \
  Log::default_logdir=/mnt/c/Users/Aditya/Desktop/NIDS/data/zeek
```

Verify that the records are JSON objects rather than tab-separated text:

```bash
grep -v '^#' /mnt/c/Users/Aditya/Desktop/NIDS/data/zeek/conn.log | head
```

3. Start the Zeek-only source from Swagger or PowerShell:

```powershell
$body = @{
    mode = "zeek_live"
    path = "data/zeek/conn.log"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/capture/start `
  -ContentType "application/json" `
  -Body $body
```

4. Generate traffic in Ubuntu and inspect `/capture/events` as in the
Suricata procedure. Zeek events should have `event_source: "zeek"` and
`event_type: "connection"`.

#### Both sensors together

Configure the paths in `backend/.env`:

```text
NIDS_SURICATA_EVE_PATH=data/suricata/eve.json
NIDS_ZEEK_CONN_PATH=data/zeek/conn.log
```

Start Suricata and Zeek first, then select:

```json
{
  "mode": "sensors"
}
```

The backend tails both files concurrently. Events from the two tools receive
different `event_id` values, while compatible observations can share a
`correlation_key`. The key is a grouping hint, not proof that two records are
duplicates.

For wireless live capture on Windows:

1. Install **Npcap** with WinPcap compatibility mode.
2. Install Scapy: `python -m pip install -e ".[api,dev,capture]"`
3. Start FastAPI and call `GET /capture/interfaces` in Swagger.
4. Select the Wi-Fi adapter shown there and call `POST /capture/start`:

```json
{
  "mode": "live",
  "interface": "YOUR-WIFI-INTERFACE"
}
```

Use the interface name returned by the API, not necessarily `Wi-Fi`; Scapy
often returns a long Npcap adapter name. Administrator privileges may be
required. If Windows capture is unavailable, run the same backend on Kali
Linux with the wireless interface (for example `wlan0`).

The interface response includes both the adapter `name` and `description`, so
you can identify the wireless adapter behind an Npcap GUID:

```json
{
  "interfaces": [
    {
      "name": "\\Device\\NPF_{...}",
      "description": "Wi-Fi"
    }
  ]
}
```

Redis is an optional Layer 3 sink during local development. If Redis is down,
Layer 1 and Layer 2 continue running and events are still written to the
history file. The status reports `"broker": "unavailable"` with the
connection error instead of stopping capture.

When Redis is available, Layer 3 publishes every normalized event to:

```text
nids:raw-events
```

The next ML worker can consume this stream using the `nids-workers` Redis
consumer group. Start the current worker boundary with:

```text
python -m backend.worker
```

The worker validates each `PacketEvent`, calls its processing handler, and only
acknowledges the Redis message after that handler succeeds. A failed handler
therefore leaves the message pending instead of silently losing it. Configure
`NIDS_REDIS_GROUP` and `NIDS_REDIS_CONSUMER` when running multiple workers.

Every normalized event includes:

- `schema_version`: version of the event contract (currently `1`)
- `event_id`: stable ID for the same sensor observation
- `event_source`: `scapy`, `pcap`, `suricata`, `zeek`, or `test`
- `correlation_key`: bidirectional protocol/endpoint key shared by matching
  Suricata and Zeek observations

The first sensor contract deliberately uses fields available from both tools:
timestamp, source/destination IP and port, protocol, duration, bytes, packets,
event type, and packet length. Suricata-only alert fields remain optional:
signature, category, and severity. The correlation key is not an identity claim;
it is a grouping hint for a future deduplication/correlation stage.

### Frontend command center

The first dashboard is available under [`frontend`](frontend). It is a
React/TypeScript/Vite application styled with Tailwind and reusable
shadcn-style panels, controls, status badges, and toast notifications.

Start the backend first, then run:

```powershell
cd C:\Users\Aditya\Desktop\NIDS\frontend
Copy-Item .env.example .env
npm install
npm run dev
```

Open the URL shown by Vite, normally `http://localhost:5173`.
`VITE_API_URL` defaults to `http://127.0.0.1:8000`.

FastAPI allows the local Vite origins by default. If the frontend is served
from another origin, add it to `NIDS_CORS_ORIGINS` as a comma-separated list,
then restart the backend:

```text
NIDS_CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

The dashboard currently shows:

- API and Redis connectivity
- Capture pipeline status and processed-event count
- Suricata + Zeek dual-sensor controls
- Individual Suricata-live and Zeek-live controls
- Windows/Kali live-interface selection
- PCAP replay controls
- Start, stop, and source-switch actions
- Paginated captured-event telemetry
- Toast feedback for API failures and successful operations

- `ScapyLiveSource` captures IPv4 packets from a live interface, including a Kali Linux interface.
- `PcapReplaySource` replays a PCAP file when the optional Scapy dependency is installed.
- `SuricataEveSource` normalizes Suricata EVE JSON records.
- `JsonlEventStore` keeps an append-only historical event log for deterministic replay.
- `RedisStreamSink` optionally publishes the same normalized event to `nids:raw-events`.
- `PacketIngestor` fans each event out to all configured sinks.

Install the development dependencies and run the tests with:

```text
pip install -e ".[dev]"
pytest
```

For live capture or PCAP replay, install Scapy as well:

```text
pip install -e ".[capture]"
```

The normalized `PacketEvent` contract intentionally sits between capture and
downstream ML processing. This keeps live capture, Suricata logs, Kali traffic,
and historical replay interchangeable for later layers.

#### Layer responsibilities

```text
Layer 1 - Network input
    Scapy live Wi-Fi capture
    Suricata EVE JSON
    Zeek JSON logs
    PCAP replay

Layer 2 - Capture and ingestion
    Normalize all inputs into PacketEvent
    Persist every event to JSONL history
    Expose paginated history through GET /capture/events

Layer 3 - Message broker
    Publish normalized events to Redis Stream nids:raw-events
    Continue local capture if Redis is unavailable
```

To turn this vision into reality, the project should be broken down into incremental, manageable phases.

### Phase 1: Data Pipeline and Storage Foundation
**Goal:** Capture network traffic and store it efficiently.
1. **Setup the Infrastructure:** Initialize PostgreSQL (for incidents/users) and Redis (for real-time queues and caching) using Docker Compose.
2. **Implement Network Ingestion:**
   - *Prototype approach:* Write a Python script using `Scapy` to sniff packets and extract basic flow features (IPs, ports, protocol, packet sizes, duration).
   - *Production approach:* Deploy Suricata to monitor a network interface. Configure it to write EVE JSON logs.
3. **Data Queueing:** Write an ingestion script to read the captured features/logs and push them to a Redis Stream or RabbitMQ topic to ensure no data is lost during traffic spikes.

### Phase 2: Hybrid ML Detection Engine
**Goal:** Classify traffic and detect anomalies in real-time.
1. **Data Collection:** Gather a labeled dataset (e.g., CICIDS2017, UNSW-NB15) for training your models.
2. **Train Supervised Model (Known Attacks):** Train an XGBoost or Random Forest classifier on the dataset to identify known attack signatures (e.g., Port Scans, DDoS, Brute Force).
3. **Train Unsupervised Model (Anomalies):** Train an Autoencoder or LSTM purely on *normal* traffic. During real-time inference, high reconstruction errors will flag potential zero-day anomalies.
4. **Real-time Inference Service:** Create a Python worker service that consumes network events from the message broker, runs them through both ML models simultaneously, and outputs a "Normalized Security Alert" containing the confidence score and anomaly score. Push these alerts to a new message queue for the Agent.

### Phase 3: Agentic AI Incident Layer (The "Brain")
**Goal:** Correlate noisy alerts into cohesive incidents and generate human-readable explanations.
1. **Alert Grouping (Heuristics):** Write a module to continuously group incoming alerts by Source IP, Destination IP, and Time Window (e.g., all alerts from IP X in the last 5 minutes).
2. **Setup Local LLM:** Install Ollama and pull a capable model like `llama3`.
3. **Build the Agent Workflow (LangGraph/CrewAI):**
   - **Context Retrieval Tool:** Create a function the agent can call to query PostgreSQL for past incidents related to the current IPs involved in the alert group.
   - **Analysis Prompt:** Pass the grouped alerts and historical context to the LLM. Instruct it to determine if this represents a coordinated attack sequence and calculate a severity score based on predefined security policies.
   - **Explanation Generation:** Instruct the LLM to write a concise, evidence-based summary of why this incident was created (e.g., "Observed a port scan followed by multiple failed SSH logins").
4. **Save Incident:** Store the LLM's structured output (Incident ID, Attack Sequence, Evidence, Explanation, Severity) into PostgreSQL.

### Phase 4: Backend API (FastAPI)
**Goal:** Serve data to the frontend and handle real-time communication.
1. **REST Endpoints:** Create standard CRUD endpoints for fetching historical incidents, fetching raw alerts, and checking system status.
2. **WebSocket Integration:** Implement a WebSocket manager. When a new Incident is saved to the database by the AI Agent in Phase 3, broadcast this event immediately to all connected WebSocket clients.
3. **Reporting Endpoint:** Create an endpoint that takes an Incident ID, fetches the relevant data, renders an HTML template using Jinja2, and converts it to a downloadable PDF using WeasyPrint or ReportLab.

### Phase 5: Live Dashboard (React)
**Goal:** Build a beautiful, responsive user interface for security analysts.
1. **Scaffold App:** Initialize the app using `npm create vite@latest nids-dashboard -- --template react-ts`.
2. **State Management:** Set up a global state store (e.g., Zustand) to hold and manage the live alerts and incidents.
3. **WebSocket Client:** Connect the frontend to the FastAPI WebSocket to receive real-time incident updates and animate them onto the screen dynamically.
4. **UI Components:**
   - **Live Feed:** A scrolling, terminal-like feed of raw alerts coming from the ML engine.
   - **Incident Board:** Cards showing active incidents prioritized by the AI-assigned severity.
   - **Incident Details Modal:** A detailed view showing the AI's explanation, attack sequence, context, and a button to "Download PDF Report" or "Approve Response" (e.g., Block IP).

### Phase 6: Orchestration, Testing, and Simulation
**Goal:** Tie everything together and test against simulated attacks.
1. **Dockerize Everything:** Ensure the ML Engine, Agent Layer, FastAPI backend, and React frontend all have dedicated Dockerfiles.
2. **Master Docker Compose:** Create a root `docker-compose.yml` that brings up the entire stack seamlessly.
3. **Attack Simulation:** Use a tool like `tcpreplay` (to replay malicious PCAP files) or Kali Linux to generate live malicious traffic (Nmap scans, brute force attempts) against the monitored interface. Watch the system detect, correlate, explain, and report it on the dashboard in real-time.

---

## Conclusion
The proposed architecture is highly feasible and represents the cutting edge of modern Security Operations Center (SOC) automation. By implementing a message broker for scale, upgrading to industry-standard tools like Suricata/PyTorch, and leveraging a strong local model like Llama 3 for the agentic layer, you will have a robust, intelligent, and highly effective Network Intrusion Detection System.
