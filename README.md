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

Run it with:

```text
cd C:\Users\Aditya\Desktop\NIDS
python -m pip install -e ".[api,dev]"
python -m uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the interactive API.

Run that command from the repository root (`C:\Users\Aditya\Desktop\NIDS`).
Do not use `uvicorn main:app` from inside the `backend` directory; that loads
the module without its `backend` package context and causes an attempted
relative import error.

If your terminal is already inside `backend`, use:

```text
python -m uvicorn backend.main:app --app-dir .. --reload
```

The service exposes `/health`, `/capture/status`, `/capture/interfaces`,
`/capture/events`, `/capture/start`, `/capture/switch`, and `/capture/stop`.
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

Supported source modes are `live`, `pcap`, `suricata`, and `jsonl`.

#### Suricata and Zeek integration

Suricata and Zeek are the production-oriented Layer 1 capture engines. They
run beside this backend and write structured logs; the backend consumes those
logs as Layer 2 input. Scapy remains useful for a lightweight Windows/Kali
prototype and direct Wi-Fi demonstration.

Suricata integration is currently available through `eve.json`:

```json
{
  "mode": "suricata",
  "path": "data/suricata/eve.json"
}
```

Start Suricata on the monitored interface and configure EVE JSON output to
`data/suricata/eve.json`. Then call `POST /capture/start` or
`POST /capture/switch` from Swagger. The backend normalizes Suricata flow,
alert, and packet records into the shared `PacketEvent` contract, persists
them to JSONL, and publishes them to Redis.

Zeek follows the same adapter boundary, but its TSV/JSON log adapter is not
implemented yet. The planned flow is:

```text
Zeek conn.log / JSON logs
    -> backend Zeek source adapter
    -> PacketEvent normalization
    -> data/normalized/events.jsonl
    -> Redis Stream: nids:raw-events
```

This lets the capture engine be changed without changing the downstream ML
consumer. The next Zeek implementation should map `id.orig_h`, `id.resp_h`,
`id.orig_p`, `id.resp_p`, `proto`, `ts`, and `duration` into the common event
model.

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

The next ML worker will consume this stream using a Redis consumer group.

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
    Zeek logs (planned adapter)
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
