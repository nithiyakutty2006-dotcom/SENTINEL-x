# SENTINEL-X 2.0 — AI-Based Network Security Monitoring and Deep Learning Anomaly Detection System

**SENTINEL-X 2.0** is a browser-based Security Operations Center (SOC) application for network-flow telemetry, explainable rule/baseline risk scoring, and optional unsupervised anomaly scoring. It is a monitoring prototype, not a validated attack-detection product.

---

## 🚀 Key Features

1. **Web-Based SOC Dashboard (`FastAPI + HTML5/CSS3/JavaScript + Chart.js`)**:
   - High-contrast cybersecurity dark theme with Cyan and Green telemetry indicators.
   - Interactive Chart.js time-series telemetry charts showing live system risk scores and severity distributions.
   - Real-time fallback placeholder: Displays `"WAITING FOR NETWORK TELEMETRY"` whenever telemetry is pending.
   - Live Threat Feed stream updating in real-time with explainable AI detection factors.

2. **12 Comprehensive Operations Center Tabs**:
   - **Dashboard**: High-level SOC metrics, live telemetry risk graph, severity doughnut chart, and live threat feed.
   - **Events**: Searchable, filterable, and paginated network telemetry event records with detailed modal inspector.
   - **Incidents**: Open, Investigating, and Resolved lifecycle triage center.
   - **Devices**: Endpoint baseline telemetry profiling, average traffic, packet rates, and incident correlation.
   - **Alerts**: Dispatched threat notification channel tracking with acknowledgment capabilities.
   - **Audit Log**: Immutable operator and system audit trail for security accountability.
   - **AI Model Management**: Train, evaluate, reload, and review Autoencoder neural network status.
   - **Datasets**: Dedicated dataset repository tracking imported CSV network captures and sample counts.
   - **Reports**: Instant PDF executive compliance summaries (PyMuPDF / ReportLab) and raw CSV telemetry export.
   - **Settings**: Configurable critical/high thresholds, accumulation interval, and hybrid AI toggle.
   - **Help & System Status**: Live platform diagnostics, network interface diagnostics, and operator guide.
   - **Logout**: Secure session termination.

3. **Opt-in Windows Network Sensor (`Scapy` / Npcap)**:
   - A separate command-line sensor can aggregate selected-interface IPv4/IPv6 TCP/UDP flow metadata and send it to the backend over HTTPS.
   - It starts only after an explicit `--run --interface ...` command; it is not auto-started by the website.
   - See the Windows sensor section below for Npcap, administrator permissions, and capture limitations.

4. **Strict Separation of Real Monitoring & Demo Simulation**:
   - Legacy host-captured packets are tagged as `source_type = "REAL"`; authenticated local sensor telemetry is tagged as `source_type = "LIVE"`.
   - Synthetic test scenarios are tagged as `source_type = "DEMO"`.
   - Offline imported captures are tagged as `source_type = "DATASET"`.

5. **Deep Learning Autoencoder (`TensorFlow / Keras`)**:
   - Neural network architecture: `Input(6) -> Dense(16) -> Dropout(0.1) -> Dense(8, Latent) -> Dense(16) -> Dense(6)`.
   - Dynamic 95th-percentile Mean Squared Error (MSE) reconstruction thresholding.
   - Model Management dashboard for dataset imports, Autoencoder training, and evaluation metrics.

6. **Hybrid AI + Rule-Based Risk Engine**:
   - Integrates rule violations, statistical endpoint baselines, and neural network anomaly scores into a unified 0–100 risk score.
   - Automated incident deduplication and alert dispatching when risk $\ge 60\%$.

7. **Role-Based Access Control (RBAC)**:
   - **ADMIN**: Full control (Start/Stop monitoring, change settings, train ML models, manage incidents).
   - **ANALYST**: Operational access (Investigate incidents, acknowledge alerts, evaluate models).
   - **VIEWER**: Read-only access to dashboards, events, and reports.

8. **Automated Compliance & Reporting**:
   - Executive PDF security reports generated dynamically with PyMuPDF / ReportLab.
   - Full CSV telemetry export for offline forensic analysis.

---

## 📁 Project Structure

```text
SENTINEL-X/
├── main.py                     # FastAPI entry point & static file server (Port 8000)
├── requirements.txt            # Python dependencies
├── run.bat                     # Windows one-click launcher
├── README.md                   # Complete system documentation
├── sentinel_x_v2.db            # Local SQLite data (gitignored)
├── project3.py                 # Local-only legacy Tkinter backup (gitignored)
├── project3_backup.py          # Local-only legacy backup (gitignored)
│
├── app/                        # Web backend modules
│   ├── __init__.py
│   ├── database.py             # SQLite connection, migrations, tables
│   ├── auth.py                 # Authentication, SHA-256 hashing, RBAC
│   ├── paths.py                # Configurable runtime data directory
│   ├── passwords.py            # Password hashing helpers
│   ├── detection.py            # Hybrid AI + baseline + rule risk engine
│   ├── monitoring.py           # Scapy packet sniffer & telemetry accumulator
│   ├── reports_gen.py          # Dual PyMuPDF & ReportLab PDF / CSV generator
│   └── api.py                  # Complete REST API routes (12+ endpoints)
│
├── frontend/                   # Web interface
│   ├── index.html              # 12 SOC tab views, modals, Chart.js canvases
│   ├── css/
│   │   └── style.css           # Cybersecurity dark styling
│   └── js/
│       └── app.js              # Interactive UI, chart rendering, API polling
│
├── ml/                         # Machine Learning pipeline
│   ├── __init__.py
│   ├── preprocessing.py        # Feature scaling & normalization
│   ├── train.py                # Autoencoder training & threshold calculation
│   ├── inference.py            # Live MSE error & anomaly prediction
│   ├── evaluation.py           # Model evaluation metrics calculation
│   └── model_manager.py        # Model lifecycle, dataset imports, SQLite sync
│
├── models/                     # Saved Keras models and scalers (.keras, .pkl)
├── data/                       # Datasets & offline CSV telemetry
├── reports/                    # Generated PDF reports
└── tests/                      # Automated test suite
    ├── test_complete_suite.py  # 18+ comprehensive unit & API tests
    ├── test_inference.py       # Inference tests
    └── test_preprocessing.py   # Preprocessing tests
```

---

## ⚡ Installation & Setup

### 1. Prerequisites
- **Python 3.9+** (Tested and verified on Python 3.13)
- Windows packet capture driver: [Npcap](https://npcap.com/) (Required for Scapy live sniffing on Windows).

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🖥️ Running the Application

### Option A: Using Python Command
```bash
python main.py
```
or:
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### Option B: Using Windows Batch Launcher
Double-click `run.bat` or run:
```cmd
run.bat
```

### Browser URL:
Open any web browser and navigate to:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 🔑 Login Accounts (RBAC)

The web application does not ship with default login passwords. On an empty
database, set `SENTINEL_ADMIN_PASSWORD` and optionally the analyst/viewer
username and password pairs shown in `.env.example` before startup. These values
are used only to initialize an empty users table; they do not overwrite users
in an existing database. `.env.example` documents the variable names but is not
loaded automatically; set the values in your shell or hosting provider. Keep
real values out of source control.

In the VS Code integrated PowerShell terminal, set the account values in that
terminal before starting the app. Use a unique password you choose; do not use
the placeholder from `.env.example` as a real password:

```powershell
$env:SENTINEL_ADMIN_USERNAME = "admin"
$env:SENTINEL_ADMIN_PASSWORD = "your-unique-password"
python main.py
```

Then sign in with username `admin` and the password you set. The environment
variables apply only to processes started from that terminal. Alternatively,
configure them in your VS Code launch configuration's `env` settings. The
`.env.example` file is documentation only and is not loaded automatically.
These variables bootstrap accounts only when the database users table is empty;
they do not change credentials in an existing database.

## ☁️ Deploying the Existing App to Render

The checked-in [`render.yaml`](./render.yaml) defines the Web Service build and
start commands and selects demo monitoring. For an existing Render Web Service,
update its settings to match this file (or sync it if it is already
Blueprint-managed); do not create a second service just for this change or add a
conflicting start command.

- **Python version environment variable:** `PYTHON_VERSION=3.13.12` (matches the
  locally tested Python version)
- **Build command:** `pip install -r requirements.txt`
- **Start command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
- **Monitoring mode:** `SENTINEL_MONITORING_MODE=demo`

Set `SENTINEL_ADMIN_PASSWORD` in Render's service Environment settings to a new,
unique password. Optionally set the analyst/viewer environment variable pairs
from `.env.example`. Do not upload `.env` or database files to GitHub.

Render's default service filesystem is ephemeral. Attach a paid Render
persistent disk mounted at `/var/data`, then set `SENTINEL_DATA_DIR` to
`/var/data` in the service Environment settings. SQLite, trained model/scaler
files, and generated PDF reports are stored there. Imported CSV datasets are
stored in SQLite rather than as standalone files. Without a persistent disk,
these runtime changes can be lost on restarts, spin-downs, or redeploys.

Scapy live packet capture depends on host interfaces and capture permissions
that Render does not provide like a local machine. `SENTINEL_MONITORING_MODE`
supports `auto`, `real`, and `demo`: `auto` (the default) selects explicitly
labeled Demo Monitoring on Render and real Scapy capture on other hosts.
Set `SENTINEL_MONITORING_MODE=demo` on other hosted platforms that do not permit
packet capture. Demo Monitoring continuously creates synthetic events marked
`DEMO`; it never represents them as live network traffic. Set
`SENTINEL_MONITORING_MODE=real` only on a host with a supported interface and
packet-capture permissions. A capture initialization failure is reported in
the dashboard rather than shown as active monitoring.

TensorFlow/Keras make this service substantially heavier than a static site.
Check Render build and runtime logs and choose a compute plan with sufficient
memory. Free services also have filesystem and availability limitations.

**Public deployment warning:** the current API accepts user/role values from
client-supplied query parameters for several privileged operations and does
not establish server-verified sessions. The login screen alone does not secure
the API. Do not put real network telemetry or sensitive data on a public
instance until server-side authorization is implemented and verified.

---

## 🧠 Deep Learning Workflow

1. **Collect Baseline Telemetry**: The current training path uses only LIVE/legacy REAL events labeled LOW, NORMAL, or MEDIUM. DEMO and DATASET events are excluded.
2. **Train Model**:
   - Navigate to the **Model Mgmt** tab in the web interface.
   - Click **🧠 TRAIN AUTOENCODER**.
   - The backend trains a 6-feature Autoencoder and saves its model plus a scaler tagged with the exact feature order/schema. A model or scaler that does not match the current schema is rejected.
3. **Evaluate Model**:
   - Click **📈 EVALUATE MODEL** to review unsupervised reconstruction-error distribution on LIVE/REAL events. No supervised accuracy metrics are available without labeled ground truth.
4. **Live Inference**:
   - A model score contributes to risk only when compatible trained artifacts are loaded. Otherwise status is NOT TRAINED or INVALID ARTIFACT and the score is N/A.

---

## 🌐 Real-Time Monitoring & Demo Mode

- **Legacy host monitoring**: The existing **▶ START MONITOR** can capture on the application host when configured for real capture and supported by its OS/permissions. Render is explicitly configured for Demo mode and does not sniff Render or your home network.
- **Demo Monitoring**: On Render, or when `SENTINEL_MONITORING_MODE=demo`, the same start button starts continuous synthetic events. The dashboard identifies this as **DEMO MONITORING**, and each event is tagged `DEMO`; it is not real network telemetry.
- Demo events use the separate `DEMO-SENSOR-01` inventory entry. Every fifth event is an explicitly simulated high-risk example so the configured detection rules can demonstrate incident and alert creation; those pages remain empty until an event meets the risk trigger.
- **Demo Mode**: Click **⚡ DEMO SIMULATION** to trigger high-volume synthetic threat scenarios for demonstrations without generating real network flood.

## 🪟 Opt-in Windows Sensor for LIVE Telemetry

The sensor runs on the Windows PC and sends flow metadata to the configured SENTINEL-X backend. Render only receives telemetry; it does not capture packets from Render or your LAN. The single configured sensor identity is set on the backend with `SENTINEL_SENSOR_ID` and `SENTINEL_SENSOR_SECRET`. Set the exact same values locally in the sensor terminal. Use a unique sensor ID (letters, digits, `.`, `_`, or `-`) and a randomly generated secret of at least 32 characters. Keep the secret only in Render's private Environment settings and the local process environment; never put it in source, `.env` committed to Git, browser JavaScript, or chat.

### Install and configure

1. Install Python dependencies from the project folder:

   ```powershell
   python -m pip install -r requirements.txt
   ```

2. Install **Npcap** from [npcap.com](https://npcap.com/). Select the option to enable WinPcap API-compatible mode if the installer offers it. Restart the terminal after installation.
3. In the Render service's **Environment** settings, add `SENTINEL_SENSOR_ID` and `SENTINEL_SENSOR_SECRET`. Generate a secret locally (do not share it):

   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Copy the generated value directly into Render's private Environment UI and your local PowerShell environment. Do not put the value in `render.yaml`.
4. Open **VS Code as Administrator** so Npcap access has the required permissions. In its PowerShell terminal, set the same identity and secret and the public URL:

   ```powershell
   $env:SENTINEL_SENSOR_ID = "your-configured-sensor-id"
   $env:SENTINEL_SENSOR_SECRET = "the-secret-you-generated-locally"
   $env:SENTINEL_SENSOR_URL = "https://sentinel-x-72rs.onrender.com"
   ```

   These are placeholders: replace them locally with the values configured in Render. The environment applies only to processes started from this terminal.
5. Start the web application separately if running it locally. For sensor-only local validation, the deployed Render site can receive telemetry:

   ```powershell
   python -m sensor.windows_sensor --check
   ```

   This checks Windows, Npcap visibility, administrator access, HTTPS reachability, and matching server sensor identity; it does **not** start packet capture. If any check fails, resolve the displayed issue before proceeding.
6. Review the listed Npcap interface names and explicitly start capture on the exact interface you intend to monitor:

   ```powershell
   python -m sensor.windows_sensor --run --interface "\Device\NPF_{INTERFACE-GUID}"
   ```

   Replace the example with an exact interface printed by `--check`. Press **Ctrl+C** to stop. Nothing starts capture automatically. The sensor sends a signed heartbeat every 30 seconds and batches flow metadata about every 10 seconds.    Public health status is available at `/api/sensors/health`; verify it from PowerShell with:

   ```powershell
   Invoke-RestMethod "https://sentinel-x-72rs.onrender.com/api/sensors/health" | Format-List
   ```

   Confirm `configured` and `online` are `True` while the sensor is running. The dashboard also shows sensor status and last event time.

### Collection and security boundaries

- The sensor aggregates timestamps, IP addresses, ports, protocol, observed packet/byte counts, and a 5-tuple flow identifier. It does not intentionally parse, persist, or transmit packet payload contents. Telemetry is validated and tagged `LIVE` by the backend; clients cannot choose `DEMO`/`LIVE` source labels.
- **Important packet-capture limitation:** Npcap/Scapy delivers a bounded 128-byte packet prefix to the local Python process so Scapy can decode network and transport headers. The sensor does not retain or upload that prefix, but payload bytes may transiently be present in process memory. Therefore this is not a strict zero-payload capture boundary and cannot guarantee that a credential never appears in that transient prefix. For environments requiring strict payload exclusion, do not run this sensor; use a trusted NetFlow/IPFIX or equivalent metadata-only exporter and an appropriately reviewed adapter.
- Requests use HTTPS and HMAC-SHA256 signatures over the timestamp, one-time nonce, and exact request body. The backend rejects expired/replayed requests, enforces a request-rate limit, and validates every telemetry field. The sensor's retry queue is memory-only; unsent events are lost when the process exits or its bounded queue overflows.
- Sensor HMAC protects telemetry writes, but it does not protect the existing dashboard/read APIs. The public deployment warning below still applies: do not send sensitive or production telemetry to the public Render site until server-side user authorization also protects access to stored telemetry.
- This sensor observes only traffic visible to the selected PC interface. Whole-LAN visibility requires a gateway/router sensor or a managed switch configured with a SPAN/mirror port feeding a dedicated sensor interface. Do not enable port mirroring without network-owner authorization.
- LIVE telemetry means observed metadata, not proof of malicious activity. Rules and baselines produce suspicion signals for analyst review, not confirmed attacks. Incidents/alerts are not ground-truth labels.

### Model status and evaluation

The inference feature order is `packets`, traffic in MB, connections, unknown-destination count, destination port, and protocol code; training, scaling, and inference use the same six-feature order and the existing min/max `FeatureScaler`. Runtime model/scaler artifacts are not present in the repository, so a fresh installation reports **NOT TRAINED** and provides no model score. Dataset and DEMO events are excluded from live-history training and evaluation. The displayed autoencoder score is an anomaly score, not a probability or confidence. Evaluation reports reconstruction-error distribution only; it does not report accuracy, precision, recall, or F1 without labeled ground-truth data. No measured attack-detection accuracy is claimed.

---

## 🧪 Automated Testing

Run the unit test suite:
```bash
python -m pytest
```
The suite covers database migrations, authentication, monitoring, model feature preprocessing/inference, APIs, and sensor telemetry. Use isolated `SENTINEL_DATA_DIR` when running tests to avoid changing a local database.

---

## ⚠️ System & Security Limitations

1. **Detection is not validated attack classification**: Rule and baseline thresholds are configurable heuristics. Anomaly scores are not confidence values. No measured attack-detection accuracy is claimed.
2. **Scapy Windows Capture Requirements**: Packet capture requires Administrator privileges and Npcap. See the documented bounded-prefix limitation above; strict payload exclusion requires a metadata-only exporter rather than the bundled packet sensor.
