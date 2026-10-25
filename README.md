# SENTINEL-X 2.0 — AI-Based Network Security Monitoring and Deep Learning Anomaly Detection System

**SENTINEL-X 2.0** is an enterprise-grade, browser-based Security Operations Center (SOC) platform for real-time network traffic telemetry monitoring, hybrid risk scoring, and unsupervised Deep Learning Autoencoder anomaly detection.

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

3. **Real Network Monitoring (`Scapy`)**:
   - Captures actual live network packets on the host network interfaces.
   - Extracts source IP, destination IP, protocol, destination port, packet count, and traffic volume.
   - Dynamically respects configured accumulation intervals.
   - Transparent error logging (e.g. Npcap requirements on Windows) with explicit active/idle indicators.

4. **Strict Separation of Real Monitoring & Demo Simulation**:
   - Real network packets are tagged as `source_type = "REAL"`.
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

For example, in PowerShell, set the account values in the current terminal
before starting the app:

```powershell
$env:SENTINEL_ADMIN_PASSWORD = "your-unique-password"
python main.py
```

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

1. **Collect Baseline Telemetry**: Start real monitoring or run Demo Simulation to collect at least 10–20 normal network events in the SQLite database (or upload an offline CSV via the **Model Mgmt** or **Datasets** tab).
2. **Train Model**:
   - Navigate to the **Model Mgmt** tab in the web interface.
   - Click **🧠 TRAIN AUTOENCODER**.
   - The backend trains a 6-feature Autoencoder, saves `models/autoencoder.keras`, and computes the 95th-percentile dynamic anomaly threshold.
3. **Evaluate Model**:
   - Click **📈 EVALUATE MODEL** to test reconstruction errors across historical events.
4. **Live Inference**:
   - Every incoming network event is automatically evaluated by `ModelInference.predict()`, contributing its AI anomaly score to the overall risk calculation.

---

## 🌐 Real-Time Monitoring & Demo Mode

- **Real Monitoring**: Click **▶ START MONITOR** in the top toolbar on a supported host. Scapy captures actual packets flowing through the host network adapter and aggregates them according to the configured interval (default 1.5s).
- **Demo Monitoring**: On Render, or when `SENTINEL_MONITORING_MODE=demo`, the same start button starts continuous synthetic events. The dashboard identifies this as **DEMO MONITORING**, and each event is tagged `DEMO`; it is not real network telemetry.
- **Demo Mode**: Click **⚡ DEMO SIMULATION** to trigger high-volume synthetic threat scenarios for demonstrations without generating real network flood.

---

## 🧪 Automated Testing

Run the comprehensive unit test suite:
```bash
python -m pytest
```
All 20 test cases pass, verifying database migrations, authentication, risk detection, ML training, ML inference, API endpoints, PDF generation, system status, and dataset management.

---

## ⚠️ System & Security Limitations

1. **Transport Layer Metadata vs. Deep Packet Inspection**: Feature extraction focuses on packet frequencies, ports, protocols, and volume. Encrypted payloads (e.g. HTTPS TLS payloads) are analyzed by traffic pattern rather than plaintext inspection.
2. **Scapy Windows Capture Requirements**: Live packet capture requires Administrator privileges and Npcap installed with WinPcap compatibility mode.
