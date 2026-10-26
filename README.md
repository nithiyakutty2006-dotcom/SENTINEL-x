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

3. **Opt-in Windows TCP Connection Sensor**:
   - A separate command-line process polls the selected Windows interface's TCP connection table; it does not open packet-capture devices or read packet bytes.
   - It starts only after an explicit `--run --interface ...` command; it is not auto-started by the website.
   - Packet and byte counts are unavailable from this collection method and remain null rather than being estimated.

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
│   ├── monitoring.py           # Existing local Scapy monitor and demo lifecycle
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
├── sensor/                     # Opt-in Windows connection-table sensor
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
- Windows PowerShell and the built-in `NetTCPIP` networking cmdlets (used by the no-payload sensor).
- Npcap is only required if you explicitly use the existing legacy Scapy packet-capture mode; it is not used by the new connection-table sensor.

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
python -m uvicorn main:app --host 127.0.0.1 --port 8011
```

Keep the terminal running while testing. Uvicorn is a foreground process and
stops when you press Ctrl+C or close its terminal. If startup succeeds, it logs
that it is running at `http://127.0.0.1:8011`.

### Option B: Using Windows Batch Launcher
Double-click `run.bat` or run:
```cmd
run.bat
```

### Browser URL:
Open any web browser and navigate to:
👉 **[http://127.0.0.1:8011](http://127.0.0.1:8011)**

### Windows local sensor workflow (two PowerShell windows)

The local launcher stores its SQLite database and a DPAPI-protected sensor
secret under `%LOCALAPPDATA%\SentinelX`, outside OneDrive. Keep both windows
open while monitoring:

1. In PowerShell window A, from the project folder, run
   `.\scripts\start_local_server.ps1`. Enter the local admin password at the
   hidden prompt. On a new database it initializes the `admin` account; for an
   existing local database, enter the existing account's password.
2. In PowerShell window B, from the same project folder, run
   `.\scripts\start_local_sensor.ps1`. It checks the backend and sensor
   credentials, lists active adapters, then asks for the exact interface name
   whose TCP connection table should be polled.
3. Open `http://127.0.0.1:8011/` and log in as `admin`. Press Ctrl+C in window
   B to stop the sensor; leave window A open until you are finished.

The sensor reports this laptop's observable TCP connection metadata only. It
does not capture packet payloads or packet/byte counts, does not provide UDP
remote endpoints, and cannot see the phone's traffic or other hotspot clients.

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

The API uses a server-verified, database-backed session cookie for dashboard
and operational routes. The cookie is HttpOnly and SameSite=Lax; roles for
privileged operations are read from the authenticated database account, not
from client-supplied query parameters. Keep the service's Environment settings
and login credentials private.

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

The sensor runs on the Windows laptop and reads TCP connection metadata exposed by Windows for a selected interface. It never captures packet bytes. Render only receives telemetry; it does not observe traffic from Render or your hotspot. The single configured sensor identity is set on the backend with `SENTINEL_SENSOR_ID` and `SENTINEL_SENSOR_SECRET`. Set the same values locally in the sensor terminal. Use a unique sensor ID (letters, digits, `.`, `_`, or `-`) and a randomly generated secret of at least 32 characters. Keep the secret only in Render's private Environment settings and the local process environment; never put it in source, `.env` committed to Git, browser JavaScript, or chat.

Deploy the backend revision containing the `/api/sensors/validate`,
`/api/sensors/heartbeat`, and `/api/sensors/ingest` routes before starting this
sensor. The current public Render service has health, heartbeat, and ingest
routes but does not yet expose `/api/sensors/validate`; the sensor check will
fail until a revision that adds that route is deployed. Its health endpoint
currently reports `NOT CONFIGURED` until the sensor identity is added privately
to the Render service Environment.

### Install and configure

1. Install Python dependencies from the project folder:

   ```powershell
   python -m pip install -r requirements.txt
   ```

2. No Npcap or other packet-capture driver is required by this sensor. Windows PowerShell's `Get-NetAdapter`, `Get-NetIPAddress`, and `Get-NetTCPConnection` cmdlets provide the connection table. Administrator elevation is not a packet-capture prerequisite, but may be needed to see connections owned by other users.
3. In the same PowerShell terminal that will run the sensor, generate the
   secret without printing it. The command copies it to the clipboard so it can
   be pasted into Render's private Environment form; do not save or share the
   value elsewhere:

   ```powershell
   $env:SENTINEL_SENSOR_ID = "windows-laptop-01"
   $env:SENTINEL_SENSOR_URL = "https://sentinel-x-72rs.onrender.com"
   $sensorSecretBytes = New-Object 'System.Byte[]' 48
   $randomGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
   try {
       $randomGenerator.GetBytes($sensorSecretBytes)
       $env:SENTINEL_SENSOR_SECRET = [Convert]::ToBase64String($sensorSecretBytes)
       Set-Clipboard -Value $env:SENTINEL_SENSOR_SECRET
   } finally {
       $randomGenerator.Dispose()
       [Array]::Clear($sensorSecretBytes, 0, $sensorSecretBytes.Length)
   }
   Write-Host "Sensor ID and secret are ready; the secret was not displayed."
   ```

   Add those exact variable names to Render's private service Environment:
   use the shown sensor ID and paste the clipboard secret into
   `SENTINEL_SENSOR_SECRET`. Save the values only after the backend revision is
   deployed so the service restarts with the new configuration. These local
   environment variables apply only to processes started from this terminal.
   Clear the clipboard after pasting the secret.
5. For the broadest connection-table visibility, open VS Code **as Administrator**. Start with a non-capturing configuration check:

   ```powershell
   python -m sensor.windows_sensor --check
   ```

   This lists active Windows interfaces and checks backend reachability/configuration; it does **not** start polling. Resolve any displayed issue before proceeding.
6. Choose the active laptop hotspot/Wi-Fi interface name printed by `--check` and explicitly start polling:

   ```powershell
   python -m sensor.windows_sensor --run --interface "Wi-Fi"
   ```

   Replace `"Wi-Fi"` with the exact interface name printed by `--check`. Press **Ctrl+C** to stop. Nothing starts automatically. The sensor checks the TCP connection table every two seconds and sends signed heartbeats every 30 seconds. Public health status is available at `/api/sensors/health`; verify it from PowerShell with:

   ```powershell
   Invoke-RestMethod "https://sentinel-x-72rs.onrender.com/api/sensors/health" | Format-List
   ```

   A recent heartbeat sets `connected` to `True`, but that alone does not confirm event ingestion. `status` is `CONNECTED` only when a recent telemetry event was also received; otherwise it reports `NO RECENT EVENTS`. A stale heartbeat reports `DISCONNECTED`, and a sensor-reported upload failure reports `ERROR`. The dashboard also shows the last event, last successful upload, and a sanitized last-upload error code if one was reported.

### Collection and security boundaries

- The sensor emits timestamps, IPv4/IPv6 TCP local/remote addresses and ports, connection state, and a connection identifier when Windows exposes them. It does not read packet contents. Windows' connection table does not provide per-flow packet or byte counts here; those fields are stored as `N/A`, not guessed. UDP remote endpoints are not provided by this TCP-table sensor and are not synthesized.
- Telemetry is validated and tagged `LIVE` by the backend; clients cannot choose `DEMO`/`LIVE` source labels. Dashboard statistics default to a LIVE-only view, with explicit DEMO and ALL choices. Device inventory is grouped by source.
- Requests use HTTPS and HMAC-SHA256 signatures over the timestamp, one-time nonce, and exact request body. The backend rejects expired/replayed requests, enforces a request-rate limit, and validates every telemetry field. The local retry queue is memory-only; unsent events are lost when the process exits or its bounded queue overflows. Failed upload codes are reported on the next successful signed heartbeat.
- The sensor uses HMAC for telemetry writes; the separate dashboard and API require a server-verified web session. Configure and deploy the backend changes before sending telemetry.
- This sensor observes only TCP connections visible on the selected laptop interface. On a normal phone hotspot, the laptop generally cannot see the phone's other traffic. The dashboard note is intentional: “Monitoring traffic observable on this laptop; other hotspot-device traffic is not guaranteed to be visible.” Whole-LAN visibility needs a gateway/router flow exporter or managed switch mirror feed; a mobile hotspot usually offers neither. Do not enable mirroring without network-owner authorization.
- LIVE telemetry means observed metadata, not proof of malicious activity. Rules and baselines produce suspicion signals for analyst review, not confirmed attacks. Incidents/alerts are not ground-truth labels.

### Model status and evaluation

The inference feature order is `packets`, traffic in MB, connections, unknown-destination count, destination port, and protocol code; training, scaling, and inference use the same six-feature order and the existing min/max `FeatureScaler`. Connection-table LIVE events have no packet/byte counters and are excluded from model scoring/training rather than assigned invented zero values. Runtime model/scaler artifacts are not present in the repository, so a fresh installation reports **NOT TRAINED** and provides no model score. Dataset and DEMO events are excluded from live-history training and evaluation. The displayed autoencoder score is an anomaly score, not a probability or confidence. Evaluation reports reconstruction-error distribution only; it does not report accuracy, precision, recall, or F1 without labeled ground-truth data. No measured attack-detection accuracy is claimed.

---

## 🧪 Automated Testing

Run the unit test suite from PowerShell with a temporary database so test
fixtures cannot modify the application's local database:

```powershell
$testData = Join-Path $env:TEMP ('sentinel-x-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testData | Out-Null
$testExitCode = 1
try {
    $env:SENTINEL_DATA_DIR = $testData
    python -m pytest
    $testExitCode = $LASTEXITCODE
} finally {
    Remove-Item Env:SENTINEL_DATA_DIR -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testData -Recurse -Force
}
if ($testExitCode -ne 0) { exit $testExitCode }
```

The suite covers database migrations, authentication, monitoring, model feature
preprocessing/inference, APIs, and sensor telemetry. `SENTINEL_DATA_DIR` must
be set before Python imports the application.

---

## ⚠️ System & Security Limitations

1. **Detection is not validated attack classification**: Rule and baseline thresholds are configurable heuristics. Anomaly scores are not confidence values. No measured attack-detection accuracy is claimed.
2. **Legacy Scapy capture**: The separate existing web monitor can still use packet capture when explicitly configured. It is not used by the new Windows sensor. Do not use that legacy path if your requirement is strict no-payload capture.
