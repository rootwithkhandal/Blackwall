# BlackWall

**A homelab-grade Security Operations Centre firewall with ML anomaly detection, blockchain-backed logging, webhook alert forwarding, and a premium Streamlit dashboard.**

---

## Overview

BlackWall turns your Linux machine into a mini SOC. It captures live network packets with Scapy, evaluates them against a dynamic rule set, detects anomalies with an IsolationForest ML model, logs every decision to an immutable ledger, forwards DROP/BAN events via webhooks, and presents everything through an interactive Streamlit dashboard.

---

## What's New

| Area | Upgrade |
|---|---|
| **Architecture** | Python monorepo — `packages/core` (engine) + `packages/dashboard` (Streamlit UI), each with its own `pyproject.toml` |
| **Anomaly detection** | IsolationForest ML model replaces static rate-limit auto-ban — catches slow-and-low attacks |
| **Webhook integration** | Fire-and-forget alert forwarding to Discord or Slack |
| **Firewall engine** | Rule persistence (JSON), rule deletion, automatic IP banning, native OS firewall integration |
| **Ledger** | Stable JSON-serialised data logging, one-click JSON export |
| **Dashboard** | Premium dark theme, glassmorphism cards, gradient accents, Plotly dark charts, live ML status badge, block inspector |
| **Design system** | Custom Streamlit theme, Inter font, color-coded stats, animated sidebar, styled empty states |
| **API** | Built-in FastAPI server for REST integration |

---

## Tech Stack

| Component | Library |
|---|---|
| UI | Streamlit ≥ 1.35 |
| Packet capture | Scapy ≥ 2.6 |
| ML detection | scikit-learn ≥ 1.4 (IsolationForest) |
| API | FastAPI & Uvicorn |
| Cryptography | cryptography ≥ 42 |
| Charts | Plotly ≥ 5.22 |
| Data | Pandas ≥ 2.2 |

Python 3.11+ recommended.

---

## Features

### 🧠 ML Anomaly Detection
- IsolationForest model baselines normal traffic for 5 minutes on startup
- Scores per-IP traffic windows using packet rates and protocol entropy
- Auto-bans IPs flagged as outliers — catches slow-and-low attacks that never trip a static threshold

### 📡 Webhook Alert Forwarding
- POSTs auto-ban events to **Discord** or **Slack** webhooks
- Fire-and-forget via background thread — zero impact on packet processing
- Configured via environment variables; no-op when unconfigured

### 🖥️ Live Logs & Block Inspector
- Auto-refreshing packet feed
- Filter by source IP, protocol, and verdict
- Inspect specific traffic blocks with the Block Inspector page

### 📊 Threat Stats
- Cumulative counters: total, allowed, dropped, auto-banned
- Protocol distribution pie chart
- Verdict distribution pie chart
- Top-10 talkers and top-10 targeted ports

### 📋 Manage Rules
- Add rules with action, IP, port, protocol, and a free-text comment
- View all active rules in a sortable table
- Delete any rule by ID — change is persisted to `rules.json` and logged to the ledger

### 🚫 Banned IPs
- Lists all auto-banned IPs with one-click unban

### 💾 Export Ledger
- Download the full JSONL ledger file directly from the UI.

---

## Project Structure

```
BlackWall/
├── packages/
│   ├── core/                          # Engine (pip: "blackwall")
│   │   ├── blackwall/
│   │   │   ├── __init__.py
│   │   │   ├── api.py                 # FastAPI server
│   │   │   ├── firewall.py            # Firewall engine — rules, ML-based auto-ban, Webhook
│   │   │   ├── ml_detector.py         # IsolationForest anomaly detector
│   │   │   ├── os_firewall.py         # Native OS iptables integration
│   │   │   ├── simulator.py           # Attack simulation
│   │   │   └── threat_intel.py        # Threat intelligence
│   │   └── pyproject.toml
│   │
│   └── dashboard/                     # Streamlit UI (pip: "blackwall-dashboard")
│       ├── dashboard/
│       │   ├── __init__.py
│       │   ├── app.py                 # Entry point — init, CSS injection, page routing
│       │   └── pages/
│       │       ├── __init__.py
│       │       ├── banned_ips.py
│       │       ├── block_inspector.py
│       │       ├── export_ledger.py
│       │       ├── live_logs.py
│       │       ├── manage_rules.py
│       │       └── threat_stats.py
│       └── pyproject.toml
│
├── .streamlit/
│   └── config.toml                    # Custom dark theme (colors, font)
├── scripts/
│   └── install.sh                     # Automated setup (Linux / macOS)
├── data/                              # Runtime files (git-ignored)
├── pyproject.toml                     # Root workspace config
├── mise.toml                          # Task runner (mise)
├── .env                               # Credentials (git-ignored)
├── .env.example                       # Credential template
├── .gitignore
├── LICENSE
└── README.md
```

---

## Getting Started

### One-Command Deployment (Docker - Recommended)

The easiest way to run BlackWall without worrying about Python dependencies or root capabilities is using Docker Compose.

```bash
git clone https://github.com/rootwithkhandal/blackwall.git
cd blackwall

# Start BlackWall in the background
docker compose up -d
```
You can now access the dashboard at `http://localhost:8501`.

### Quick Start (mise)

```bash
git clone https://github.com/rootwithkhandal/blackwall.git
cd blackwall

# Install all packages
pip3 install -r requirements.txt

# Run the dashboard
streamlit run packages/dashboard/dashboard/app.py
```

### Attack Simulation Mode

For demos, CTFs, or job interviews, you can launch BlackWall in simulation mode.

```bash
streamlit run packages/dashboard/dashboard/app.py -- --simulate
```
*Note: Simulation mode truncates the ML baseline duration from 5 minutes to 5 seconds so auto-bans occur almost immediately.*

### Testing with Real Traffic (Ping Flood)
Alternatively, you can test the ML Anomaly detector using live network traffic. Start the BlackWall dashboard normally, wait for the baseline to finish, and then execute a continuous ping flood from another terminal.

### Multi-User Authentication
On the first run, BlackWall automatically generates a `data/auth_config.yaml` file to secure the dashboard with `streamlit-authenticator`.
The default credentials are:
- **Admin**: `admin` / `admin123`
- **Demo User**: `demo` / `demo123`

You can change these passwords or add new users by editing the `data/auth_config.yaml` file.

### Manual Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e packages/core
pip install -e packages/dashboard

streamlit run packages/dashboard/dashboard/app.py
```

> **Linux note:** Scapy requires root (or `CAP_NET_RAW`) for live capture.

### Running as a Service (Linux)

```bash
sudo cp scripts/blackwall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blackwall
```

---

## Integrations & APIs

### Discord / Slack Webhook Alerts

To receive instant notifications when the dashboard detects a massive traffic spike or attack:

```bash
export WEBHOOK_URL=https://discord.com/api/webhooks/...
```
BlackWall automatically formats the alert properly for either Discord or Slack.

### REST API

BlackWall automatically runs a FastAPI server concurrently with the dashboard on port `8000`.

- `GET http://localhost:8000/rules` - Returns all active firewall rules.
- `GET http://localhost:8000/banned` - Returns a list of auto-banned IPs.
- `GET http://localhost:8000/stats` - Returns live traffic metrics.
- `GET http://localhost:8000/ledger?limit=50` - Returns the JSONL ledger.

---

## Configuration

| Setting | Location | Default |
|---|---|---|
| ML baseline duration | `packages/core` → `ml_detector.py` → `BASELINE_DURATION` | 300 s (5 min) |
| ML scoring window | `packages/core` → `ml_detector.py` → `WINDOW_SECONDS` | 10 s |
| Dashboard theme | `.streamlit/config.toml` | Deep purple dark theme |
| Webhook URL | env var `WEBHOOK_URL` | _(disabled)_ |
| AbuseIPDB API key | env var `ABUSEIPDB_KEY` | _(disabled)_ |
| Shodan API key | env var `SHODAN_KEY` | _(disabled)_ |

### Enabling the GeoIP World Map

To see a beautiful choropleth heatmap of attack origins on the Threat Stats page:
1. Ensure the `geoip2` Python library is installed.
2. Download the **GeoLite2-Country** database (MMDB format) from MaxMind.
3. Place the `GeoLite2-Country.mmdb` file inside the `data/` directory.

---

## Development

The project uses a Python monorepo pattern with two packages:

- **`packages/core`** (`blackwall`) — the engine: firewall, ML detector, API, simulator.
- **`packages/dashboard`** (`blackwall-dashboard`) — the Streamlit UI.

Both are installed as editable packages (`pip install -e`), so changes are reflected immediately without reinstalling.

---

## Security Notes

- The dashboard is intended for isolated homelabs. Do not expose it to the public internet without authentication.
- **Firewall Persistence**: On Linux, iptables rules are automatically saved.

---

## Roadmap

- [x] ML-based anomaly detection (IsolationForest)
- [x] API Server for SOC tools integration
- [x] Monorepo architecture
- [x] Premium dark-theme dashboard with glassmorphism
- [x] Discord / Slack webhook alerts on spike detection
- [x] Threat-intel feed integration (AbuseIPDB, Shodan)
- [x] Docker image for one-command deployment
- [x] PCAP export of captured packets
- [x] Multi-user auth for the dashboard
- [x] Block inspector dashboard page
