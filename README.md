# BlackWall

**A homelab-grade Security Operations Centre firewall with ML anomaly detection, blockchain-backed logging, SIEM alert forwarding, and a premium Streamlit dashboard.**

---

## Overview

BlackWall turns your Linux machine into a mini SOC. It captures live network packets with Scapy, evaluates them against a dynamic rule set, detects anomalies with an IsolationForest ML model, logs every decision to an immutable blockchain ledger signed with RSA keys, forwards DROP/BAN events to Splunk or Wazuh, and presents everything through an interactive Streamlit dashboard.

---

## What's New (v2.1)

| Area | Upgrade |
|---|---|
| **Architecture** | Python monorepo — `packages/core` (engine) + `packages/dashboard` (Streamlit UI), each with its own `pyproject.toml` |
| **Anomaly detection** | IsolationForest ML model replaces static rate-limit auto-ban — catches slow-and-low attacks |
| **SIEM integration** | Fire-and-forget alert forwarding to Splunk HEC and Wazuh agent socket |
| **Firewall engine** | Rule persistence (JSON), rule deletion, automatic IP banning |
| **Blockchain** | Proof-of-work mining (configurable difficulty), stable JSON-serialised data hashing, one-click JSON export |
| **Dashboard** | 7 pages with premium dark theme, glassmorphism cards, gradient accents, Plotly dark charts, live ML status badge |
| **Design system** | Custom Streamlit theme, Inter font, color-coded stats (green/red/yellow), animated sidebar, styled empty states |
| **Code quality** | Type hints throughout, thread-safe locks, bounded packet buffer, graceful iptables fallback on Windows |

---

## Tech Stack

| Component | Library |
|---|---|
| UI | Streamlit ≥ 1.35 |
| Packet capture | Scapy ≥ 2.6 |
| ML detection | scikit-learn ≥ 1.4 (IsolationForest) |
| Cryptography | cryptography ≥ 42 |
| Charts | Plotly ≥ 5.22 |
| Data | Pandas ≥ 2.2 |
| SIEM forwarding | Requests ≥ 2.32 |

Python 3.11+ recommended.

---

## Features

### 🧠 ML Anomaly Detection
- IsolationForest model baselines normal traffic for 5 minutes on startup
- Scores per-IP traffic windows using 4 features: `pkt_rate`, `byte_rate`, `unique_ports`, `protocol_entropy`
- Auto-bans IPs flagged as outliers — catches slow-and-low attacks that never trip a static threshold

### 📡 SIEM Alert Forwarding
- POSTs every DROP/BAN event to **Splunk HEC** and/or **Wazuh** agent socket
- Fire-and-forget via background thread — zero impact on packet processing
- Configured via environment variables; no-op when unconfigured

### 🖥️ Live Logs
- Auto-refreshing packet feed (every 1.5 s)
- Filter by source IP, protocol, and verdict
- Rolling ALLOW/DROP trend line chart
- Attack spike alert when DROP rate exceeds threshold
- Top-20 source IPs bar chart

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
- ML anomaly detection with IsolationForest — baselines for 5 min, then scores per-IP traffic windows

### 🔒 Ledger Integrity
- Checks every block for hash mismatch, broken chain linkage, and invalid RSA signature
- Reports exact block indices and issue types

### 🔍 Block Inspector
- Browse any block by index
- View index, timestamp, nonce, signer, hash, prev-hash, data, and signature
- One-click signature verification
- **Forensic PCAP Download**: Instantly download the raw packets that triggered an auto-ban directly from the blockchain log.

### 💾 Export Ledger
- Download the full blockchain as a pretty-printed JSON file

---

## Project Structure

```
BlackWall/
├── packages/
│   ├── core/                          # Engine (pip: "blackwall")
│   │   ├── blackwall/
│   │   │   ├── __init__.py
│   │   │   ├── blockchain.py          # Block, Blockchain — PoW, RSA signing, export
│   │   │   ├── firewall.py            # Firewall engine — rules, ML-based auto-ban, SIEM
│   │   │   ├── ml_detector.py         # IsolationForest anomaly detector
│   │   │   └── siem_forwarder.py      # Splunk HEC + Wazuh alert forwarding
│   │   └── pyproject.toml
│   │
│   └── dashboard/                     # Streamlit UI (pip: "blackwall-dashboard")
│       ├── dashboard/
│       │   ├── __init__.py
│       │   ├── app.py                 # Entry point — init, CSS injection, page routing
│       │   └── pages/
│       │       ├── __init__.py
│       │       ├── live_logs.py
│       │       ├── threat_stats.py
│       │       ├── manage_rules.py
│       │       ├── banned_ips.py
│       │       ├── ledger_integrity.py
│       │       ├── block_inspector.py
│       │       └── export_ledger.py
│       └── pyproject.toml
│
├── .streamlit/
│   └── config.toml                    # Custom dark theme (colors, font)
├── scripts/
│   └── install.sh                     # Automated setup (Linux / macOS)
├── data/                              # Runtime files (git-ignored)
│   ├── ledger.json
│   ├── rules.json
│   └── banned_ips.json
├── pyproject.toml                     # Root workspace config (linters, formatters)
├── mise.toml                          # Task runner (mise)
├── .env                               # SIEM credentials (git-ignored)
├── .env.example                       # SIEM credential template
├── .gitignore
├── LICENSE
└── README.md
```

---

## Getting Started

### Quick Start (mise)

```bash
git clone https://github.com/rootwithkhandal/blackwall.git
cd blackwall

# Install all packages
pip3 install -r requirements.txt

# Run the dashboard
streamlit run app.py
```

### Attack Simulation Mode

For demos, CTFs, or job interviews, you can launch BlackWall in simulation mode. This creates a background thread that automatically generates synthetic attacks (SYN floods, Port scans, Slow loris, and DNS exfiltration) against `127.0.0.1` so you can instantly see the dashboard, ML anomaly detector, and Threat Intel features in action.

```bash
streamlit run app.py -- --simulate
```
*Note: Simulation mode truncates the ML baseline duration from 5 minutes to 5 seconds so auto-bans occur almost immediately.*

### Multi-User Authentication
On the first run, BlackWall automatically generates a `data/auth_config.yaml` file to secure the dashboard with `streamlit-authenticator`.
The default credentials are:
- **Admin**: `admin` / `admin123`
- **Demo User**: `demo` / `demo123`

You can change these passwords or add new users by editing the `data/auth_config.yaml` file.

### Manual Setup

```bash
git clone https://github.com/rootwithkhandal/blackwall.git
cd blackwall

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e packages/core
pip install -e packages/dashboard

streamlit run packages/dashboard/dashboard/app.py
```

> **Linux note:** Scapy requires root (or `CAP_NET_RAW`) for live capture.
> Run with `sudo -E streamlit run packages/dashboard/dashboard/app.py` or grant the capability to the Python binary.

### Running as a Service (Linux)

To run BlackWall in the background and ensure your firewall rules survive a reboot, install the systemd service (assuming you cloned to `/opt/blackwall`):

```bash
sudo cp scripts/blackwall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now blackwall
```

---

## SIEM Integration

BlackWall can forward every DROP and auto-BAN event to your SOC stack. Configure via environment variables or a `.env` file (copy from `.env.example`):

### Splunk HEC

```bash
export SPLUNK_HEC_URL=https://splunk.example.com:8088/services/collector/event
export SPLUNK_HEC_TOKEN=your-hec-token-here
```

Events are POSTed as:
```json
{
  "event": {
    "type": "auto_ban",
    "ip": "10.0.0.5",
    "reason": "ML anomaly detection (IsolationForest)",
    "timestamp": "2026-06-22T19:30:00+0530",
    "source": "blackwall"
  }
}
```

### Wazuh

```bash
export WAZUH_SOCKET_PATH=/var/ossec/queue/sockets/queue
```

Events are written as JSON lines to the Wazuh agent Unix domain socket in the format `1:blackwall:{json}`.

### REST API

BlackWall automatically runs a FastAPI server concurrently with the dashboard on port `8000` (no extra setup required). You can use this to pull data into n8n, Tines, Slack bots, or other SOC automation tools:

- `GET http://localhost:8000/rules` - Returns all active firewall rules.
- `GET http://localhost:8000/banned` - Returns a list of auto-banned IPs.
- `GET http://localhost:8000/stats` - Returns live traffic metrics.
- `GET http://localhost:8000/ledger?limit=50` - Returns the immutable blockchain log.

### Disabling

If neither `SPLUNK_HEC_URL`/`SPLUNK_HEC_TOKEN` nor `WAZUH_SOCKET_PATH` is set, the forwarder is a zero-overhead no-op.

---

## Configuration

| Setting | Location | Default |
|---|---|---|
| ML baseline duration | `packages/core` → `ml_detector.py` → `BASELINE_DURATION` | 300 s (5 min) |
| ML scoring window | `packages/core` → `ml_detector.py` → `WINDOW_SECONDS` | 10 s |
| ML contamination | `packages/core` → `ml_detector.py` → `CONTAMINATION` | 0.05 (5%) |
| PoW difficulty | `packages/dashboard` → `app.py` → `Blockchain(..., difficulty=2)` | 2 leading zeros |
| Packet buffer size | `packages/dashboard` → `app.py` → buffer trim logic | 5 000 / trim to 2 000 |
| Attack spike alert | `packages/dashboard` → `live_logs.py` → `DROP_THRESHOLD` | 15 drops / 10 pkts |
| Dashboard theme | `.streamlit/config.toml` | Deep purple dark theme |
| Splunk HEC URL | env var `SPLUNK_HEC_URL` | _(disabled)_ |
| Splunk HEC token | env var `SPLUNK_HEC_TOKEN` | _(disabled)_ |
| Wazuh socket path | env var `WAZUH_SOCKET_PATH` | _(disabled)_ |
| AbuseIPDB API key | env var `ABUSEIPDB_KEY` | _(disabled)_ |
| Shodan API key | env var `SHODAN_KEY` | _(disabled)_ |

### Enabling the GeoIP World Map

To see a beautiful choropleth heatmap of attack origins on the Threat Stats page:
1. Ensure the `geoip2` Python library is installed (`pip install geoip2`).
2. Create a free account at [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
3. Download the **GeoLite2-Country** database (MMDB format).
4. Place the extracted `GeoLite2-Country.mmdb` file inside the `data/` directory.

The dashboard will automatically detect the database and render the interactive heatmap!

---

## Development

### Installing Individual Packages

```bash
# Core engine only
mise run req:core
# or: pip install -e packages/core

# Dashboard only (pulls core as a dependency)
mise run req:dashboard
# or: pip install -e packages/dashboard
```

### Monorepo Layout

The project uses a Python monorepo pattern with two packages:

- **`packages/core`** (`blackwall`) — the engine: firewall, blockchain, ML detector, SIEM forwarder. No UI dependencies.
- **`packages/dashboard`** (`blackwall-dashboard`) — the Streamlit UI. Depends on `blackwall` core.

Both are installed as editable packages (`pip install -e`), so changes are reflected immediately without reinstalling.

---

## Security Notes

- `fw_key.pem` is generated automatically on first run and stored unencrypted. Protect it like any private key — it is git-ignored.
- The dashboard is intended for isolated homelabs. Do not expose it to the public internet without authentication.
- **Firewall Persistence**: On Linux, iptables rules are automatically saved to `/etc/iptables/rules.v4`. If you run BlackWall using the provided systemd service, these rules are restored on boot.
- SIEM credentials in `.env` should be kept out of version control (`.env` is git-ignored; only `.env.example` is committed).

---

## Roadmap

- [x] ML-based anomaly detection (IsolationForest)
- [x] Splunk HEC / Wazuh alert forwarding
- [x] Monorepo architecture
- [x] Premium dark-theme dashboard with glassmorphism and gradient accents
- [x] GeoIP world-map heatmap (MaxMind GeoLite2)
- [ ] Discord / Slack webhook alerts on spike detection
- [x] Threat-intel feed integration (AbuseIPDB, Shodan)
- [ ] Docker image for one-command deployment
- [x] PCAP export of captured packets
- [ ] Multi-user auth for the dashboard

---

## Ideal For

- Security students learning SOC workflows
- Penetration testers practising blue-team defence
- Red team / blue team lab exercises
- Homelab network monitoring and anomaly detection
- Azure / cloud SOC lab sensor feeding Splunk or Wazuh
