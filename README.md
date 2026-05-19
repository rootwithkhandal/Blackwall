# BlackWall

**A homelab-grade Security Operations Centre firewall with blockchain-backed logging, real-time analytics, auto-banning, and a full Streamlit dashboard.**

---

## Overview

BlackWall turns your Linux machine into a mini SOC. It captures live network packets with Scapy, evaluates them against a dynamic rule set, logs every decision to an immutable blockchain ledger signed with RSA keys, and presents everything through an interactive Streamlit dashboard.

---

## What's New (v2)

| Area | Upgrade |
|---|---|
| **Firewall engine** | Rule persistence (JSON), rule deletion, per-IP rate limiting, automatic IP banning |
| **Blockchain** | Proof-of-work mining (configurable difficulty), stable JSON-serialised data hashing, one-click JSON export |
| **Dashboard** | 7 pages (was 4), packet table with filters, threat stats with pie charts, rule manager with delete, banned-IP manager with unban, block inspector, ledger export |
| **Code quality** | Type hints throughout, thread-safe locks, bounded packet buffer, graceful iptables fallback on Windows |

---

## Tech Stack

| Component | Library |
|---|---|
| UI | Streamlit ≥ 1.35 |
| Packet capture | Scapy ≥ 2.6 |
| Cryptography | cryptography ≥ 42 |
| Charts | Plotly ≥ 5.22 |
| Data | Pandas ≥ 2.2 |
| File watching | Watchdog ≥ 4.0 |

Python 3.11+ recommended.

---

## Features

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
- Rate-limit config: 100 packets / 10 seconds per IP (adjustable in `firewall.py`)

### 🔒 Ledger Integrity
- Checks every block for hash mismatch, broken chain linkage, and invalid RSA signature
- Reports exact block indices and issue types

### 🔍 Block Inspector
- Browse any block by index
- View index, timestamp, nonce, signer, hash, prev-hash, data, and signature
- One-click signature verification

### 💾 Export Ledger
- Download the full blockchain as a pretty-printed JSON file

---

## Installation

```bash
git clone https://github.com/rootwithkhandal/blackwall.git
cd blackwall

python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
streamlit run app.py
```

> **Linux note:** Scapy requires root (or `CAP_NET_RAW`) for live capture.  
> Run with `sudo -E streamlit run app.py` or grant the capability to the Python binary.

---

## Project Structure

```
BlackWall/
├── app.py              # Streamlit dashboard (7 pages)
├── firewall.py         # Firewall engine — rules, rate limiting, auto-ban
├── blockchain.py       # Blockchain ledger — PoW, RSA signing, export
├── rules.json          # Persisted firewall rules (auto-created)
├── ledger.json         # Append-only blockchain log (auto-created)
├── ledger_export.json  # Full-chain JSON export (generated on demand)
├── fw_key.pem          # RSA-2048 private key (auto-generated, keep secret)
├── requirements.txt    # Python dependencies
└── README.md
```

---

## Configuration

| Setting | Location | Default |
|---|---|---|
| Rate-limit threshold | `firewall.py` → `RATE_LIMIT_THRESHOLD` | 100 packets |
| Rate-limit window | `firewall.py` → `RATE_LIMIT_WINDOW` | 10 seconds |
| PoW difficulty | `app.py` → `Blockchain(..., difficulty=2)` | 2 leading zeros |
| Packet buffer size | `app.py` → buffer trim logic | 5 000 / trim to 2 000 |
| Attack spike alert | `app.py` → `DROP_THRESHOLD` | 15 drops / 10 pkts |

---

## Security Notes

- `fw_key.pem` is generated automatically on first run and stored unencrypted. Protect it like any private key — add it to `.gitignore`.
- The dashboard is intended for isolated homelabs. Do not expose it to the public internet without authentication.
- iptables rules applied by the firewall persist across Streamlit restarts but not across reboots unless you save them with `iptables-save`.

---

## Roadmap

- [ ] GeoIP world-map heatmap (MaxMind GeoLite2)
- [ ] Discord / Slack webhook alerts on spike detection
- [ ] Threat-intel feed integration (AbuseIPDB, Shodan)
- [ ] Docker image for one-command deployment
- [ ] PCAP export of captured packets
- [ ] Multi-user auth for the dashboard

---

## Ideal For

- Security students learning SOC workflows
- Penetration testers practising blue-team defence
- Red team / blue team lab exercises
- Homelab network monitoring and anomaly detection
