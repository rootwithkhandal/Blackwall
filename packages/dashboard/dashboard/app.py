#!/usr/bin/env python3
"""
app.py — BlackWall entry point.

Initialises shared state (RSA keys, blockchain, firewall, packet sniffer)
then routes to the selected dashboard page.

Thread-safety note:
  The Scapy sniffer runs in a daemon thread.  It writes captured packets
  into a thread-safe queue (st.session_state["pkt_queue"]).  The main
  Streamlit thread drains that queue on every rerun so that session_state
  is only mutated from the main thread, avoiding Streamlit's internal
  state-corruption issues.
"""

import os
import queue
import sys
import threading
import time
from collections import deque

import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from scapy.all import sniff, IP, TCP, UDP

from blackwall.blockchain import Blockchain
from blackwall.firewall   import Firewall
from dashboard.pages      import (
    live_logs, threat_stats, manage_rules,
    banned_ips, ledger_integrity, block_inspector, export_ledger,
)

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="BlackWall",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Premium CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Google Font ─────────────────────────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

* { font-family: 'Inter', sans-serif !important; }

/* ── Hide default Streamlit multi-page nav ───────────────────────────────── */
[data-testid="stSidebarNav"] { display: none !important; }
header[data-testid="stHeader"] { background: transparent !important; }

/* ── Main area ───────────────────────────────────────────────────────────── */
.main .block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1400px;
}

/* ── Sidebar ─────────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0D1120 0%, #131825 50%, #0D1120 100%);
    border-right: 1px solid rgba(124, 106, 255, 0.12);
}

section[data-testid="stSidebar"] .stRadio > div {
    gap: 2px;
}

section[data-testid="stSidebar"] .stRadio > div > label {
    background: rgba(124, 106, 255, 0.04);
    border: 1px solid rgba(124, 106, 255, 0.08);
    border-radius: 8px;
    padding: 0.55rem 0.85rem;
    margin: 0;
    transition: all 0.2s ease;
    cursor: pointer;
}

section[data-testid="stSidebar"] .stRadio > div > label:hover {
    background: rgba(124, 106, 255, 0.12);
    border-color: rgba(124, 106, 255, 0.25);
    transform: translateX(3px);
}

section[data-testid="stSidebar"] .stRadio > div > label[data-checked="true"],
section[data-testid="stSidebar"] .stRadio > div > label:has(input:checked) {
    background: linear-gradient(135deg, rgba(124, 106, 255, 0.2) 0%, rgba(99, 179, 237, 0.12) 100%);
    border-color: rgba(124, 106, 255, 0.4);
    box-shadow: 0 0 15px rgba(124, 106, 255, 0.1);
}

/* ── Metric cards ────────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, rgba(124, 106, 255, 0.06) 0%, rgba(99, 179, 237, 0.04) 100%);
    border: 1px solid rgba(124, 106, 255, 0.12);
    border-radius: 12px;
    padding: 1rem 1.2rem;
    transition: all 0.3s ease;
}

[data-testid="stMetric"]:hover {
    border-color: rgba(124, 106, 255, 0.3);
    box-shadow: 0 4px 20px rgba(124, 106, 255, 0.08);
    transform: translateY(-2px);
}

[data-testid="stMetricLabel"] {
    font-size: 0.75rem !important;
    font-weight: 500 !important;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #8B95A8 !important;
}

[data-testid="stMetricValue"] {
    font-size: 1.8rem !important;
    font-weight: 700 !important;
    background: linear-gradient(135deg, #E8ECF4, #7C6AFF);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

/* ── DataFrames / Tables ─────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid rgba(124, 106, 255, 0.1);
    border-radius: 12px;
    overflow: hidden;
}

/* ── Buttons ─────────────────────────────────────────────────────────────── */
.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    letter-spacing: 0.02em;
    transition: all 0.25s ease;
    border: 1px solid rgba(124, 106, 255, 0.3);
}

.stButton > button:hover {
    box-shadow: 0 4px 15px rgba(124, 106, 255, 0.2);
    transform: translateY(-1px);
}

.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #7C6AFF 0%, #5B4FD9 100%);
    border: none;
}

/* ── Expanders ───────────────────────────────────────────────────────────── */
[data-testid="stExpander"] {
    border: 1px solid rgba(124, 106, 255, 0.12);
    border-radius: 12px;
    overflow: hidden;
}

[data-testid="stExpander"] summary {
    font-weight: 600;
}

/* ── Alerts ──────────────────────────────────────────────────────────────── */
[data-testid="stAlert"] {
    border-radius: 10px;
    border-left: 4px solid;
}

/* ── Inputs ──────────────────────────────────────────────────────────────── */
[data-testid="stTextInput"] input,
[data-testid="stNumberInput"] input,
[data-testid="stSelectbox"] > div > div {
    border-radius: 8px !important;
    border-color: rgba(124, 106, 255, 0.15) !important;
    transition: border-color 0.2s ease;
}

[data-testid="stTextInput"] input:focus,
[data-testid="stNumberInput"] input:focus {
    border-color: rgba(124, 106, 255, 0.5) !important;
    box-shadow: 0 0 10px rgba(124, 106, 255, 0.1) !important;
}

/* ── Page titles ─────────────────────────────────────────────────────────── */
h1 {
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
    padding-bottom: 0.3rem !important;
    border-bottom: 2px solid rgba(124, 106, 255, 0.15);
    margin-bottom: 1.5rem !important;
}

h2, h3 {
    font-weight: 600 !important;
    letter-spacing: -0.01em !important;
    color: #C5CBE0 !important;
}

/* ── Dividers ────────────────────────────────────────────────────────────── */
hr {
    border-color: rgba(124, 106, 255, 0.1) !important;
}

/* ── Captions ────────────────────────────────────────────────────────────── */
.stCaption, small {
    color: #5A6478 !important;
}

/* ── Slider ──────────────────────────────────────────────────────────────── */
[data-testid="stSlider"] > div > div > div {
    background: linear-gradient(90deg, #7C6AFF, #63B3ED) !important;
}

/* ── Plotly chart containers ─────────────────────────────────────────────── */
[data-testid="stPlotlyChart"] {
    border: 1px solid rgba(124, 106, 255, 0.08);
    border-radius: 12px;
    padding: 0.5rem;
    background: rgba(124, 106, 255, 0.02);
}

/* ── Custom scrollbar ────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0B0F19; }
::-webkit-scrollbar-thumb { background: #2A2F42; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #3A3F55; }

/* ── Sidebar brand ───────────────────────────────────────────────────────── */
.brand-title {
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: -0.03em;
    background: linear-gradient(135deg, #7C6AFF 0%, #63B3ED 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.2rem;
}

.brand-subtitle {
    font-size: 0.7rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    color: #5A6478;
    margin-bottom: 1.2rem;
}

.sidebar-stat-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    margin: 0.8rem 0;
}

.sidebar-stat {
    background: rgba(124, 106, 255, 0.06);
    border: 1px solid rgba(124, 106, 255, 0.1);
    border-radius: 10px;
    padding: 0.7rem 0.8rem;
    text-align: center;
}

.sidebar-stat-value {
    font-size: 1.3rem;
    font-weight: 700;
    color: #E8ECF4;
    line-height: 1.2;
}

.sidebar-stat-label {
    font-size: 0.6rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #5A6478;
    margin-top: 2px;
}

.stat-allow .sidebar-stat-value { color: #4ADE80; }
.stat-drop  .sidebar-stat-value { color: #F87171; }
.stat-ban   .sidebar-stat-value { color: #FBBF24; }

.sidebar-footer {
    font-size: 0.65rem;
    color: #3A4255;
    text-align: center;
    padding: 0.5rem 0;
    border-top: 1px solid rgba(124, 106, 255, 0.08);
    margin-top: 0.5rem;
}

/* ── ML badge ────────────────────────────────────────────────────────────── */
.ml-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: linear-gradient(135deg, rgba(124, 106, 255, 0.15), rgba(99, 179, 237, 0.1));
    border: 1px solid rgba(124, 106, 255, 0.2);
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 0.7rem;
    font-weight: 600;
    color: #A5B4FC;
    letter-spacing: 0.05em;
}

.ml-badge-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #4ADE80;
    animation: pulse-dot 2s infinite;
}

@keyframes pulse-dot {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
}
</style>
""", unsafe_allow_html=True)

# ── Backend Singleton ──────────────────────────────────────────────────────────
@st.cache_resource
def init_backend():
    """Initialize singletons: Keys, Ledger, Firewall, and Sniffer thread."""
    _DATA_DIR = os.path.join(os.getcwd(), "data")
    os.makedirs(_DATA_DIR, exist_ok=True)

    _KEY_FILE = os.path.join(os.getcwd(), "fw_key.pem")
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as _f:
            _priv = serialization.load_pem_private_key(_f.read(), password=None)
    else:
        _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(_KEY_FILE, "wb") as _f:
            _f.write(_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    ledger = Blockchain(_priv.public_key(), _priv, difficulty=2, data_dir=_DATA_DIR)
    fw = Firewall(ledger, data_dir=_DATA_DIR)
    pkt_queue = queue.SimpleQueue()

    def _on_packet(pkt) -> None:
        """Runs in background thread. Uses closure variables, NOT st.session_state."""
        try:
            verdict = fw.check_packet(pkt)
            ip_src  = pkt[IP].src    if IP  in pkt else "unknown"
            dport   = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
            proto   = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
            pkt_queue.put({
                "src":       ip_src,
                "port":      dport,
                "proto":     proto,
                "verdict":   verdict,
                "timestamp": time.strftime("%H:%M:%S"),
            })
        except Exception:
            pass # Silently drop malformed packets that don't match the layers

    # Start sniffer on default active interface
    t = threading.Thread(target=lambda: sniff(prn=_on_packet, store=0), daemon=True)
    t.start()

    # Start FastAPI REST server for SOC integration
    try:
        from blackwall.api import start_api_server
        start_api_server(fw, ledger, port=8000)
        with open("api_error.log", "a") as f:
            f.write("start_api_server successfully called\n")
    except Exception as e:
        with open("api_error.log", "a") as f:
            import traceback
            f.write(f"FATAL: {e}\n{traceback.format_exc()}\n")

    return fw, ledger, pkt_queue

# Check for simulate flag
IS_SIMULATION = "--simulate" in sys.argv

if IS_SIMULATION:
    # Shorten ML baseline for faster demo
    os.environ["BLACKWALL_SIMULATE"] = "1"

fw, ledger, pkt_queue = init_backend()

if IS_SIMULATION:
    if "simulator" not in st.session_state:
        from blackwall.simulator import AttackSimulator
        st.session_state["simulator"] = AttackSimulator()
        st.session_state["simulator"].start()

# ── Packet buffer (main thread only) ───────────────────────────────────────────
if "packets" not in st.session_state:
    st.session_state["packets"] = []
if "rolling_allow" not in st.session_state:
    st.session_state["rolling_allow"] = deque(maxlen=100)
if "rolling_drop" not in st.session_state:
    st.session_state["rolling_drop"]  = deque(maxlen=100)

# Drain the global thread-safe queue into the UI's session state
while not pkt_queue.empty():
    try:
        st.session_state["packets"].append(pkt_queue.get_nowait())
    except queue.Empty:
        break

# Keep buffer bounded
if len(st.session_state["packets"]) > 5000:
    st.session_state["packets"] = st.session_state["packets"][-2000:]

import yaml
from yaml.loader import SafeLoader

auth_config_path = os.path.join(os.getcwd(), "data", "auth_config.yaml")

# Auto-generate default credentials if missing
if not os.path.exists(auth_config_path):
    import streamlit_authenticator as stauth
    default_config = {
        'credentials': {
            'usernames': {
                'admin': {
                    'email': 'admin@blackwall.local',
                    'name': 'Administrator',
                    'password': stauth.Hasher(['admin123']).generate()[0]
                },
                'demo': {
                    'email': 'demo@blackwall.local',
                    'name': 'Demo User',
                    'password': stauth.Hasher(['demo123']).generate()[0]
                }
            }
        },
        'cookie': {
            'expiry_days': 1,
            'key': 'blackwall_auth_signature',
            'name': 'blackwall_auth_cookie'
        },
        'preauthorized': {
            'emails': []
        }
    }
    with open(auth_config_path, 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False)

with open(auth_config_path) as file:
    auth_config = yaml.load(file, Loader=SafeLoader)

import streamlit_authenticator as stauth
authenticator = stauth.Authenticate(
    auth_config['credentials'],
    auth_config['cookie']['name'],
    auth_config['cookie']['key'],
    auth_config['cookie']['expiry_days'],
    auth_config['preauthorized']
)

try:
    authenticator.login()
except Exception as e:
    st.error(e)

if st.session_state.get("authentication_status"):
    # ── Sidebar ────────────────────────────────────────────────────────────────────
    PAGES = {
        "🖥️  Live Logs":        live_logs,
        "📊  Threat Stats":     threat_stats,
        "📋  Manage Rules":     manage_rules,
        "🚫  Banned IPs":       banned_ips,
        "🔒  Ledger Integrity": ledger_integrity,
        "🔍  Block Inspector":  block_inspector,
        "💾  Export Ledger":    export_ledger,
    }

    # Brand header
    st.sidebar.markdown('<div class="brand-title">🛡️ BlackWall</div>', unsafe_allow_html=True)
    st.sidebar.markdown('<div class="brand-subtitle">Security Operations Centre</div>', unsafe_allow_html=True)
    
    st.sidebar.markdown(f"**Welcome, {st.session_state['name']}**")
    authenticator.logout('Logout', 'sidebar')

    if IS_SIMULATION:
        st.sidebar.error("🚨 **SIMULATION MODE ACTIVE**", icon="🚨")

    # ML status badge
    ml_phase = "Baselining…" if fw.ml_detector.is_baseline_phase else "Active"
    st.sidebar.markdown(
        f'<div class="ml-badge">'
        f'<span class="ml-badge-dot"></span> ML Detector: {ml_phase}'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("")

    # Navigation
    page = st.sidebar.radio("Navigation", list(PAGES.keys()), label_visibility="collapsed")

    # Stats grid
    stats = fw.get_stats()
    st.sidebar.markdown(f"""
    <div class="sidebar-stat-grid">
        <div class="sidebar-stat">
            <div class="sidebar-stat-value">{stats['total']:,}</div>
            <div class="sidebar-stat-label">Total</div>
        </div>
        <div class="sidebar-stat stat-allow">
            <div class="sidebar-stat-value">{stats['allow']:,}</div>
            <div class="sidebar-stat-label">Allowed</div>
        </div>
        <div class="sidebar-stat stat-drop">
            <div class="sidebar-stat-value">{stats['drop']:,}</div>
            <div class="sidebar-stat-label">Dropped</div>
        </div>
        <div class="sidebar-stat stat-ban">
            <div class="sidebar-stat-value">{stats['banned']:,}</div>
            <div class="sidebar-stat-label">Banned</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.sidebar.markdown(
        f'<div class="sidebar-footer">📦 {len(ledger)} ledger blocks  •  v2.1.0</div>',
        unsafe_allow_html=True,
    )

    # ── Route ──────────────────────────────────────────────────────────────────────
    PAGES[page].render(fw, ledger)
elif st.session_state.get("authentication_status") is False:
    st.error("Username/password is incorrect")
elif st.session_state.get("authentication_status") is None:
    st.warning("Please enter your username and password to access the SOC Dashboard.")
