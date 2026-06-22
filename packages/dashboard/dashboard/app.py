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

# ── Data directory (project root / data) ───────────────────────────────────────
_DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(_DATA_DIR, exist_ok=True)

# ── RSA keys ───────────────────────────────────────────────────────────────────
_KEY_FILE = os.path.join(os.getcwd(), "fw_key.pem")

if "keys" not in st.session_state:
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
    st.session_state["keys"] = (_priv.public_key(), _priv)

public_key, private_key = st.session_state["keys"]

# ── Blockchain & Firewall ──────────────────────────────────────────────────────
if "ledger" not in st.session_state:
    st.session_state["ledger"] = Blockchain(
        public_key, private_key, difficulty=2, data_dir=_DATA_DIR,
    )
ledger: Blockchain = st.session_state["ledger"]

if "fw" not in st.session_state:
    st.session_state["fw"] = Firewall(ledger, data_dir=_DATA_DIR)
fw: Firewall = st.session_state["fw"]

# ── Packet queue & buffer ──────────────────────────────────────────────────────
# The sniffer thread pushes raw dicts here; the main thread drains it.
if "pkt_queue" not in st.session_state:
    st.session_state["pkt_queue"] = queue.SimpleQueue()

if "packets" not in st.session_state:
    st.session_state["packets"] = []

if "rolling_allow" not in st.session_state:
    st.session_state["rolling_allow"] = deque(maxlen=100)
    st.session_state["rolling_drop"]  = deque(maxlen=100)


def _on_packet(pkt) -> None:
    """Sniffer callback — runs in the sniffer thread. Only enqueues data."""
    verdict = fw.check_packet(pkt)
    ip_src  = pkt[IP].src    if IP  in pkt else "unknown"
    dport   = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
    proto   = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
    st.session_state["pkt_queue"].put({
        "src":       ip_src,
        "port":      dport,
        "proto":     proto,
        "verdict":   verdict,
        "timestamp": time.strftime("%H:%M:%S"),
    })


if "sniffer_thread" not in st.session_state:
    _t = threading.Thread(target=lambda: sniff(prn=_on_packet, store=0), daemon=True)
    _t.start()
    st.session_state["sniffer_thread"] = _t

# ── Drain the queue into the packet buffer (main thread only) ─────────────────
_q: queue.SimpleQueue = st.session_state["pkt_queue"]
while not _q.empty():
    try:
        st.session_state["packets"].append(_q.get_nowait())
    except queue.Empty:
        break

# Keep buffer bounded
if len(st.session_state["packets"]) > 5000:
    st.session_state["packets"] = st.session_state["packets"][-2000:]

# ── Sidebar ────────────────────────────────────────────────────────────────────
PAGES = {
    "🖥️ Live Logs":        live_logs,
    "📊 Threat Stats":     threat_stats,
    "📋 Manage Rules":     manage_rules,
    "🚫 Banned IPs":       banned_ips,
    "🔒 Ledger Integrity": ledger_integrity,
    "🔍 Block Inspector":  block_inspector,
    "💾 Export Ledger":    export_ledger,
}

st.sidebar.title("🛡️ BlackWall")
page = st.sidebar.radio("Navigation", list(PAGES.keys()), label_visibility="collapsed")

stats = fw.get_stats()
st.sidebar.markdown("---")
st.sidebar.metric("Total Packets",   stats["total"])
st.sidebar.metric("Allowed",         stats["allow"])
st.sidebar.metric("Dropped",         stats["drop"])
st.sidebar.metric("Auto-Banned IPs", stats["banned"])
st.sidebar.markdown("---")
st.sidebar.caption(f"Ledger blocks: {len(ledger)}")

# ── Route ──────────────────────────────────────────────────────────────────────
PAGES[page].render(fw, ledger)
