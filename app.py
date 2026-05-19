#!/usr/bin/env python3
"""
app.py — BlackWall Dashboard (Streamlit)

Pages:
  1. Live Logs        — real-time packet feed with filters & charts
  2. Threat Stats     — cumulative stats, top talkers, protocol split
  3. Manage Rules     — view, add, and delete firewall rules
  4. Banned IPs       — auto-banned IPs with manual unban
  5. Ledger Integrity — blockchain tamper detection
  6. Block Inspector  — per-block hash & signature verification
  7. Export Ledger    — download full chain as JSON
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import threading
import time
from collections import deque, Counter

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from scapy.all import sniff, IP, TCP, UDP
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from blockchain import Blockchain
from firewall import Firewall

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="BlackWall",
    page_icon="🔥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── RSA key management ─────────────────────────────────────────────────────────
KEY_FILE = "fw_key.pem"

if "keys" not in st.session_state:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            _priv = serialization.load_pem_private_key(f.read(), password=None)
            _pub  = _priv.public_key()
    else:
        _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _pub  = _priv.public_key()
        with open(KEY_FILE, "wb") as f:
            f.write(_priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    st.session_state["keys"] = (_pub, _priv)

public_key, private_key = st.session_state["keys"]

# ── Blockchain & Firewall ──────────────────────────────────────────────────────
if "ledger" not in st.session_state:
    st.session_state["ledger"] = Blockchain(public_key, private_key, difficulty=2)
ledger: Blockchain = st.session_state["ledger"]

if "fw" not in st.session_state:
    st.session_state["fw"] = Firewall(ledger)
fw: Firewall = st.session_state["fw"]

# ── Packet buffer ──────────────────────────────────────────────────────────────
if "packets" not in st.session_state:
    st.session_state["packets"] = []

if "rolling_allow" not in st.session_state:
    st.session_state["rolling_allow"] = deque(maxlen=100)
    st.session_state["rolling_drop"]  = deque(maxlen=100)


def _packet_callback(pkt) -> None:
    verdict = fw.check_packet(pkt)
    ip_src  = pkt[IP].src  if IP  in pkt else "unknown"
    dport   = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
    proto   = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
    st.session_state["packets"].append({
        "src":       ip_src,
        "port":      dport,
        "proto":     proto,
        "verdict":   verdict,
        "timestamp": time.strftime("%H:%M:%S"),
    })
    # Keep buffer bounded
    if len(st.session_state["packets"]) > 5000:
        st.session_state["packets"] = st.session_state["packets"][-2000:]


def _start_sniffing() -> None:
    sniff(prn=_packet_callback, store=0)


if "sniffer_thread" not in st.session_state:
    t = threading.Thread(target=_start_sniffing, daemon=True)
    t.start()
    st.session_state["sniffer_thread"] = t

# ── Sidebar navigation ─────────────────────────────────────────────────────────
PAGES = [
    "🖥️ Live Logs",
    "📊 Threat Stats",
    "📋 Manage Rules",
    "🚫 Banned IPs",
    "🔒 Ledger Integrity",
    "🔍 Block Inspector",
    "💾 Export Ledger",
]

st.sidebar.title("🛡️ BlackWall")
page = st.sidebar.radio("Navigation", PAGES, label_visibility="collapsed")

# Sidebar quick-stats
stats = fw.get_stats()
st.sidebar.markdown("---")
st.sidebar.metric("Total Packets",  stats["total"])
st.sidebar.metric("Allowed",        stats["allow"])
st.sidebar.metric("Dropped",        stats["drop"])
st.sidebar.metric("Auto-Banned IPs", stats["banned"])
st.sidebar.markdown("---")
st.sidebar.caption(f"Ledger blocks: {len(ledger)}")

# ==============================================================================
# PAGE 1 — Live Logs
# ==============================================================================
if page == "🖥️ Live Logs":
    st.title("🖥️ Live Packet Feed")
    st_autorefresh(interval=1500, key="live_refresh")

    logs = st.session_state["packets"][-500:]

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_ip    = st.text_input("Filter by Source IP", placeholder="e.g. 192.168.1.1")
    with col2:
        filter_proto = st.selectbox("Protocol", ["All", "TCP", "UDP", "OTHER"])
    with col3:
        filter_verdict = st.selectbox("Verdict", ["All", "ALLOW", "DROP"])

    show_last_n = st.slider("Show last N packets", 10, 200, 50)

    filtered = [
        p for p in reversed(logs)
        if (not filter_ip    or p["src"]     == filter_ip)
        and (filter_proto    == "All"         or p["proto"]   == filter_proto)
        and (filter_verdict  == "All"         or p["verdict"] == filter_verdict)
    ]

    # Packet table
    st.subheader(f"Recent Packets (showing {min(show_last_n, len(filtered))})")
    if filtered:
        df_pkts = pd.DataFrame(filtered[:show_last_n])
        df_pkts["icon"] = df_pkts["verdict"].map({"ALLOW": "✅", "DROP": "❌"})
        st.dataframe(
            df_pkts[["timestamp", "src", "port", "proto", "verdict", "icon"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No packets captured yet — waiting for traffic…")

    # Rolling verdict chart
    st.subheader("📈 Rolling Verdict Trend (last 100 windows)")
    count_allow = sum(1 for p in logs[-10:] if p["verdict"] == "ALLOW")
    count_drop  = sum(1 for p in logs[-10:] if p["verdict"] == "DROP")
    st.session_state["rolling_allow"].append(count_allow)
    st.session_state["rolling_drop"].append(count_drop)
    df_roll = pd.DataFrame({
        "ALLOW": list(st.session_state["rolling_allow"]),
        "DROP":  list(st.session_state["rolling_drop"]),
    })
    st.line_chart(df_roll)

    # Attack spike alert
    DROP_THRESHOLD = 15
    if count_drop >= DROP_THRESHOLD:
        st.error(f"🚨 High DROP rate detected! {count_drop} drops in the last 10 packets.")
    else:
        st.success(f"DROP rate normal ({count_drop} in last 10 packets).")

    # Source IP bar chart
    st.subheader("🌡️ Top Source IPs")
    ip_counts = Counter(p["src"] for p in logs if p["src"] and p["src"] != "unknown")
    if ip_counts:
        df_ip = (
            pd.DataFrame(ip_counts.most_common(20), columns=["IP", "Packets"])
        )
        fig = px.bar(
            df_ip, x="IP", y="Packets",
            color="Packets", color_continuous_scale="Reds",
            title="Top 20 Source IPs by Packet Count",
        )
        fig.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No IP data yet.")

# ==============================================================================
# PAGE 2 — Threat Stats
# ==============================================================================
elif page == "📊 Threat Stats":
    st.title("📊 Threat Statistics")

    logs = st.session_state["packets"]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Packets",   stats["total"])
    col2.metric("Allowed",         stats["allow"])
    col3.metric("Dropped",         stats["drop"])
    col4.metric("Auto-Banned IPs", stats["banned"])

    if not logs:
        st.info("No traffic data yet.")
    else:
        # Protocol distribution
        proto_counts = Counter(p["proto"] for p in logs)
        df_proto = pd.DataFrame(proto_counts.items(), columns=["Protocol", "Count"])
        fig_proto = px.pie(df_proto, names="Protocol", values="Count",
                           title="Protocol Distribution", hole=0.4)
        st.plotly_chart(fig_proto, use_container_width=True)

        # Verdict distribution
        verdict_counts = Counter(p["verdict"] for p in logs)
        df_verdict = pd.DataFrame(verdict_counts.items(), columns=["Verdict", "Count"])
        fig_verdict = px.pie(df_verdict, names="Verdict", values="Count",
                             title="Verdict Distribution",
                             color="Verdict",
                             color_discrete_map={"ALLOW": "#00cc96", "DROP": "#ef553b"},
                             hole=0.4)
        st.plotly_chart(fig_verdict, use_container_width=True)

        # Top talkers
        st.subheader("🏆 Top 10 Talkers")
        top_ips = Counter(p["src"] for p in logs if p["src"] != "unknown").most_common(10)
        if top_ips:
            df_top = pd.DataFrame(top_ips, columns=["IP", "Packets"])
            st.dataframe(df_top, use_container_width=True, hide_index=True)

        # Top targeted ports
        st.subheader("🎯 Top 10 Targeted Ports")
        top_ports = Counter(p["port"] for p in logs if p["port"]).most_common(10)
        if top_ports:
            df_ports = pd.DataFrame(top_ports, columns=["Port", "Hits"])
            st.dataframe(df_ports, use_container_width=True, hide_index=True)

# ==============================================================================
# PAGE 3 — Manage Rules
# ==============================================================================
elif page == "📋 Manage Rules":
    st.title("📋 Firewall Rule Manager")

    # ── Add rule form ──────────────────────────────────────────────────────────
    with st.expander("➕ Add New Rule", expanded=True):
        with st.form("add_rule_form"):
            c1, c2, c3, c4 = st.columns(4)
            action  = c1.selectbox("Action",   ["ALLOW", "DROP"])
            ip      = c2.text_input("Source IP",  placeholder="leave blank = any")
            port    = c3.text_input("Port",        placeholder="leave blank = any")
            proto   = c4.selectbox("Protocol",    ["", "TCP", "UDP"])
            comment = st.text_input("Comment / label", placeholder="optional description")
            submitted = st.form_submit_button("Add Rule")

        if submitted:
            port_val = int(port) if port.strip() else None
            fw.add_rule(
                action=action,
                ip=ip.strip() or None,
                port=port_val,
                proto=proto or None,
                comment=comment.strip(),
            )
            st.success(f"Rule added: {action} {ip or 'any'} port={port_val} proto={proto or 'any'}")
            st.rerun()

    # ── Current rules table ────────────────────────────────────────────────────
    st.subheader("Current Rules")
    rules = fw.get_rules()
    if rules:
        df_rules = pd.DataFrame(rules)
        st.dataframe(df_rules, use_container_width=True, hide_index=True)

        # Delete rule
        st.subheader("🗑️ Delete a Rule")
        rule_ids = [r["id"] for r in rules]
        del_id = st.selectbox("Select Rule ID to delete", rule_ids)
        if st.button("Delete Rule", type="primary"):
            if fw.delete_rule(del_id):
                st.success(f"Rule {del_id} deleted.")
                st.rerun()
            else:
                st.error("Rule not found.")
    else:
        st.info("No rules configured yet.")

# ==============================================================================
# PAGE 4 — Banned IPs
# ==============================================================================
elif page == "🚫 Banned IPs":
    st.title("🚫 Auto-Banned IPs")

    banned = list(fw.banned_ips)
    if banned:
        st.warning(f"{len(banned)} IP(s) currently banned.")
        df_banned = pd.DataFrame({"Banned IP": banned})
        st.dataframe(df_banned, use_container_width=True, hide_index=True)

        st.subheader("Unban an IP")
        unban_ip = st.selectbox("Select IP to unban", banned)
        if st.button("Unban", type="primary"):
            fw.banned_ips.discard(unban_ip)
            fw.rate_limiter.reset(unban_ip)
            # Remove the auto-ban DROP rule from the rule list
            fw.rules = [
                r for r in fw.rules
                if not (r.get("ip") == unban_ip and "auto-ban" in r.get("comment", ""))
            ]
            fw.save_rules()
            st.success(f"{unban_ip} has been unbanned.")
            st.rerun()
    else:
        st.success("No IPs are currently banned. 🎉")

    st.markdown("---")
    st.caption(
        "IPs are auto-banned when they exceed the rate limit "
        f"({fw.rate_limiter.threshold} packets / {fw.rate_limiter.window}s)."
    )

# ==============================================================================
# PAGE 5 — Ledger Integrity
# ==============================================================================
elif page == "🔒 Ledger Integrity":
    st.title("🔒 Blockchain Ledger Integrity")

    summary = ledger.summary()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Blocks",  summary["total_blocks"])
    c2.metric("PoW Difficulty", summary["difficulty"])
    c3.metric("Latest Hash",   summary["latest_hash"][:16] + "…" if summary["latest_hash"] else "—")

    if st.button("🔍 Run Integrity Check"):
        issues = ledger.check_integrity()
        if issues:
            st.error(f"⚠️ {len(issues)} integrity issue(s) found!")
            df_issues = pd.DataFrame(issues)
            st.dataframe(df_issues, use_container_width=True, hide_index=True)
        else:
            st.success("✅ Ledger is clean — no tampering detected.")

# ==============================================================================
# PAGE 6 — Block Inspector
# ==============================================================================
elif page == "🔍 Block Inspector":
    st.title("🔍 Block Inspector")

    if not ledger.chain:
        st.info("Ledger is empty.")
    else:
        blk_index = st.number_input(
            "Block Index",
            min_value=0,
            max_value=len(ledger.chain) - 1,
            value=0,
            step=1,
        )
        blk = ledger.chain[int(blk_index)]
        blk_dict = blk.to_dict()

        col1, col2 = st.columns(2)
        col1.metric("Index",     blk_dict["index"])
        col1.metric("Nonce",     blk_dict["nonce"])
        col2.metric("Timestamp", time.strftime("%Y-%m-%d %H:%M:%S",
                                               time.localtime(blk_dict["timestamp"])))
        col2.metric("Signer",    blk_dict["signer"] or "—")

        st.text_input("Hash",      blk_dict["hash"],      disabled=True)
        st.text_input("Prev Hash", blk_dict["prev_hash"], disabled=True)
        st.text_area("Data",       json_pretty(blk_dict["data"]), height=120, disabled=True)

        if blk_dict["signature"]:
            st.text_area("Signature (hex)", blk_dict["signature"], height=80, disabled=True)

        if st.button("✅ Verify Signature"):
            valid = blk.verify(public_key)
            if valid:
                st.success("Signature is valid.")
            else:
                st.error("Signature verification FAILED.")

# ==============================================================================
# PAGE 7 — Export Ledger
# ==============================================================================
elif page == "💾 Export Ledger":
    st.title("💾 Export Blockchain Ledger")

    st.write(f"Chain contains **{len(ledger.chain)}** blocks.")

    if st.button("Generate Export"):
        export_path = ledger.export_json("ledger_export.json")
        with open(export_path, "r") as f:
            export_data = f.read()
        st.download_button(
            label="⬇️ Download ledger_export.json",
            data=export_data,
            file_name="ledger_export.json",
            mime="application/json",
        )
        st.success(f"Export ready: {export_path}")


# ── Utility ────────────────────────────────────────────────────────────────────
import json as _json

def json_pretty(obj) -> str:
    try:
        return _json.dumps(obj, indent=2)
    except Exception:
        return str(obj)
