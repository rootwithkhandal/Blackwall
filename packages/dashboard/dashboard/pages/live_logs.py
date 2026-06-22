"""Live Logs page — real-time packet feed with filters and charts."""

from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# Configurable alert threshold (drops per 10-packet window)
DROP_THRESHOLD = 15


def render(fw, ledger) -> None:
    st.title("🖥️ Live Packet Feed")
    st_autorefresh(interval=1500, key="live_refresh")

    logs = st.session_state["packets"][-500:]

    # ── Filters ───────────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_ip = st.text_input("Filter by Source IP", placeholder="e.g. 192.168.1.1")
    with col2:
        filter_proto = st.selectbox("Protocol", ["All", "TCP", "UDP", "OTHER"])
    with col3:
        filter_verdict = st.selectbox("Verdict", ["All", "ALLOW", "DROP"])

    show_last_n = st.slider("Show last N packets", 10, 200, 50)

    filtered = [
        p for p in reversed(logs)
        if (not filter_ip      or p["src"]     == filter_ip)
        and (filter_proto   == "All" or p["proto"]   == filter_proto)
        and (filter_verdict == "All" or p["verdict"] == filter_verdict)
    ]

    # ── Packet table ──────────────────────────────────────────────────────────
    st.subheader(f"Recent Packets (showing {min(show_last_n, len(filtered))})")
    if filtered:
        df = pd.DataFrame(filtered[:show_last_n])
        df["icon"] = df["verdict"].map({"ALLOW": "✅", "DROP": "❌"})
        st.dataframe(
            df[["timestamp", "src", "port", "proto", "verdict", "icon"]],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No packets captured yet — waiting for traffic…")

    # ── Rolling verdict trend ─────────────────────────────────────────────────
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

    # ── Attack spike alert ────────────────────────────────────────────────────
    if count_drop >= DROP_THRESHOLD:
        st.error(f"🚨 High DROP rate! {count_drop} drops in the last 10 packets.")
    else:
        st.success(f"DROP rate normal ({count_drop} in last 10 packets).")

    # ── Top source IPs bar chart ──────────────────────────────────────────────
    st.subheader("🌡️ Top Source IPs")
    ip_counts = Counter(p["src"] for p in logs if p["src"] and p["src"] != "unknown")
    if ip_counts:
        df_ip = pd.DataFrame(ip_counts.most_common(20), columns=["IP", "Packets"])
        fig = px.bar(
            df_ip, x="IP", y="Packets",
            color="Packets", color_continuous_scale="Reds",
            title="Top 20 Source IPs by Packet Count",
        )
        fig.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No IP data yet.")
