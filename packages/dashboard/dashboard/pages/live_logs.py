"""Live Logs page — real-time packet feed with filters and charts."""

from collections import Counter

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# Configurable alert threshold (drops per 10-packet window)
DROP_THRESHOLD = 15

# Chart theme
_CHART_TEMPLATE = "plotly_dark"
_CHART_COLORS = {"ALLOW": "#4ADE80", "DROP": "#F87171"}
_CHART_BG = "rgba(0,0,0,0)"
_CHART_GRID = "rgba(124, 106, 255, 0.06)"


def render(fw, ledger) -> None:
    st.title("🖥️ Live Packet Feed")
    st_autorefresh(interval=1500, key="live_refresh")

    logs = st.session_state["packets"][-500:]

    # ── Filters ───────────────────────────────────────────────────────────────
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_ip = st.text_input("🔎 Filter by Source IP", placeholder="e.g. 192.168.1.1")
    with col2:
        filter_proto = st.selectbox("📡 Protocol", ["All", "TCP", "UDP", "OTHER"])
    with col3:
        filter_verdict = st.selectbox("⚖️ Verdict", ["All", "ALLOW", "DROP"])

    show_last_n = st.slider("Show last N packets", 10, 200, 50)

    filtered = [
        p for p in reversed(logs)
        if (not filter_ip      or p["src"]     == filter_ip)
        and (filter_proto   == "All" or p["proto"]   == filter_proto)
        and (filter_verdict == "All" or p["verdict"] == filter_verdict)
    ]

    # ── Packet table ──────────────────────────────────────────────────────────
    st.subheader(f"Recent Packets ({min(show_last_n, len(filtered))} shown)")
    if filtered:
        df = pd.DataFrame(filtered[:show_last_n])
        df["icon"] = df["verdict"].map({"ALLOW": "✅", "DROP": "🛑"})
        st.dataframe(
            df[["timestamp", "src", "port", "proto", "verdict", "icon"]],
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": st.column_config.TextColumn("Time", width="small"),
                "src": st.column_config.TextColumn("Source IP"),
                "port": st.column_config.NumberColumn("Port", format="%d"),
                "proto": st.column_config.TextColumn("Protocol", width="small"),
                "verdict": st.column_config.TextColumn("Verdict", width="small"),
                "icon": st.column_config.TextColumn("", width="small"),
            },
        )
    else:
        st.info("⏳ No packets captured yet — waiting for traffic…")

    # ── Rolling verdict trend ─────────────────────────────────────────────────
    st.subheader("📈 Verdict Trend")
    count_allow = sum(1 for p in logs[-10:] if p["verdict"] == "ALLOW")
    count_drop  = sum(1 for p in logs[-10:] if p["verdict"] == "DROP")
    st.session_state["rolling_allow"].append(count_allow)
    st.session_state["rolling_drop"].append(count_drop)

    fig_trend = go.Figure()
    fig_trend.add_trace(go.Scatter(
        y=list(st.session_state["rolling_allow"]),
        mode="lines", name="ALLOW",
        line=dict(color="#4ADE80", width=2),
        fill="tozeroy", fillcolor="rgba(74, 222, 128, 0.08)",
    ))
    fig_trend.add_trace(go.Scatter(
        y=list(st.session_state["rolling_drop"]),
        mode="lines", name="DROP",
        line=dict(color="#F87171", width=2),
        fill="tozeroy", fillcolor="rgba(248, 113, 113, 0.08)",
    ))
    fig_trend.update_layout(
        template=_CHART_TEMPLATE,
        paper_bgcolor=_CHART_BG, plot_bgcolor=_CHART_BG,
        margin=dict(l=0, r=0, t=30, b=0),
        height=250,
        legend=dict(orientation="h", yanchor="top", y=1.12, xanchor="right", x=1),
        xaxis=dict(gridcolor=_CHART_GRID, showgrid=True),
        yaxis=dict(gridcolor=_CHART_GRID, showgrid=True),
    )
    st.plotly_chart(fig_trend, use_container_width=True)

    # ── Attack spike alert ────────────────────────────────────────────────────
    if count_drop >= DROP_THRESHOLD:
        st.error(f"🚨 **High DROP rate!** {count_drop} drops in the last 10 packets.")
    else:
        st.success(f"✅ DROP rate normal — {count_drop} in last 10 packets.")

    # ── Top source IPs bar chart ──────────────────────────────────────────────
    st.subheader("🌡️ Top Source IPs")
    ip_counts = Counter(p["src"] for p in logs if p["src"] and p["src"] != "unknown")
    if ip_counts:
        df_ip = pd.DataFrame(ip_counts.most_common(20), columns=["IP", "Packets"])
        fig = px.bar(
            df_ip, x="IP", y="Packets",
            color="Packets",
            color_continuous_scale=[[0, "#2D1B69"], [0.5, "#7C6AFF"], [1, "#F87171"]],
            template=_CHART_TEMPLATE,
        )
        fig.update_layout(
            paper_bgcolor=_CHART_BG, plot_bgcolor=_CHART_BG,
            margin=dict(l=0, r=0, t=30, b=0),
            height=300,
            xaxis=dict(tickangle=-45, gridcolor=_CHART_GRID),
            yaxis=dict(gridcolor=_CHART_GRID),
            coloraxis_showscale=False,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No IP data yet.")
