"""Threat Stats page — cumulative counters, protocol/verdict charts, top talkers."""

from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st


def render(fw, ledger) -> None:
    st.title("📊 Threat Statistics")

    logs  = st.session_state["packets"]
    stats = fw.get_stats()

    # ── Top-level metrics ─────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Packets",   stats["total"])
    c2.metric("Allowed",         stats["allow"])
    c3.metric("Dropped",         stats["drop"])
    c4.metric("Auto-Banned IPs", stats["banned"])

    if not logs:
        st.info("No traffic data yet.")
        return

    # ── Charts side by side ───────────────────────────────────────────────────
    left, right = st.columns(2)

    proto_counts = Counter(p["proto"] for p in logs)
    df_proto = pd.DataFrame(proto_counts.items(), columns=["Protocol", "Count"])
    fig_proto = px.pie(
        df_proto, names="Protocol", values="Count",
        title="Protocol Distribution", hole=0.4,
    )
    left.plotly_chart(fig_proto, use_container_width=True)

    verdict_counts = Counter(p["verdict"] for p in logs)
    df_verdict = pd.DataFrame(verdict_counts.items(), columns=["Verdict", "Count"])
    fig_verdict = px.pie(
        df_verdict, names="Verdict", values="Count",
        title="Verdict Distribution",
        color="Verdict",
        color_discrete_map={"ALLOW": "#00cc96", "DROP": "#ef553b"},
        hole=0.4,
    )
    right.plotly_chart(fig_verdict, use_container_width=True)

    # ── Top talkers ───────────────────────────────────────────────────────────
    st.subheader("🏆 Top 10 Talkers")
    top_ips = Counter(p["src"] for p in logs if p["src"] != "unknown").most_common(10)
    if top_ips:
        st.dataframe(
            pd.DataFrame(top_ips, columns=["IP", "Packets"]),
            use_container_width=True, hide_index=True,
        )

    # ── Top targeted ports ────────────────────────────────────────────────────
    st.subheader("🎯 Top 10 Targeted Ports")
    top_ports = Counter(p["port"] for p in logs if p["port"]).most_common(10)
    if top_ports:
        st.dataframe(
            pd.DataFrame(top_ports, columns=["Port", "Hits"]),
            use_container_width=True, hide_index=True,
        )
