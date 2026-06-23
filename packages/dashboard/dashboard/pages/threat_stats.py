"""Threat Stats page — cumulative counters, protocol/verdict charts, top talkers."""

from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st

_CHART_BG = "rgba(0,0,0,0)"
_CHART_GRID = "rgba(124, 106, 255, 0.06)"


def render(fw) -> None:
    st.title("📊 Threat Statistics")

    all_packets = [pkt for q in st.session_state["packets"].values() for pkt in q]
    logs = all_packets
    stats = fw.get_stats()

    # ── Top-level metrics ─────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Packets",   f"{stats['total']:,}")
    c2.metric("Allowed",         f"{stats['allow']:,}")
    c3.metric("Dropped",         f"{stats['drop']:,}")
    c4.metric("Auto-Banned IPs", f"{stats['banned']:,}")

    if not logs:
        st.info("⏳ No traffic data yet — waiting for packets…")
        return

    # ── Charts side by side ───────────────────────────────────────────────────
    left, right = st.columns(2)

    proto_counts = Counter(p["proto"] for p in logs)
    df_proto = pd.DataFrame(proto_counts.items(), columns=["Protocol", "Count"])
    fig_proto = px.pie(
        df_proto, names="Protocol", values="Count",
        title="Protocol Distribution", hole=0.45,
        color_discrete_sequence=["#7C6AFF", "#63B3ED", "#FBBF24", "#F87171"],
        template="plotly_dark",
    )
    fig_proto.update_layout(
        paper_bgcolor=_CHART_BG, plot_bgcolor=_CHART_BG,
        margin=dict(l=20, r=20, t=50, b=20),
        height=350,
        font=dict(family="Inter"),
    )
    fig_proto.update_traces(
        textposition="inside", textinfo="percent+label",
        marker=dict(line=dict(color="#0B0F19", width=2)),
    )
    left.plotly_chart(fig_proto, width="stretch")

    verdict_counts = Counter(p["verdict"] for p in logs)
    df_verdict = pd.DataFrame(verdict_counts.items(), columns=["Verdict", "Count"])
    fig_verdict = px.pie(
        df_verdict, names="Verdict", values="Count",
        title="Verdict Distribution",
        color="Verdict",
        color_discrete_map={"ALLOW": "#4ADE80", "DROP": "#F87171"},
        hole=0.45,
        template="plotly_dark",
    )
    fig_verdict.update_layout(
        paper_bgcolor=_CHART_BG, plot_bgcolor=_CHART_BG,
        margin=dict(l=20, r=20, t=50, b=20),
        height=350,
        font=dict(family="Inter"),
    )
    fig_verdict.update_traces(
        textposition="inside", textinfo="percent+label",
        marker=dict(line=dict(color="#0B0F19", width=2)),
    )
    right.plotly_chart(fig_verdict, width="stretch")

    # ── Top talkers ───────────────────────────────────────────────────────────
    left2, right2 = st.columns(2)

    with left2:
        st.subheader("🏆 Top 10 Talkers")
        top_ips = Counter(p["src"] for p in logs if p["src"] != "unknown").most_common(10)
        if top_ips:
            st.dataframe(
                pd.DataFrame(top_ips, columns=["IP", "Packets"]),
                width="stretch", hide_index=True,
            )

    with right2:
        st.subheader("🎯 Top 10 Targeted Ports")
        top_ports = Counter(p["port"] for p in logs if p["port"]).most_common(10)
        if top_ports:
            st.dataframe(
                pd.DataFrame(top_ports, columns=["Port", "Hits"]),
                width="stretch", hide_index=True,
            )

    # ── GeoIP World Map Heatmap ───────────────────────────────────────────────
    st.write("---")
    try:
        import os
        import geoip2.database
        import geoip2.errors
        _has_geoip2 = True
    except ImportError:
        _has_geoip2 = False

    _DB_PATH = os.path.join(os.getcwd(), "data", "GeoLite2-Country.mmdb")
    
    if _has_geoip2 and os.path.exists(_DB_PATH):
        st.subheader("🌍 Attack Origins")
        try:
            reader = geoip2.database.Reader(_DB_PATH)
            country_counts = Counter()
            for p in logs:
                if p["src"] and p["src"] != "unknown":
                    try:
                        resp = reader.country(p["src"])
                        if resp.country.name:
                            country_counts[resp.country.name] += 1
                    except geoip2.errors.AddressNotFoundError:
                        pass
            
            if country_counts:
                df_geo = pd.DataFrame(country_counts.items(), columns=["Country", "Hits"])
                fig_geo = px.choropleth(
                    df_geo,
                    locations="Country",
                    locationmode="country names",
                    color="Hits",
                    color_continuous_scale=[[0, "#2D1B69"], [0.5, "#7C6AFF"], [1, "#F87171"]],
                    template="plotly_dark"
                )
                fig_geo.update_layout(
                    paper_bgcolor=_CHART_BG, plot_bgcolor=_CHART_BG,
                    margin=dict(l=0, r=0, t=30, b=0),
                    height=500,
                    geo=dict(
                        bgcolor="rgba(0,0,0,0)",
                        showcoastlines=True, coastlinecolor="rgba(124, 106, 255, 0.2)",
                        showframe=False,
                        projection_type="equirectangular",
                        landcolor="rgba(255, 255, 255, 0.02)",
                    ),
                    coloraxis_colorbar=dict(title="Hits", x=0.95)
                )
                st.plotly_chart(fig_geo, width="stretch")
            else:
                st.info("No external IP data mapped yet.")
        except Exception as e:
            st.error(f"Error reading GeoIP database: {e}")
    else:
        st.info(
            "🌍 **GeoIP Map Disabled**\n\n"
            "To enable the world-map heatmap:\n"
            "1. Run `pip install geoip2` (or `mise run req`)\n"
            "2. Download the free [MaxMind GeoLite2-Country database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)\n"
            "3. Place `GeoLite2-Country.mmdb` inside the `data/` directory."
        )
