"""Banned IPs page — view auto-banned IPs and unban them."""

import pandas as pd
import streamlit as st


def render(fw) -> None:
    st.title("🚫 Auto-Banned IPs")

    banned = sorted(fw.banned_ips)

    if banned:
        st.markdown(
            f'<div style="background: linear-gradient(135deg, rgba(248,113,113,0.12), rgba(251,191,36,0.08)); '
            f'border: 1px solid rgba(248,113,113,0.25); border-radius: 10px; padding: 0.8rem 1.2rem; '
            f'font-weight: 600; color: #FBBF24;">'
            f'⚠️ {len(banned)} IP(s) currently banned</div>',
            unsafe_allow_html=True,
        )
        st.markdown("")

        st.dataframe(
            pd.DataFrame({"Banned IP": banned}),
            width="stretch",
            hide_index=True,
            column_config={
                "Banned IP": st.column_config.TextColumn("🔴 Banned IP Address"),
            },
        )

        st.subheader("🔓 Unban an IP")
        unban_ip = st.selectbox("Select IP to unban", banned)
        if st.button("Unban IP", type="primary"):
            if fw.unban_ip(unban_ip):
                st.success(f"✅ **{unban_ip}** has been unbanned.")
                st.rerun()
            else:
                st.error(f"❌ {unban_ip} was not in the ban list.")
    else:
        st.markdown(
            '<div style="text-align: center; padding: 3rem 1rem;">'
            '<div style="font-size: 3rem; margin-bottom: 0.5rem;">🎉</div>'
            '<div style="font-size: 1.2rem; font-weight: 600; color: #4ADE80; margin-bottom: 0.3rem;">'
            'All Clear</div>'
            '<div style="color: #5A6478; font-size: 0.85rem;">'
            'No IPs are currently banned. The ML detector is monitoring traffic.</div>'
            '</div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.caption(
        "IPs are auto-banned when the ML anomaly detector (IsolationForest) "
        "flags their traffic pattern as anomalous. "
        "Bans persist across restarts."
    )
