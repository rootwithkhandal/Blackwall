"""Banned IPs page — view auto-banned IPs and unban them."""

import pandas as pd
import streamlit as st


def render(fw, ledger) -> None:
    st.title("🚫 Auto-Banned IPs")

    banned = sorted(fw.banned_ips)

    if banned:
        st.warning(f"{len(banned)} IP(s) currently banned.")
        st.dataframe(
            pd.DataFrame({"Banned IP": banned}),
            use_container_width=True,
            hide_index=True,
        )

        st.subheader("Unban an IP")
        unban_ip = st.selectbox("Select IP to unban", banned)
        if st.button("Unban", type="primary"):
            if fw.unban_ip(unban_ip):          # uses the proper API
                st.success(f"{unban_ip} has been unbanned.")
                st.rerun()
            else:
                st.error(f"{unban_ip} was not in the ban list.")
    else:
        st.success("No IPs are currently banned. 🎉")

    st.markdown("---")
    st.caption(
        "IPs are auto-banned when the ML anomaly detector (IsolationForest) "
        "flags their traffic pattern as anomalous. "
        "Bans persist across restarts."
    )
