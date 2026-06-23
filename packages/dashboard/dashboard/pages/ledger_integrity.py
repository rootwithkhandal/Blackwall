"""Ledger Integrity page — blockchain tamper detection."""

import pandas as pd
import streamlit as st


def render(fw, ledger) -> None:
    st.title("🔒 Blockchain Ledger Integrity")

    summary = ledger.summary()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Blocks",   f"{summary['total_blocks']:,}")
    c2.metric("PoW Difficulty", summary["difficulty"])
    latest = summary["latest_hash"]
    c3.metric("Latest Hash", (latest[:16] + "…") if latest else "—")

    st.markdown("")

    if st.button("🔍 Run Integrity Check", type="primary"):
        issues = ledger.check_integrity()
        if issues:
            st.error(f"⚠️ **{len(issues)} integrity issue(s) found!**")
            st.dataframe(
                pd.DataFrame(issues),
                width="stretch", hide_index=True,
                column_config={
                    "index": st.column_config.NumberColumn("Block #"),
                    "issue": st.column_config.TextColumn("Issue"),
                },
            )
        else:
            st.markdown(
                '<div style="text-align: center; padding: 2rem;">'
                '<div style="font-size: 2.5rem; margin-bottom: 0.5rem;">✅</div>'
                '<div style="font-size: 1.1rem; font-weight: 600; color: #4ADE80;">'
                'Ledger is clean — no tampering detected</div>'
                '</div>',
                unsafe_allow_html=True,
            )
