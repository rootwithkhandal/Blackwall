"""Ledger Integrity page — blockchain tamper detection."""

import pandas as pd
import streamlit as st


def render(fw, ledger) -> None:
    st.title("🔒 Blockchain Ledger Integrity")

    summary = ledger.summary()
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Blocks",   summary["total_blocks"])
    c2.metric("PoW Difficulty", summary["difficulty"])
    latest = summary["latest_hash"]
    c3.metric("Latest Hash", (latest[:16] + "…") if latest else "—")

    if st.button("🔍 Run Integrity Check"):
        issues = ledger.check_integrity()
        if issues:
            st.error(f"⚠️ {len(issues)} integrity issue(s) found!")
            st.dataframe(
                pd.DataFrame(issues),
                use_container_width=True, hide_index=True,
            )
        else:
            st.success("✅ Ledger is clean — no tampering detected.")
