"""Export Logs page — download the full ledger as JSONL."""

import streamlit as st
import os


def render() -> None:
    st.title("💾 Export Audit Logs")

    ledger_path = os.path.join(os.getcwd(), "data", "ledger.jsonl")
    
    if os.path.exists(ledger_path):
        with open(ledger_path, "r") as f:
            lines = f.readlines()
        st.metric("Total Log Entries", f"{len(lines):,}")
    else:
        st.metric("Total Log Entries", "0")
        lines = []

    st.markdown("")

    if st.button("📦 Generate Export", type="primary"):
        if lines:
            data = "".join(lines)
            st.download_button(
                label="⬇️ Download ledger.jsonl",
                data=data,
                file_name="ledger.jsonl",
                mime="application/json",
            )
            st.success("✅ Export ready!")
        else:
            st.warning("No logs to export.")
