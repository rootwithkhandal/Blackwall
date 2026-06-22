"""Export Ledger page — download the full blockchain as JSON."""

import streamlit as st


def render(fw, ledger) -> None:
    st.title("💾 Export Blockchain Ledger")

    st.metric("Chain Length", f"{len(ledger.chain):,} blocks")
    st.markdown("")

    if st.button("📦 Generate Export", type="primary"):
        export_path = ledger.export_json()
        with open(export_path, "r") as f:
            data = f.read()
        st.download_button(
            label="⬇️ Download ledger_export.json",
            data=data,
            file_name="ledger_export.json",
            mime="application/json",
        )
        st.success(f"✅ Export ready: `{export_path}`")
