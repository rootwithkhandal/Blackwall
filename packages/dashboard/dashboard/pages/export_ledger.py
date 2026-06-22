"""Export Ledger page — download the full blockchain as JSON."""

import streamlit as st


def render(fw, ledger) -> None:
    st.title("💾 Export Blockchain Ledger")
    st.write(f"Chain contains **{len(ledger.chain)}** blocks.")

    if st.button("Generate Export"):
        # export_json() resolves the path internally to data/ledger_export.json
        export_path = ledger.export_json()
        with open(export_path, "r") as f:
            data = f.read()
        st.download_button(
            label="⬇️ Download ledger_export.json",
            data=data,
            file_name="ledger_export.json",
            mime="application/json",
        )
        st.success(f"Export ready: {export_path}")
