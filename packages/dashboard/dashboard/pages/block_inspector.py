"""Block Inspector page — per-block hash, data, and signature verification."""

import json
import time

import streamlit as st


def _pretty(obj) -> str:
    try:
        return json.dumps(obj, indent=2)
    except Exception:
        return str(obj)


def render(fw, ledger) -> None:
    st.title("🔍 Block Inspector")

    if not ledger.chain:
        st.info("Ledger is empty.")
        return

    blk_index = st.number_input(
        "Block Index",
        min_value=0,
        max_value=len(ledger.chain) - 1,
        value=0,
        step=1,
    )
    blk      = ledger.chain[int(blk_index)]
    blk_dict = blk.to_dict()

    c1, c2 = st.columns(2)
    c1.metric("Index",  blk_dict["index"])
    c1.metric("Nonce",  f"{blk_dict['nonce']:,}")
    c2.metric("Timestamp", time.strftime(
        "%Y-%m-%d %H:%M:%S", time.localtime(blk_dict["timestamp"])
    ))
    c2.metric("Signer", blk_dict["signer"] or "—")

    st.markdown("")
    st.text_input("🔗 Hash",      blk_dict["hash"],      disabled=True)
    st.text_input("⬅️ Prev Hash", blk_dict["prev_hash"], disabled=True)
    st.text_area("📦 Data",       _pretty(blk_dict["data"]), height=120, disabled=True)

    if blk_dict["signature"]:
        st.text_area("🔐 Signature (hex)", blk_dict["signature"], height=80, disabled=True)

    if st.button("✅ Verify Signature", type="primary"):
        public_key = st.session_state["keys"][0]
        if blk.verify(public_key):
            st.success("✅ Signature is cryptographically valid.")
        else:
            st.error("❌ Signature verification **FAILED**.")
