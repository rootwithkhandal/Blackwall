"""Manage Rules page — add and delete firewall rules."""

import pandas as pd
import streamlit as st


def render(fw, ledger) -> None:
    st.title("📋 Firewall Rule Manager")

    # ── Add rule ──────────────────────────────────────────────────────────────
    with st.expander("➕ Add New Rule", expanded=True):
        with st.form("add_rule_form"):
            c1, c2, c3, c4 = st.columns(4)
            action  = c1.selectbox("⚡ Action",   ["ALLOW", "DROP"])
            ip      = c2.text_input("🌐 Source IP",  placeholder="blank = any")
            port    = c3.text_input("🔌 Port",        placeholder="blank = any")
            proto   = c4.selectbox("📡 Protocol",    ["", "TCP", "UDP"])
            comment = st.text_input("💬 Comment / label", placeholder="optional — e.g. 'block scanner'")
            submitted = st.form_submit_button("Add Rule", type="primary")

        if submitted:
            port_val = None
            port_err = None
            if port.strip():
                if port.strip().isdigit() and 1 <= int(port.strip()) <= 65535:
                    port_val = int(port.strip())
                else:
                    port_err = f"'{port}' is not a valid port number (1–65535)."

            if port_err:
                st.error(f"❌ {port_err}")
            else:
                fw.add_rule(
                    action  = action,
                    ip      = ip.strip() or None,
                    port    = port_val,
                    proto   = proto or None,
                    comment = comment.strip(),
                )
                st.success(
                    f"✅ Rule added: **{action}** | ip={ip.strip() or 'any'} | "
                    f"port={port_val or 'any'} | proto={proto or 'any'}"
                )
                st.rerun()

    # ── Active rules table ────────────────────────────────────────────────────
    st.subheader("📑 Active Rules")
    rules = fw.get_rules()
    if rules:
        st.dataframe(
            pd.DataFrame(rules),
            width="stretch",
            hide_index=True,
            column_config={
                "id": st.column_config.NumberColumn("#", width="small"),
                "action": st.column_config.TextColumn("Action", width="small"),
                "ip": st.column_config.TextColumn("IP"),
                "port": st.column_config.NumberColumn("Port", format="%d"),
                "proto": st.column_config.TextColumn("Proto", width="small"),
                "comment": st.column_config.TextColumn("Comment"),
                "created": st.column_config.TextColumn("Created", width="medium"),
            },
        )

        st.subheader("🗑️ Delete a Rule")
        rule_options = {f"[{r['id']}] {r['action']} ip={r['ip'] or 'any'} "
                        f"port={r['port'] or 'any'} proto={r['proto'] or 'any'}": r["id"]
                        for r in rules}
        selected = st.selectbox("Select rule to delete", list(rule_options.keys()))
        if st.button("Delete Rule", type="primary"):
            if fw.delete_rule(rule_options[selected]):
                st.success("✅ Rule deleted.")
                st.rerun()
            else:
                st.error("❌ Rule not found.")
    else:
        st.markdown(
            '<div style="text-align: center; padding: 2rem 1rem;">'
            '<div style="font-size: 2.5rem; margin-bottom: 0.5rem;">📭</div>'
            '<div style="color: #5A6478; font-size: 0.9rem;">'
            'No rules configured yet. Add one above to get started.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
