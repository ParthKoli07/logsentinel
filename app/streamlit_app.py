"""Thin Streamlit UI. Keep all real logic in src/logsentinel."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from logsentinel.auth import can, get_role  # noqa: E402
from logsentinel.parser import parse_lines  # noqa: E402

st.set_page_config(page_title="LogSentinel", page_icon="🛡️", layout="wide")
st.title("🛡️ LogSentinel")


def _role_lists() -> tuple[list[str], list[str]]:
    try:
        roles = st.secrets["roles"]
        return list(roles.get("admins", [])), list(roles.get("analysts", []))
    except Exception:
        return [], []


if not getattr(st.user, "is_logged_in", False):
    st.info("Please sign in to continue.")
    st.button("Log in with Google", on_click=st.login, args=["google"])
    st.stop()

admins, analysts = _role_lists()
role = get_role(st.user.email, admins, analysts)

with st.sidebar:
    st.write(f"Signed in as **{st.user.email}**")
    st.write(f"Role: `{role}`")
    st.button("Log out", on_click=st.logout)

    st.divider()
    try:
        from logsentinel.db import check_connection, get_client

        sb_client = get_client(st.secrets["supabase"]["url"], st.secrets["supabase"]["anon_key"])
        ok, msg = check_connection(sb_client)
        st.write("Database:", "🟢 " + msg if ok else "🔴 " + msg)
    except Exception as exc:
        st.write("Database: 🔴", str(exc))

st.caption("Upload a web server access log to parse it.")

if not can(role, "upload_logs"):
    st.warning("Your role cannot upload logs. Ask an admin for analyst access.")
    st.stop()

uploaded = st.file_uploader("Nginx/Apache combined-format log file", type=["log", "txt"])

if uploaded is None:
    st.info("Upload a log file to get started. A sample is in sample_data/.")
    st.stop()

text = uploaded.getvalue().decode("utf-8", errors="replace")
entries, malformed = parse_lines(text.splitlines())

if entries and can(role, "upload_logs"):
    if st.button("Save this batch to the database"):
        from logsentinel.storage import save_batch

        batch_id = save_batch(sb_client, st.user.email, uploaded.name, entries, malformed)
        st.session_state["batch_id"] = batch_id
        st.success(f"Saved batch {batch_id}")

    from logsentinel.detection.rules import run_all_rules

    rule_alerts = run_all_rules(entries)
    if rule_alerts:
        st.warning(f"⚠️ {len(rule_alerts)} potential threat(s) detected in this batch.")
        if st.button("Save alerts to the database"):
            if "batch_id" not in st.session_state:
                st.error("Save the batch first, then save alerts.")
            else:
                from logsentinel.alerts import save_alerts

                count = save_alerts(
                    sb_client, st.session_state["batch_id"], rule_alerts, st.user.email
                )
                st.success(f"Saved {count} alert(s).")
                count = save_alerts(
                sb_client, st.session_state["batch_id"], rule_alerts, st.user.email
            )
            st.success(f"Saved {count} alert(s).")

            from logsentinel.audit import log_action
            log_action(sb_client, st.user.email, "save_alerts", f"{count} alerts")

col1, col2 = st.columns(2)

col1, col2 = st.columns(2)
col1.metric("Parsed lines", len(entries))
col2.metric("Malformed lines", malformed)

if entries:
    df = pd.DataFrame([e.__dict__ for e in entries])
    st.dataframe(df.head(100))
else:
    st.warning("No valid log lines found.")
