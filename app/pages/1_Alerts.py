"""Alert triage dashboard. Lists alerts, lets analysts/admins change status."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from logsentinel.alerts import list_alerts, update_alert_status  # noqa: E402
from logsentinel.auth import can, get_role  # noqa: E402

st.set_page_config(page_title="Alerts — LogSentinel", page_icon="🚨", layout="wide")
st.title("🚨 Alert Triage")


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

if not can(role, "triage_alerts"):
    st.warning("Your role cannot triage alerts. Ask an admin for analyst access.")
    st.stop()

from logsentinel.db import get_client  # noqa: E402

sb_client = get_client(st.secrets["supabase"]["url"], st.secrets["supabase"]["anon_key"])

status_filter = st.selectbox("Filter by status", ["All", "open", "investigating", "resolved"])
filter_value = None if status_filter == "All" else status_filter

alerts = list_alerts(sb_client, status=filter_value)

if not alerts:
    st.info("No alerts match this filter.")
    st.stop()

st.caption(f"{len(alerts)} alert(s) found.")

for alert in alerts:
    severity_icon = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(alert["severity"], "⚪")
    with st.expander(
        f"{severity_icon} {alert['rule']} — {alert['ip']} — `{alert['status']}`"
    ):
        st.write(f"**Detail:** {alert['detail']}")
        st.write(f"**Created:** {alert['created_at']}")
        st.write(f"**Created by:** {alert.get('created_by', 'unknown')}")
        st.write(f"**Created by:** {alert.get('created_by', 'unknown')}")

        col1, col2, col3 = st.columns(3)
        if col1.button("Mark investigating", key=f"inv_{alert['id']}"):
            update_alert_status(sb_client, alert["id"], "investigating")
            from logsentinel.audit import log_action
            log_action(
                sb_client, st.user.email, "update_alert_status",
                f"{alert['id']} -> investigating",
            )
            st.rerun()
        if col2.button("Mark resolved", key=f"res_{alert['id']}"):
            update_alert_status(sb_client, alert["id"], "resolved")
            from logsentinel.audit import log_action
            log_action(
                sb_client, st.user.email, "update_alert_status",
                f"{alert['id']} -> resolved",
            )
            st.rerun()
        if col3.button("Reopen", key=f"open_{alert['id']}"):
            update_alert_status(sb_client, alert["id"], "open")
            from logsentinel.audit import log_action
            log_action(
                sb_client, st.user.email, "update_alert_status",
                f"{alert['id']} -> open",
            )
            st.rerun()

st.divider()
st.subheader("Summary")
df = pd.DataFrame(alerts)
status_counts = df["status"].value_counts()
st.bar_chart(status_counts)


st.divider()
st.subheader("Summary")
df = pd.DataFrame(alerts)
status_counts = df["status"].value_counts()
st.bar_chart(status_counts)
