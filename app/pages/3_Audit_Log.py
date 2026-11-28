"""Admin-only view of the append-only audit log."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from logsentinel.audit import list_audit_log  # noqa: E402
from logsentinel.auth import can, get_role  # noqa: E402

st.set_page_config(page_title="Audit Log — LogSentinel", page_icon="📋", layout="wide")
st.title("📋 Audit Log")


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

if not can(role, "manage_users"):
    st.warning("Only admins can view the audit log.")
    st.stop()

from logsentinel.db import get_client  # noqa: E402

sb_client = get_client(st.secrets["supabase"]["url"], st.secrets["supabase"]["anon_key"])
entries = list_audit_log(sb_client, limit=200)

if not entries:
    st.info("No audit entries yet.")
    st.stop()

st.caption(f"Showing the {len(entries)} most recent entries.")
df = pd.DataFrame(entries)[["created_at", "actor", "action", "details"]]
st.dataframe(df, use_container_width=True)
