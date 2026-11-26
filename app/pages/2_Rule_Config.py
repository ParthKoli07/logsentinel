"""Admin-only page to tune detection thresholds without editing code."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import streamlit as st  # noqa: E402

from logsentinel.auth import can, get_role  # noqa: E402
from logsentinel.rule_config import RuleConfig, get_rule_config, update_rule_config  # noqa: E402

st.set_page_config(page_title="Rule Config — LogSentinel", page_icon="⚙️", layout="wide")
st.title("⚙️ Rule Configuration")


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

if not can(role, "manage_rules"):
    st.warning("Only admins can configure detection rules.")
    st.stop()

from logsentinel.db import get_client  # noqa: E402

sb_client = get_client(st.secrets["supabase"]["url"], st.secrets["supabase"]["anon_key"])
current = get_rule_config(sb_client)

st.caption(
    "Changes apply to the next log batch uploaded. Existing alerts are not retroactively re-scored."
)

with st.form("rule_config_form"):
    brute_force_threshold = st.number_input(
        "Brute-force threshold (failed logins to flag)",
        min_value=1, max_value=100, value=current.brute_force_threshold,
        help="An IP is flagged after this many failed /login attempts within one window.",
    )
    scan_threshold = st.number_input(
        "Scan threshold (distinct sensitive paths)",
        min_value=1, max_value=50, value=current.scan_threshold,
        help="An IP is flagged after probing this many distinct sensitive paths within one window.",
    )
    window_seconds = st.number_input(
        "Detection window (seconds)",
        min_value=10, max_value=3600, value=current.window_seconds,
        help="The time window used to group requests when counting failed logins or scanned paths.",
    )
    submitted = st.form_submit_button("Save configuration")

if submitted:
    try:
        new_config = RuleConfig(
            brute_force_threshold=int(brute_force_threshold),
            scan_threshold=int(scan_threshold),
            window_seconds=int(window_seconds),
        )
        update_rule_config(sb_client, new_config, st.user.email)
        st.success("Configuration saved.")
        st.rerun()
    except ValueError as exc:
        st.error(str(exc))

st.divider()
st.subheader("Current configuration")
st.json(
    {
        "brute_force_threshold": current.brute_force_threshold,
        "scan_threshold": current.scan_threshold,
        "window_seconds": current.window_seconds,
    }
)
