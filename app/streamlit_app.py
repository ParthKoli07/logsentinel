"""Thin Streamlit UI. Keep all real logic in src/logsentinel."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from logsentinel.parser import parse_lines  # noqa: E402

st.set_page_config(page_title="LogSentinel", page_icon="🛡️", layout="wide")
st.title("🛡️ LogSentinel")
st.caption("Upload a web server access log to parse it.")

uploaded = st.file_uploader("Nginx/Apache combined-format log file", type=["log", "txt"])

if uploaded is None:
    st.info("Upload a log file to get started. A sample is in sample_data/.")
    st.stop()

text = uploaded.getvalue().decode("utf-8", errors="replace")
entries, malformed = parse_lines(text.splitlines())

col1, col2 = st.columns(2)
col1.metric("Parsed lines", len(entries))
col2.metric("Malformed lines", malformed)

if entries:
    df = pd.DataFrame([e.__dict__ for e in entries])
    st.dataframe(df.head(100))
else:
    st.warning("No valid log lines found.")
