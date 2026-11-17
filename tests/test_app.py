from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"


def test_app_starts_without_errors():
    at = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not at.exception
    assert "LogSentinel" in at.title[0].value
