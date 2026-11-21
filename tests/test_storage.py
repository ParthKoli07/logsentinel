from datetime import datetime, timezone
from unittest.mock import MagicMock

from logsentinel.parser import LogEntry
from logsentinel.storage import save_batch


def _entry(ip="203.0.113.5"):
    return LogEntry(
        ip=ip,
        user=None,
        timestamp=datetime(2026, 11, 21, 9, 0, 0, tzinfo=timezone.utc),
        method="GET",
        path="/",
        protocol="HTTP/1.1",
        status=200,
        size=100,
        referrer=None,
        user_agent="pytest",
    )


def test_save_batch_inserts_batch_then_entries():
    client = MagicMock()
    client.table.return_value.insert.return_value.execute.return_value.data = [{"id": "batch-123"}]

    batch_id = save_batch(
        client, "a@example.com", "sample.log", [_entry(), _entry()], malformed_lines=1)

    assert batch_id == "batch-123"
    # First call creates the batch, second inserts entries.
    calls = client.table.call_args_list
    assert calls[0].args[0] == "log_batches"
    assert calls[1].args[0] == "log_entries"


def test_save_batch_with_no_entries_skips_entry_insert():
    client = MagicMock()
    client.table.return_value.insert.return_value.execute.return_value.data = [{"id": "batch-456"}]

    save_batch(client, "a@example.com", "empty.log", [], malformed_lines=0)

    # Only one table() call: log_batches. No log_entries insert happens.
    tables_called = [c.args[0] for c in client.table.call_args_list]
    assert tables_called == ["log_batches"]
