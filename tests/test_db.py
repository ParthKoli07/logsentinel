from unittest.mock import MagicMock

from logsentinel.db import check_connection


def test_successful_query_means_connected():
    client = MagicMock()
    client.table.return_value.select.return_value.limit.return_value.execute.return_value = None
    ok, message = check_connection(client)
    assert ok
    assert "Connected" in message


def test_missing_table_still_counts_as_connected():
    client = MagicMock()
    client.table.return_value.select.return_value.limit.return_value.execute.side_effect = (
        Exception("relation \"_connection_check\" does not exist")
    )
    ok, _ = check_connection(client)
    assert ok


def test_auth_failure_is_not_connected():
    client = MagicMock()
    client.table.return_value.select.return_value.limit.return_value.execute.side_effect = (
        Exception("Invalid API key")
    )
    ok, message = check_connection(client)
    assert not ok
    assert "Invalid API key" in message
