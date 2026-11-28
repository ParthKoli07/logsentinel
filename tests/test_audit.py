from unittest.mock import MagicMock

import pytest

from logsentinel.audit import list_audit_log, log_action


def test_log_action_inserts_with_correct_fields():
    client = MagicMock()
    log_action(client, "a@example.com", "upload_batch", "sample.log")
    client.table.return_value.insert.assert_called_once_with(
        {"actor": "a@example.com", "action": "upload_batch", "details": "sample.log"}
    )


def test_log_action_rejects_unknown_action():
    client = MagicMock()
    with pytest.raises(ValueError):
        log_action(client, "a@example.com", "delete_everything")


def test_log_action_defaults_details_to_empty_string():
    client = MagicMock()
    log_action(client, "a@example.com", "update_rule_config")
    client.table.return_value.insert.assert_called_once_with(
        {"actor": "a@example.com", "action": "update_rule_config", "details": ""}
    )


def test_list_audit_log_orders_newest_first_and_respects_limit():
    client = MagicMock()
    chain = client.table.return_value.select.return_value.order.return_value.limit.return_value
    chain.execute.return_value.data = [{"id": "1", "action": "upload_batch"}]

    results = list_audit_log(client, limit=50)

    client.table.return_value.select.return_value.order.assert_called_with(
        "created_at", desc=True
    )
    client.table.return_value.select.return_value.order.return_value.limit.assert_called_with(50)
    assert results == [{"id": "1", "action": "upload_batch"}]
