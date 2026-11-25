from unittest.mock import MagicMock

import pytest

from logsentinel.alerts import list_alerts, save_alerts, update_alert_status
from logsentinel.detection.rules import Alert


def _alert(ip="198.51.100.7", rule="brute_force"):
    return Alert(ip=ip, rule=rule, severity="high", detail="test detail")


def test_save_alerts_inserts_one_row_per_alert():
    client = MagicMock()
    count = save_alerts(client, "batch-1", [_alert(), _alert(ip="2.2.2.2")], "a@example.com")
    assert count == 2
    client.table.assert_called_with("alerts")


def test_save_alerts_with_empty_list_does_nothing():
    client = MagicMock()
    count = save_alerts(client, "batch-1", [], "a@example.com")
    assert count == 0
    client.table.assert_not_called()


def test_list_alerts_without_status_filter():
    client = MagicMock()
    client.table.return_value.select.return_value.order.return_value.execute.return_value.data = [
        {"id": "1", "status": "open"}
    ]
    results = list_alerts(client)
    assert len(results) == 1


def test_list_alerts_with_status_filter_applies_eq():
    client = MagicMock()
    chain = client.table.return_value.select.return_value.order.return_value
    chain.eq.return_value.execute.return_value.data = [{"id": "1", "status": "resolved"}]
    results = list_alerts(client, status="resolved")
    chain.eq.assert_called_with("status", "resolved")
    assert results == [{"id": "1", "status": "resolved"}]


def test_update_alert_status_rejects_invalid_status():
    client = MagicMock()
    with pytest.raises(ValueError):
        update_alert_status(client, "alert-1", "deleted")


def test_update_alert_status_calls_update_with_eq():
    client = MagicMock()
    update_alert_status(client, "alert-1", "investigating")
    client.table.return_value.update.assert_called_with({"status": "investigating"})
    client.table.return_value.update.return_value.eq.assert_called_with("id", "alert-1")
