from unittest.mock import MagicMock

import pytest

from logsentinel.rule_config import RuleConfig, get_rule_config, update_rule_config


def test_get_rule_config_returns_values_from_the_row():
    client = MagicMock()
    client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
        {"brute_force_threshold": 7, "scan_threshold": 4, "window_seconds": 300}
    ]
    config = get_rule_config(client)
    assert config.brute_force_threshold == 7
    assert config.scan_threshold == 4
    assert config.window_seconds == 300


def test_get_rule_config_falls_back_to_defaults_if_row_missing():
    client = MagicMock()
    client.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
    config = get_rule_config(client)
    assert config.brute_force_threshold == 5
    assert config.scan_threshold == 3
    assert config.window_seconds == 600


def test_update_rule_config_rejects_invalid_threshold():
    client = MagicMock()
    bad_config = RuleConfig(brute_force_threshold=0, scan_threshold=3, window_seconds=600)
    with pytest.raises(ValueError):
        update_rule_config(client, bad_config, "a@example.com")


def test_update_rule_config_rejects_too_small_window():
    client = MagicMock()
    bad_config = RuleConfig(brute_force_threshold=5, scan_threshold=3, window_seconds=5)
    with pytest.raises(ValueError):
        update_rule_config(client, bad_config, "a@example.com")


def test_update_rule_config_calls_update_with_correct_values():
    client = MagicMock()
    config = RuleConfig(brute_force_threshold=8, scan_threshold=4, window_seconds=300)
    update_rule_config(client, config, "admin@example.com")

    client.table.return_value.update.assert_called_once_with(
        {
            "brute_force_threshold": 8,
            "scan_threshold": 4,
            "window_seconds": 300,
            "updated_by": "admin@example.com",
        }
    )
    client.table.return_value.update.return_value.eq.assert_called_with("id", 1)
