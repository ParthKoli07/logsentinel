from logsentinel.auth import can, get_role


def test_admin_and_analyst_resolution_is_case_insensitive():
    assert get_role("Boss@Example.com", admins=["boss@example.com"]) == "admin"
    assert get_role("a@example.com", analysts=["A@example.com"]) == "analyst"


def test_unknown_or_missing_email_is_viewer():
    assert get_role("nobody@example.com") == "viewer"
    assert get_role(None) == "viewer"


def test_admin_wins_if_email_is_in_both_lists():
    email = "x@example.com"
    assert get_role(email, admins=[email], analysts=[email]) == "admin"


def test_permissions():
    assert can("admin", "manage_rules")
    assert can("analyst", "triage_alerts")
    assert not can("viewer", "upload_logs")


def test_unknown_role_or_action_is_denied():
    assert not can("unknown-role", "view_dashboard")
    assert not can("admin", "launch_missiles")
