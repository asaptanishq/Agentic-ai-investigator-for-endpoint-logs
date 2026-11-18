"""Tests for deterministic baseline activity context (ISSUE-07)."""
from a1.baseline_context import assess_activity_context


def test_admin_management_context_is_not_anomalous():
    ctx = assess_activity_context({
        "process_name": "psexec.exe",
        "parent_process_name": "services.exe",
        "user": "svc-backup",
        "hostname": "dc-01",
    })
    assert ctx["is_admin_account"] is True
    assert ctx["is_management_host"] is True
    assert ctx["is_anomaly"] is False


def test_web_server_spawning_shell_is_anomalous():
    ctx = assess_activity_context({
        "process_name": "cmd.exe",
        "parent_process_name": "w3wp.exe",
        "user": "iis_apppool",
        "hostname": "web-01",
    })
    assert ctx["is_anomaly"] is True
    assert ctx["context_notes"]
